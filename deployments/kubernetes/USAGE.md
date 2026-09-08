# Using a deployed Veraison

How to talk to Veraison once it is running. For deploying it see
[DEPLOYMENT.md](DEPLOYMENT.md); for why the manifests look as they do, see
[README.md](README.md).

Every request and response shown here was run against the built images. Where
something has *not* been exercised, it says so.

## The three jobs

Veraison serves three different audiences, and they use different services:

| You want to | Service | Port | Auth |
|---|---|---|---|
| Verify evidence from a device (**relying party**) | `verification-service` | 8443 | none |
| Supply reference values / trust anchors (**provisioner**) | `provisioning-service` | 9443 | `provisioner` role |
| Manage appraisal policy | `management-service` | 10443 | `manager` role |
| Fetch endorsements (CoSERV) | `coserv-service` | 11443 | none |

`vts-service` (50051) is internal — the other services call it over gRPC. Do not
expose it.

Note the verification API is **unauthenticated**. Anything that can reach it can
submit evidence and get a signed attestation result. Treat network reachability
as the access control, and plan ingress accordingly.

## Reaching the services

Everything is `ClusterIP`, so for ad-hoc use:

```sh
kubectl -n veraison port-forward svc/verification-service 8443:8443
```

All the APIs are HTTPS, presenting certificates signed by Veraison's own CA. In
the examples below `-k` skips verification for brevity. To verify properly, use
the root certificate and address the service by the name in its SAN:

```sh
curl --cacert deployments/docker/src/certs/rootCA.crt \
     --resolve verification-service:8443:127.0.0.1 \
     https://verification-service:8443/.well-known/veraison/verification
```

Plain `https://localhost:8443` will fail certificate validation — `localhost` is
in the SAN list, but the certificate chains to a private CA your client does not
trust by default.

## Start with discovery

Each service publishes a `.well-known` document listing the media types it
actually accepts **in this deployment**. These are unauthenticated and are the
authoritative answer — the set depends on which scheme plugins loaded, so do not
hardcode media types from documentation.

| Service | Endpoint |
|---|---|
| verification | `/.well-known/veraison/verification` |
| provisioning | `/.well-known/veraison/provisioning` |
| management | `/.well-known/veraison/management` |
| coserv | `/.well-known/coserv-configuration` |

```sh
curl -sk https://localhost:8443/.well-known/veraison/verification | jq .
```

```json
{
  "ear-verification-key": {
    "alg": "ES256", "crv": "P-256", "kty": "EC",
    "x": "usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
    "y": "IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4"
  },
  "media-types": [ "application/psa-attestation-token", "..." ]
}
```

`ear-verification-key` is the public key that signs attestation results. Fetch it
once and pin it — you need it to check that a result really came from this
Veraison (see [Reading the result](#reading-the-result-important)).

## Verifying evidence

A two-step challenge-response exchange. Veraison issues a nonce, the device signs
evidence over it, you submit the evidence.

### 1. Open a session

```sh
curl -sk -i -X POST 'https://localhost:8443/challenge-response/v1/newSession?nonceSize=32'
```

```http
HTTP/2 201
content-type: application/vnd.veraison.challenge-response-session+json
location: session/d43436be-a8ac-11f1-9f5d-666364323230

{"status":"waiting",
 "nonce":"VfnDwk_75JLQ7oRF4kOQN8Xeb5uWTwE4MHN5yPE6NOM",
 "expiry":"2026-09-04T22:08:37Z",
 "accept":["application/psa-attestation-token", "..."]}
```

* `nonceSize` is in bytes, **8–64**, default 32. Alternatively supply your own
  with `?nonce=<base64url>` — the two are mutually exclusive and sending both is
  a 400.
* The session id is in the `Location` header (`session/<uuid>`), not the body.
* **Sessions expire after 2m30s.** Get the nonce to the device and the evidence
  back within that window, or you start again.
* `accept` is the media-type list for *this* session — use it to pick the
  `Content-Type` in step 2.

### 2. Submit evidence

POST the evidence to the session URL, with the evidence media type as
`Content-Type`:

```sh
curl -sk -X POST \
  "https://localhost:8443/challenge-response/v1/session/$ID" \
  -H 'Content-Type: application/psa-attestation-token' \
  --data-binary @evidence.cbor
```

The response is the session object again, now with `"status":"complete"` and a
`result` field.

You can also `GET` the session to re-read it, and `DELETE` it when finished
(`204`; a subsequent `GET` is `404`). Sessions expire on their own, so deleting
is tidiness rather than a requirement.

### Reading the result (important)

**HTTP 200 does not mean attestation succeeded.** A 200 means Veraison
*processed* the evidence. The verdict is inside `result`, and rejected evidence
comes back 200 as readily as good evidence. This is verified behaviour — posting
the bytes `notarealtoken` as a PSA token returns:

```
HTTP 200
{"status":"complete", "result":"eyJhbGciOiJFUzI1NiIs..."}
```

`result` is an **EAR**: a JWT signed with ES256 by the `ear-verification-key`
from the discovery document. Verify that signature — an unverified result proves
nothing — then read `submods.<scheme>.ear.status`. For the junk evidence above:

```json
{
  "ear.verifier-id": {"build": "0.0.2609+3e6d113", "developer": "Veraison Project"},
  "eat_nonce": "Q1nPrRuMIb2SGhPawrgizQ==",
  "eat_profile": "tag:github.com,2023:veraison/ear",
  "submods": {
    "PSA_IOT": {
      "ear.status": "contraindicated",
      "ear.appraisal-policy-id": "policy:PSA_IOT",
      "ear.trustworthiness-vector": { "hardware": 99, "executables": 99, "...": "..." }
    }
  }
}
```

`ear.status` is one of:

| Status | Meaning | Treat as |
|---|---|---|
| `affirming` | evidence checks out | pass |
| `warning` | something is off but not disqualifying | your policy decides |
| `contraindicated` | evidence is bad, or failed cryptographic checks | **fail** |
| `none` | no claim made | **fail** — not a pass |

Only `affirming` is a pass. Also check `eat_nonce` matches the nonce you
requested, or you have no freshness guarantee — a replayed result would
otherwise be accepted.

## Provisioning endorsements

Requires a token with the `provisioner` role.

### Get a token

The bundled realm is `veraison`, with a confidential client that has direct
access grants enabled:

```sh
TOKEN=$(curl -sk -X POST \
  'https://localhost:11111/realms/veraison/protocol/openid-connect/token' \
  -d grant_type=password \
  -d client_id=veraison-client \
  -d client_secret=YifmabB4cVSPPtFLAmHfq7wKaEHQn10Z \
  -d username=veraison-provisioner -d password=veraison \
  | jq -r .access_token)
```

Shipped identities — **development defaults, change them**:

| User | Password | Realm role | Use for |
|---|---|---|---|
| `veraison-provisioner` | `veraison` | `provisioner` | provisioning |
| `veraison-manager` | `veraison` | `manager` | policy management |

Tokens last 1800s. The role travels in `realm_access.roles`, and Veraison checks
it there; a token from the right user but the wrong role gets a 403, not a 401.

### Submit

```sh
curl -sk -X POST https://localhost:9443/endorsement-provisioning/v1/submit \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/rim+cbor; profile="tag:arm.com,2025:cca_platform#1.0.0"' \
  --data-binary @endorsements.cbor
```

**Take the `Content-Type` from `/.well-known/veraison/provisioning`.** The
accepted types are profile-qualified `application/rim+cbor` and
`application/rim+cose` values; the obvious guess of
`application/corim-unsigned+cbor` is rejected with
`415 no active plugin found`. Verified: without a token this endpoint returns
401, with a valid token it proceeds to media-type handling.

## Managing policy

Requires a token with the `manager` role. Policies are per-scheme, written in
Rego, and must be **activated** before they take effect.

| Method | Path | Purpose |
|---|---|---|
| POST | `/management/v1/policy/:scheme` | create a policy |
| POST | `/management/v1/policy/:scheme/:uuid/activate` | activate one |
| GET | `/management/v1/policy/:scheme` | the active policy |
| GET | `/management/v1/policy/:scheme/:uuid` | one policy by id |
| GET | `/management/v1/policies/:scheme` | all policies |
| POST | `/management/v1/policies/:scheme/deactivate` | deactivate all |

`:scheme` is a scheme name such as `PSA_IOT` — the same value that appears as the
key under `submods` in an EAR.

Reaching this service means port-forwarding `management-service`, which lives in
the same Pod as vts.

> Not exercised: these routes are transcribed from
> `management/api/router.go`, but no policy was created against a running
> management service during testing.

## CoSERV endorsement distribution

```
GET /.well-known/coserv-configuration
GET /endorsement-distribution/v1/coserv/{query}
```

`{query}` is an encoded CoSERV query; the well-known document advertises the
supported profiles. The NVIDIA CoSERV proxy is marked experimental upstream
(`scheme/nvidia-coserv/README.md`) — it fetches RIMs from
`rim.attestation.nvidia.com`.

## Errors

Failures come back as RFC 7807 `application/problem+json`:

```json
{"type":"about:blank","title":"Unsupported Media Type","status":415,
 "detail":"no active plugin found for application/corim-unsigned+cbor"}
```

The `detail` field is specific and worth reading — it is what distinguishes a
media type Veraison has never heard of from one whose scheme plugin failed to
load in this deployment.

| Code | Usually means |
|---|---|
| 400 | bad nonce request (`nonce` and `nonceSize` together, or size outside 8–64) |
| 401 | missing or invalid bearer token |
| 403 | valid token, wrong realm role |
| 404 | session expired or already deleted |
| 415 | media type not handled by any loaded scheme plugin |

## Command-line tools

Veraison's CLIs — `evcli` (evidence), `cocli` (endorsements/CoRIM), `pocli`
(policy) — are **not in the service images**. The docker deployment builds them
into its deploy directory, but the Kubernetes manifests do not include them.
Install them where you need them:

```sh
go install github.com/veraison/evcli/v2@latest
go install github.com/veraison/cocli@latest
go install github.com/veraison/pocli@latest
```

The config templates under `deployments/docker/src/*-config.yaml.template` show
the expected shape; substitute your own host and port.

> One caveat if you copy `pocli-config.yaml.template`: it authenticates as
> `veraison-provisioner`, but the management API requires the `manager` role, so
> that configuration should yield a 403. Use `veraison-manager` instead. This
> looks like an upstream mistake rather than something intentional.

## Gotchas

* **HTTP 200 is not a pass.** Decode the EAR and check `ear.status`. This is the
  single easiest way to build something that believes every device is healthy.
* **Verify the EAR signature** against `ear-verification-key`, and check
  `eat_nonce`. Otherwise a result can be forged or replayed.
* **Sessions expire in 2m30s.**
* **Media types are deployment-specific.** Always read `.well-known` first; a
  scheme plugin that failed to load silently removes its media types.
* **NVIDIA GPU attestation is off unless configured.** If the NVIDIA media type
  is missing from the discovery document, the scheme did not load — see
  [README.md](README.md#nvidia-gpu-attestation).
* **The verification API has no authentication.**
* **The bundled Keycloak credentials and TLS keys are public development
  defaults.** The client secret above is committed to the Veraison repository.
