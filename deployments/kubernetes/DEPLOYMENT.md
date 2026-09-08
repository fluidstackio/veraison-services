# Deploying Veraison to Kubernetes

A step-by-step runbook for getting Veraison running on a cluster. For *why* the
manifests are shaped the way they are, see [README.md](README.md). Once it is
running, [USAGE.md](USAGE.md) covers how to actually use it.

> **Status:** the images have been built and verified, and the manifests render
> and have been checked against the images' real contents. They have **not** been
> applied to a live cluster. Treat the first deployment as a new one — work
> through [Verify the deployment](#6-verify-the-deployment) rather than assuming
> it comes up clean.

## What you are deploying

| Component | Port | Protocol | Replicas | State |
|---|---|---|---|---|
| `vts` | 50051 | gRPC/TLS | 1 | SQLite on a PVC |
| `management` | 10443 | HTTPS | 1 (same Pod as vts) | shares the vts PVC |
| `provisioning` | 9443 | HTTPS | 2 | none |
| `verification` | 8443 | HTTPS | 2 | none |
| `coserv` | 11443 | HTTPS | 2 | none |
| `keycloak` | 11111 | HTTPS | 1 | embedded H2, **ephemeral** |

`vts` and `management` run as two containers in one Pod because both open the
same SQLite files directly. That Pod is single-replica with a `Recreate`
strategy, so **upgrading it means a short outage**. The three stateless services
scale freely.

## Prerequisites

* A cluster and a working `kubectl` context. Check you are pointed at the right
  one before anything else — these manifests create a namespace and a PVC:

  ```sh
  kubectl config current-context
  ```

* A **default StorageClass**, or an explicit one for the `veraison-stores` PVC.
  The claim is `ReadWriteOnce`, 5Gi. Confirm you have a default:

  ```sh
  kubectl get storageclass
  ```

  If none is marked `(default)`, add `storageClassName:` to the PVC in
  `vts.yaml`.

* A **container registry the cluster can pull from**, and the six images pushed
  to it (steps 1–2).

* `kubectl` v1.21+ for built-in kustomize (`kubectl apply -k`). Everything here
  uses `kubectl kustomize`; a standalone `kustomize` binary works too.

## 1. Build the images

From `deployments/docker`:

```sh
make vts-image provisioning-image verification-image \
     management-image coserv-image keycloak-image
```

This produces `veraison/{vts,provisioning,verification,management,coserv,keycloak}:latest`.
No files under `deployments/docker` need editing.

On **macOS with colima** you must redirect the build paths onto something the
VM can see, or every service image builds from an empty context:

```sh
make DEPLOY_DEST="$HOME/src/veraison-deploy" \
     CONTEXT_DIR="$HOME/src/veraison-build-context" \
     vts-image provisioning-image verification-image \
     management-image coserv-image keycloak-image
```

See [README.md](README.md#build-paths-on-macos). On Linux the defaults work.

**Build on the architecture your nodes run.** `scheme/nvidia` is cgo-bound to
NVIDIA's `libnvat`, so these cannot be cross-compiled with `GOARCH`. Check what
you are targeting:

```sh
kubectl get nodes -o wide
```

If the pools are mixed, build both and publish a multi-arch manifest. The full
procedure — including the Rosetta requirement for building `linux/amd64` on
Apple Silicon, and the cleanup needed between architectures — is in
[README.md](README.md#architecture). Do not skip that cleanup: the Go build
writes into the shared source tree, and a stale tree yields images labelled one
architecture but containing binaries for the other.

Verify what you built before pushing:

```sh
docker image inspect veraison/vts:latest --format '{{.Os}}/{{.Architecture}}'
```

## 2. Push to your registry

```sh
REGISTRY=registry.example.com/veraison
TAG=v0.0.2609    # use a real version; see "Never deploy :latest" below

for s in vts provisioning verification management coserv keycloak; do
    docker image tag  "veraison/${s}:latest" "${REGISTRY}/${s}:${TAG}"
    docker image push "${REGISTRY}/${s}:${TAG}"
done
```

**Never deploy `:latest`.** The Makefile reuses that tag for every build and
architecture, so it means "whatever was built last on someone's laptop". Pin a
version tag; it is also what makes a rollback possible.

If the registry is private, create a pull secret in the namespace and attach it
to the default ServiceAccount (the manifests do not set `imagePullSecrets`):

```sh
kubectl create namespace veraison
kubectl -n veraison create secret docker-registry regcred \
    --docker-server="${REGISTRY%%/*}" \
    --docker-username=... --docker-password=...
kubectl -n veraison patch serviceaccount default \
    -p '{"imagePullSecrets":[{"name":"regcred"}]}'
```

### Alternative: package for transfer

If the build machine cannot reach the registry — or there is no registry — build
a self-contained bundle instead. Save all six images in a **single**
`docker save`, so shared base layers are stored once rather than six times:

```sh
VER=0.0.2609-3e6d113
SERVICES=(vts provisioning verification management coserv keycloak)
BUNDLE="$HOME/veraison-k8s-amd64-$VER"
mkdir -p "$BUNDLE/images" "$BUNDLE/manifests"

for s in "${SERVICES[@]}"; do
    docker image tag "veraison/${s}:amd64" "veraison/${s}:${VER}-amd64"
done

docker save $(printf "veraison/%s:${VER}-amd64 " "${SERVICES[@]}") \
    | gzip -1 > "$BUNDLE/images/veraison-images-${VER}-amd64.tar.gz"
```

Render the manifests with the same pinned tags so the two cannot drift — copy
the kustomize directory, set the tag, and render:

```sh
TMP=$(mktemp -d) && cp -r deployments/kubernetes "$TMP/k8s"
sed -i '' "s/newTag: latest/newTag: ${VER}-amd64/" "$TMP/k8s/kustomization.yaml"  # GNU sed: -i
kubectl kustomize "$TMP/k8s" > "$BUNDLE/manifests/veraison.yaml"

cd "$BUNDLE" && find . -type f ! -name SHA256SUMS -print0 | sort -z \
    | xargs -0 shasum -a 256 > SHA256SUMS
```

Expect roughly **1GB** compressed for amd64.

Verify the bundle before shipping it — that every image the manifests reference
is actually inside the archive:

```sh
tar -xzOf images/veraison-images-${VER}-amd64.tar.gz manifest.json \
    | grep -o '"veraison/[^"]*"' | tr -d '"' | sort > /tmp/in-archive
grep -oE '^\s*image: \S+' manifests/veraison.yaml | awk '{print $2}' | sort -u > /tmp/in-manifests
comm -13 /tmp/in-archive /tmp/in-manifests   # must print nothing
```

On the receiving side, import into containerd's **`k8s.io` namespace** — images
imported elsewhere are invisible to kubelet — on **every** node that could
schedule a Veraison pod:

```sh
gunzip -c veraison-images-${VER}-amd64.tar.gz | sudo ctr -n k8s.io images import -
```

This is why the manifests set `imagePullPolicy: IfNotPresent` on every
container: `veraison/*` resolves to Docker Hub, where these images do not exist,
so any attempt to pull fails. A node you forget to load gives `ImagePullBackOff`
— which is the main reason to prefer a registry.

## 3. Point the manifests at your registry

Edit the image names through kustomize rather than editing six Deployments:

```sh
cd deployments/kubernetes
for s in vts provisioning verification management coserv keycloak; do
    kustomize edit set image "veraison/${s}=${REGISTRY}/${s}:${TAG}"
done
```

Set all six to the same tag. A deployment that mixes versions across services is
not a configuration anyone has tested.

## 4. Review before applying

Four things need a decision. None of them have safe defaults.

**Certificates.** The service certs are baked into the images from
`deployments/docker/src/certs`, which is committed to the repository — the
service private keys are public, and upstream the root CA key is too. They are
fine for a scratch cluster and unacceptable anywhere else. Regenerate with
`deployments/docker/src/certs/gen-certs` and mount them as Secrets over the
`.crt`/`.key` paths. Keep the Service names: the certs' SANs are the short
names (`vts-service`, `keycloak-service`), and renaming a Service breaks
in-cluster TLS.

**Keycloak.** `keycloak.yaml` ships an `admin`/`admin` Secret carried over from
the docker deployment. Replace it. Keycloak also runs on the embedded H2
database with `--import-realm`, so **it discards all state on every restart** —
point it at a real database before anyone depends on a user or client you
created at runtime.

**NVIDIA GPU attestation.** Out of the box vts logs

```
ERROR plugin q: nvidia-scheme-plugin ... service token is required
```

and carries on *without that plugin*, which means GPU evidence is rejected as an
unsupported media type. If you need GPU attestation, uncomment the `scheme:`
block at the end of `configmap-config.yaml` and choose a mode.

Two things to plan for:

* **The pods need egress to NVIDIA**, in *both* modes. `verifier_mode: remote`
  ships evidence to NVIDIA's attestation service; `local` still creates a
  *remote* RIM store and OCSP client to fetch reference measurements and
  revocation data. Veraison binds no offline RIM store, so neither mode works
  air-gapped. `remote_host` can repoint both at a mirror. If your egress is
  restricted, this needs a NetworkPolicy exception.
* **The token cannot come from an environment variable.**
  `config.ReadRawConfig` calls `AutomaticEnv` without a key replacer, so nested
  settings are unreachable that way. A token does not belong in a ConfigMap
  either — for `remote`, move the whole config into a Secret and point the
  `config` volume at it.

Note that `vts` and `management` are built `FROM ubuntu:24.04` rather than
`debian`, because the plugin `dlopen`s `libnvat.so.1` and NVIDIA does not
publish that package for Debian. See [README.md](README.md#nvidia-gpu-attestation).

**Resource requests and limits.** The values in the manifests are conservative
placeholders, not measurements. Review them against your cluster.

Render and read the result before applying:

```sh
kubectl kustomize deployments/kubernetes | less
```

## 5. Deploy

```sh
kubectl apply -k deployments/kubernetes
```

Order does not matter; the namespace is part of the kustomization.

## 6. Verify the deployment

Watch everything settle:

```sh
kubectl -n veraison get pods -w
```

Expect one `vts` pod with `2/2` containers ready, one `keycloak`, and two each of
`provisioning`, `verification` and `coserv`.

Confirm the store seeding did what it should — this is the step most likely to
be wrong on a new cluster, because it depends on your StorageClass honouring
`fsGroup`:

```sh
kubectl -n veraison logs deploy/vts -c seed-stores
```

On a first deployment it prints `seeding /mnt/stores/vts/store.sql` and
`seeding /mnt/stores/vts/po-store.sql`. On every later restart it prints
`keeping existing ...` — it never overwrites, so your data survives.

Then confirm vts is actually serving:

```sh
kubectl -n veraison logs deploy/vts -c vts | tail -20
```

The line you are looking for is:

```
INFO	vts	listening for GRPC requests	{"address": ":50051"}
```

Finally, check that a stateless service can reach vts. The `.well-known`
endpoints sit outside the auth middleware, so they need no token:

```sh
kubectl -n veraison port-forward svc/verification-service 8443:8443 &
curl -k https://localhost:8443/.well-known/veraison/verification
```

That returns the service's media types and API map. `-k` is needed because the
cert chains to Veraison's private CA; to verify properly, pass the root:
`--cacert deployments/docker/src/certs/rootCA.crt --resolve verification-service:8443:127.0.0.1`
and address it as `https://verification-service:8443/...`.

The equivalent endpoints on the other services:

| Service | Endpoint |
|---|---|
| verification | `/.well-known/veraison/verification` |
| provisioning | `/.well-known/veraison/provisioning` |
| management | `/.well-known/veraison/management` |
| coserv | `/.well-known/coserv-configuration` |

## Accessing the services

Everything is `ClusterIP`. There is deliberately no Ingress: the APIs are HTTPS
with a private CA, so an Ingress that terminates TLS leaves clients needing to
trust that CA anyway, and one that passes through needs TLS-passthrough support.
Decide based on your ingress controller before exposing anything.

For ad-hoc access, port-forward:

```sh
kubectl -n veraison port-forward svc/provisioning-service 9443:9443
kubectl -n veraison port-forward svc/verification-service 8443:8443
kubectl -n veraison port-forward svc/management-service  10443:10443
kubectl -n veraison port-forward svc/coserv-service      11443:11443
kubectl -n veraison port-forward svc/keycloak-service    11111:11111
```

The provisioning and management APIs (as opposed to their `.well-known`
endpoints) require a Keycloak token — see `deployments/docker/src/veraison-realm.json`
for the realm's clients and roles.

## Day-two operations

### Changing configuration

Edit `configmap-config.yaml`, re-apply, then restart the consumers. The config is
mounted with `subPath`, which does **not** receive ConfigMap updates, so a
restart is mandatory:

```sh
kubectl apply -k deployments/kubernetes
kubectl -n veraison rollout restart deploy/vts deploy/provisioning \
    deploy/verification deploy/coserv
```

### Upgrading

Push new images, bump the tag in `kustomization.yaml`, apply, and watch:

```sh
kubectl -n veraison rollout status deploy/vts
```

The stateless services roll normally. `vts` uses `Recreate`, so the old Pod is
torn down before the new one starts — **expect an outage** for the duration, and
for provisioning/verification/coserv to fail their vts calls meanwhile.

The `seed-stores` init container never overwrites existing files, which means it
does **not** migrate schemas. If a Veraison release changes the store schema,
that migration is on you; back up first.

To roll back, re-apply the previous tag.

### Backing up the stores

The data is the SQLite files on the PVC. Copying a live SQLite database can
produce a torn file, so scale down first:

```sh
kubectl -n veraison scale deploy/vts --replicas=0
kubectl -n veraison wait --for=delete pod -l app.kubernetes.io/name=vts --timeout=120s
# bring up a throwaway pod with the claim attached, then:
#   kubectl -n veraison cp <pod>:/opt/veraison/stores/vts ./backup
kubectl -n veraison scale deploy/vts --replicas=1
```

### Scaling

`provisioning`, `verification` and `coserv` are stateless — scale them freely:

```sh
kubectl -n veraison scale deploy/verification --replicas=4
```

Do **not** scale `vts` above 1. Two replicas would mean two processes writing
one SQLite database across two nodes, which corrupts it — and the RWO claim will
usually block the second Pod from scheduling before that happens.

## Troubleshooting

**`seed-stores` fails, or vts logs errors opening the store.** Almost always
volume permissions. The images run as `uid=997 gid=616`, and the manifests set
`fsGroup: 616` so the mounted volume is group-writable. Some CSI drivers ignore
`fsGroup`. Check:

```sh
kubectl -n veraison exec deploy/vts -c vts -- ls -la /opt/veraison/stores/vts
kubectl -n veraison exec deploy/vts -c vts -- id
```

Files should be group `616` and group-writable.

**vts `CrashLoopBackOff` with `could not configure logging: open sink "logs/vts-stdout.log"`.**
The ConfigMap is not reaching the container, so it fell back to the config baked
into the image, which logs to a `logs/` directory the image does not have.
Confirm the mount:

```sh
kubectl -n veraison exec deploy/vts -c vts -- head -5 /opt/veraison/config.yaml
```

The first lines should be the `logging:` block with `- stdout` and no file path.

**`Could not connect to VTS server` right after a Pod starts.** Benign on its
own. The stateless services initialise their vts client before vts is
listening, log this once as a `WARN`, and retry. Confirm the retry succeeded —
the follow-up line is what matters:

```sh
kubectl -n veraison logs deploy/verification | grep -i "vts connection"
# INFO  vts connection established  {"server-version": "0.0.2609+3e6d113"}
```

If that line never appears, treat it as the next entry instead.

**`provisioning`/`verification`/`coserv` cannot reach vts, or report TLS errors.**
Either vts is not ready, or a Service was renamed. The certs' SANs are the short
Service names, so `vts-service` must be exactly that. Check:

```sh
kubectl -n veraison get svc
kubectl -n veraison exec deploy/verification -- \
    getent hosts vts-service
```

**Pod stuck `Pending`.** Usually the PVC. Check the claim bound and that a
StorageClass exists:

```sh
kubectl -n veraison get pvc veraison-stores
kubectl -n veraison describe pod -l app.kubernetes.io/name=vts | tail -20
```

**`ImagePullBackOff`.** The manifests reference `veraison/*` names that only
exist on a build machine unless you completed steps 2–3, or the registry needs a
pull secret. `kubectl -n veraison describe pod ...` names the exact reference it
tried.

**`exec format error` in any container.** The image architecture does not match
the node. Rebuild for the right architecture — see [README.md](README.md#architecture).

**vts logs `nvidia-scheme-plugin ... service token is required`.** Expected
unless you configured the NVIDIA scheme; see step 4. vts continues without that
plugin, so GPU attestation silently will not work.

## Teardown

```sh
kubectl delete -k deployments/kubernetes
```

This deletes the namespace and everything in it. **The PVC and its data go with
it.** Back up first if the stores matter — see above. Depending on your
StorageClass reclaim policy the underlying volume may also be deleted.
