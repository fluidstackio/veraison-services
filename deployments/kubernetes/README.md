# Veraison on Kubernetes

Manifests for running the images produced by `deployments/docker` in a
Kubernetes cluster. These are not upstream; they were derived from the docker
deployment and the differences below are deliberate.

* **[DEPLOYMENT.md](DEPLOYMENT.md)** — the step-by-step procedure: prerequisites,
  registry, packaging, deploying, verifying, day-two operations, troubleshooting.
* **[USAGE.md](USAGE.md)** — how to use the running service: authentication,
  verifying evidence, provisioning endorsements, managing policy, and how to read
  an attestation result.

This document covers how the images are built and why the manifests look like
they do.

## Building the images

The Kubernetes manifests consume the images the docker deployment builds. From
`deployments/docker`:

```sh
make all
```

That produces `veraison/vts`, `veraison/provisioning`, `veraison/verification`,
`veraison/management`, `veraison/coserv` and `veraison/keycloak`, plus the
`veraison/builder` and `veraison/manager` images used to build them.

Nothing under `deployments/docker` needs to be modified to build these — see
the note below if you build on macOS.

### Build paths on macOS

`deployment.cfg` puts the build context in `/tmp`, which works on Linux but not
on macOS with colima. There the docker daemon runs inside a VM, so the deploy
container writes the context to the VM's `/tmp` while the docker CLI reads the
context from the host. Those are two different directories, and every service
image build gets an empty context.

Point both at a path bind-mounted into the VM (`colima start --mount`). Pass
them on the make command line rather than editing `deployment.cfg` — make gives
command-line variables precedence over the `include`, so the checkout stays
clean:

```sh
make DEPLOY_DEST="$HOME/src/veraison-deploy" \
     CONTEXT_DIR="$HOME/src/veraison-build-context" \
     <targets>
```

On Linux the defaults are fine and no override is needed.

### Architecture

The build must run on the target architecture. `scheme/nvidia` is cgo bound to
NVIDIA's `libnvat`, which the builder installs from NVIDIA's CUDA apt repo, so
the binaries cannot be cross-compiled with `GOARCH` alone. `libnvat` is
published for both `x86_64` and `sbsa`, so either architecture works.

Building `linux/amd64` on an Apple Silicon host **requires Rosetta**. Under
QEMU it does not work at all: `qemu-x86_64` mis-emulates the Go runtime badly
enough that the `go` command itself segfaults within half a second of starting
`go mod download`, while parsing `go.sum`. Adding `GODEBUG=asyncpreemptoff=1` to
the builder image only relocates the crash — it was tried, and is not worth
repeating. Set up Rosetta once:

```sh
softwareupdate --install-rosetta --agree-to-license
colima start --vm-type vz --vz-rosetta --cpu 8 --memory 10 --disk 100 \
    --mount-type virtiofs --mount "$HOME/src:w"
```

Confirm `/proc/sys/fs/binfmt_misc/rosetta` is `enabled` and `qemu-x86_64` is
`disabled` inside the VM, then build with `DOCKER_DEFAULT_PLATFORM=linux/amd64`.
A native `linux/amd64` build host or CI runner works too, and is the better
option if you build these often.

### Building both architectures

The Makefile always tags its output `veraison/<service>:latest`, so a second
build overwrites the first. To keep both, tag after each build and clean the Go
artifacts in between — the compiled binaries live in the mounted source tree,
and a stale set from the other architecture would be copied straight into the
images:

Use **arrays**, and expand them quoted. These must not be plain strings: zsh —
the default shell on macOS — does not word-split unquoted parameters, so
`make $PATHS ...` passes both assignments to make as a single variable value and
the build dies in the deploy step with
`invalid reference format: repository name ... must be lowercase`. Arrays behave
the same in bash and zsh.

```sh
SERVICES=(vts provisioning verification management coserv keycloak)
IMAGES=(vts-image provisioning-image verification-image
        management-image coserv-image keycloak-image)

# macOS/colima only -- see "Build paths on macOS" above. Use PATHS=() on Linux.
PATHS=(DEPLOY_DEST="$HOME/src/veraison-deploy"
       CONTEXT_DIR="$HOME/src/veraison-build-context")

# arm64 (native on Apple Silicon)
make "${PATHS[@]}" "${IMAGES[@]}"
for s in "${SERVICES[@]}"; do docker image tag "veraison/${s}:latest" "veraison/${s}:arm64"; done

# Clean between the two. The Go build writes into the mounted source tree, so a
# stale tree from the other architecture would be copied straight into the next
# set of images. Pass "${PATHS[@]}" here too, or host-clean cleans the wrong
# directories and leaves that stale tree in place.
make "${PATHS[@]}" clean host-clean && rm -rf .built

# amd64 (via Rosetta)
DOCKER_DEFAULT_PLATFORM=linux/amd64 make "${PATHS[@]}" "${IMAGES[@]}"
for s in "${SERVICES[@]}"; do docker image tag "veraison/${s}:latest" "veraison/${s}:amd64"; done
```

Re-tag immediately after each build, before starting the next: the Makefile
writes `:latest`, so tagging late (or after a failed build) points the arch tag
at whichever image was built last.

Arch-suffixed tags are the local-only approach. Once these go to a registry,
publish a real multi-arch manifest instead so the tag resolves per node:

```sh
docker buildx imagetools create -t registry.example.com/veraison/vts:v0.0.2609 \
    registry.example.com/veraison/vts:amd64 \
    registry.example.com/veraison/vts:arm64
```

## Deploying

See [DEPLOYMENT.md](DEPLOYMENT.md). In short: push the images to a registry the
cluster can pull from, repoint the manifests with `kustomize edit set image`,
then `kubectl apply -k deployments/kubernetes`.

## How this differs from the docker deployment

**vts and management share a Pod.** Both open the same SQLite files directly —
vts uses `stores/vts/store.sql` and `stores/vts/po-store.sql`, and
`management/policy.go` opens the same po-store. SQLite locking is only safe
across processes on one filesystem, so the two must be co-scheduled and share a
volume, exactly as they share the `veraison-stores` docker volume today. That
also means one replica and a `Recreate` strategy — a rolling update would put
two pods on one RWO volume. `provisioning`, `verification` and `coserv` hold no
local state and scale horizontally.

**The stores are seeded by an init container.** A named docker volume inherits
the image's content at the mount point on first use; a Kubernetes volume mounts
empty and hides the initialised databases baked into the vts image at
`/opt/veraison/stores/vts`. The `seed-stores` init container mounts the claim at
`/mnt/stores` — where it does not shadow the image copy — and copies in anything
missing. It never overwrites existing files, so restarts and upgrades keep data.

**Config comes from a ConfigMap, not the baked-in file.** `veraison-config` is
mounted over `/opt/veraison/config.yaml` so it can be changed without rebuilding
images. It drops the `logs/<service>-stdout.log` output path so logging goes to
the container log stream only, which also removes the need for a writable logs
volume in every pod. Note that Veraison's viper setup calls `AutomaticEnv` with
a `veraison` prefix but no key replacer, so nested settings cannot be overridden
with environment variables — the ConfigMap is the way to change these.

**Every container sets `imagePullPolicy: IfNotPresent`.** These images are not
on a public registry, so `veraison/*` — which resolves to Docker Hub — can never
be pulled. `IfNotPresent` lets nodes use images loaded directly into containerd,
and stops a pinned tag being re-fetched. It is also the right policy once the
images are in your own registry, because the tags are versioned rather than
mutable; `latest` would default to `Always` and fail.

**Service names are load-bearing.** The service certificates in
`deployments/docker/src/certs` carry SANs for the short names (`DNS:vts-service`,
`DNS:keycloak-service`), and `vts.server-addr` and `auth.host` in the config
resolve them. Renaming a Service breaks in-cluster TLS verification.

## NVIDIA GPU attestation

Veraison does not implement GPU attestation itself. It binds NVIDIA's
attestation SDK, `libnvat`, through cgo and `dlopen`s `libnvat.so.1` at runtime
([scheme/nvidia/nvat_bindings.go](../../scheme/nvidia/nvat_bindings.go)). NVIDIA
supplies the SDK (apt packages `libnvat` and `libnvat-dev` from the CUDA repo),
the NRAS attestation service, a RIM service for reference measurements, and an
OCSP responder.

`verifier_mode` picks where appraisal happens: `remote` sends evidence to NRAS,
`local` appraises in-process inside libnvat. **Neither is offline** — `local`
still creates a remote RIM store and OCSP client, and Veraison binds no offline
RIM store constructor. Both modes need egress to NVIDIA.

Be aware how thin the Veraison side is. For this scheme `ValidateEvidenceIntegrity`
is a no-op, `GetTrustAnchorIDs` and `GetReferenceValueIDs` return `nil` (no CoRIM
endorsements participate), and the claims collection libnvat returns is freed
without being read. A pass therefore collapses to two EAR claims —
`GenuineHardwareClaim` and `EncryptedMemoryRuntimeClaim` — with no per-GPU
detail. All trust decisions belong to NVIDIA's SDK.

### Local changes to the service images

`vts.docker` and `management.docker` are modified from upstream: they are based
on `ubuntu:24.04` instead of `debian` and install the `libnvat` runtime package.

Upstream builds these `FROM debian`, and the builder image installs
`libnvat-dev` — so the plugin *compiles* but the runtime library is absent from
the service images, and the plugin fails to load at startup:

```
ERROR plugin q: nvidia-scheme-plugin ... failed to load NVAT library:
libnvat.so.1: cannot open shared object file: No such file or directory
```

The base image had to change with it: `libnvat` is not published in NVIDIA's
`debian13` repository (only `ubuntu2404`, for both `x86_64` and `sbsa`), and the
library links against `libicuuc.so.74` — Ubuntu 24.04's ICU, where Debian trixie
ships ICU 76 — so lifting the `.so` across distributions would not have worked
either.

Only `vts` and `management` load scheme plugins and need this; `provisioning`
does not, and is untouched.

Check NVIDIA's redistribution terms for `libnvat` before publishing these images
to a registry.

## Before this is production-ready

* **Replace the certificates.** `deployments/docker/src/certs` is committed to
  the repository — the service private keys and, in the upstream checkout, the
  root CA key are public. Regenerate with `deployments/docker/src/certs/gen-certs`
  and deliver them as Secrets rather than baking them into images. Note the
  current certs are also baked in at image build time, so replacing them
  properly means mounting Secrets over the `.crt`/`.key` paths.
* **Replace the Keycloak admin Secret** and move Keycloak off the embedded H2
  database; as configured it discards state on every restart.
* **Decide on ingress.** Everything is ClusterIP. The service APIs are HTTPS
  with a private CA, so if you terminate TLS at an ingress the clients still
  need to trust that CA, or the ingress needs to re-encrypt to the backends.
  For a quick check, port-forward instead:
  `kubectl -n veraison port-forward svc/verification-service 8443:8443`
* **Configure the NVIDIA scheme if you need GPU attestation.** The images now
  carry `libnvat`, but the scheme still stays off until you add a `scheme`
  section with a `verifier_mode` and, for `remote`, a token — see the commented
  block at the end of `configmap-config.yaml` and
  [NVIDIA GPU attestation](#nvidia-gpu-attestation) above. Both modes need
  egress to NVIDIA.
* **Review the resource requests/limits** — they are conservative placeholders,
  not measurements.

## What was verified

Both image sets were built and checked:

* Image manifests report the expected `linux/amd64` and `linux/arm64`, and the
  ELF `e_machine` of `vts-service` and `scheme-nvidia.plugin` inside each image
  matches (`0x3e` / `0xb7`) — so no cross-architecture binaries leaked through
  the shared build tree.
* `kubectl kustomize` renders all 15 resources.
* vts starts against this ConfigMap and reaches
  `listening for GRPC requests {"address": ":50051"}` with TLS.
* With the image's *baked-in* config it instead dies with
  `could not configure logging: open sink "logs/vts-stdout.log"`, because the
  vts image has no `logs` directory — the docker deployment supplies one via a
  volume. That is the concrete reason this ConfigMap drops the file sink.
* vts and verification were run together on a container network with the
  hostnames the Services use. verification reached vts over gRPC/TLS against the
  private CA — `vts connection established {"server-version": "0.0.2609+3e6d113"}`
  — which is what confirms the certificate SANs match the short Service names.
* `GET /.well-known/veraison/verification` returns the EAR verification key and
  the supported media types, both with `curl -k` and with full verification via
  `--cacert rootCA.crt`.
* The `libnvat` fix was checked by before/after, not just by the error going
  away. With a `scheme.nvidia` section configured, the unpatched image does not
  register the NVIDIA evidence media type
  (`application/eat-ucs+json; eat_profile="tag:github.com,2024:veraison/ratsd"`)
  and logs `failed to load NVAT library`; the patched image registers it and
  starts clean. `libnvat` 1.2.2 resolves via `ldconfig` in both images.

Not verified:

* **An actual cluster.** Nothing here has been applied to one, so StorageClass
  behaviour — in particular whether your CSI driver honours `fsGroup: 616`,
  which the store seeding depends on — is untested.
* **Real GPU evidence, or that a token is accepted by NRAS.** The checks above
  prove the plugin loads and the scheme registers; they do not prove end-to-end
  attestation against NVIDIA succeeds.
