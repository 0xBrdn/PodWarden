# PodWarden

[![Go 1.23+](https://img.shields.io/badge/go-1.23+-blue.svg?style=flat-square)](https://go.dev/)
[![Kubernetes](https://img.shields.io/badge/kubernetes-1.31+-326CE5.svg?style=flat-square)](https://kubernetes.io/)
[![Falco](https://img.shields.io/badge/falco-modern__ebpf-00AEC7.svg?style=flat-square)](https://falco.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

Automated Kubernetes runtime incident response controller, written in Go.

PodWarden consumes high-severity eBPF syscall alerts emitted by Falco through Falcosidekick, captures container forensics (pod metadata and recent logs), terminates the compromised pod, and writes an HMAC-SHA256-signed incident report that can be verified offline.

It is meant to shorten attacker dwell time and preserve evidence, not to replace inline prevention: see [Limitations](#limitations).

---

## Why PodWarden

Most runtime security stacks stop at sending an alert to a chat channel. By the time someone reads it, the attacker has moved on and the logs disappeared together with the pod.

PodWarden closes that loop automatically and keeps the evidence:

- **Detect to contain**: a Falco alert becomes a pod termination through a single authenticated webhook.
- **Forensics first**: metadata, owners, ServiceAccount and the last log lines of every container are captured before the pod is deleted.
- **Tamper-evident reports**: each incident is signed with HMAC-SHA256 over the entire report and can be checked offline with `pwverify`.
- **Bounded blast radius**: protected namespaces, alert deduplication, a deletion circuit breaker, `DRY_RUN`, and UID-pinned deletes.
- **Small attack surface**: one static binary, distroless nonroot image, read-only root filesystem, least-privilege RBAC and a NetworkPolicy.

---

## Quick start

```bash
make kind-load                       # build the image and load it into the kind lab cluster
kubectl apply -f deploy/namespace.yaml
# ... secrets, Falco: see "Deployment lab" below

kubectl apply -f demo/vulnerable-app.yaml
./demo/simulate_attack.sh
```

The script reads a ServiceAccount token inside a `prod-apps` pod, waits for PodWarden to terminate it, prints the measured delay and shows the signed incident report.

---

## Validation

The unit tests use the client-go fake clientset and cover:

- Webhook authentication (missing and wrong secret, 1 MiB body limit)
- Severity filtering (`emergency`, `alert`, `critical`, `error` act; lower priorities are ignored)
- Protected namespaces and `DRY_RUN` never delete
- Malformed namespace or pod names (path traversal, uppercase, slashes) are rejected
- Alert deduplication and circuit breaker behaviour
- Report signing, verification and tamper detection on individual fields
- Configuration validation (missing or weak secrets, invalid durations)

```bash
make test        # go test -race -count=1 ./...
make cover       # with coverage summary
```

CI also runs `go vet`, `golangci-lint`, `govulncheck` and a Docker build.

**How to read this.** The tests validate the logic against a fake Kubernetes API. They say nothing about Falco detection quality or real-world latency. The end-to-end simulation (`demo/simulate_attack.sh`) prints the attack-to-pod-gone delay measured on your own cluster; no latency figure is published here because it depends on the node, the driver and the Falcosidekick configuration.

---

## Limitations

- **Detection is asynchronous.** Alerts travel from the kernel ring buffer through Falco, Falcosidekick and an HTTP webhook. A fast automated payload can exfiltrate data before the pod is killed. PodWarden reduces dwell time and blocks interactive post-exploitation; it does not replace inline prevention.
- **The Deployment respawns the pod.** Terminating a compromised pod makes its ReplicaSet start a fresh replica from the same image. If the underlying vulnerability is not patched or isolated, the new pod can be exploited again.
- **Filesystem evidence is lost.** Deleting a pod destroys its writable layer and memory. PodWarden keeps metadata and logs, not a disk or memory image. A quarantine mode is on the roadmap.
- **Rules need tuning.** Operators and controllers legitimately read their ServiceAccount token, and probes may call `curl` or `wget`. Start with `DRY_RUN=true` and allow-list known workloads before enforcing.
- **The circuit breaker favours availability.** When the deletion budget is exhausted, PodWarden keeps collecting and signing evidence but stops killing. Tune `MAX_ACTIONS_PER_MINUTE` to the size of the fleet.
- **HMAC is not non-repudiation.** The signature proves integrity to whoever holds the key. Asymmetric signatures are on the roadmap.
- **Reports are sensitive.** Captured container logs may contain secrets. Incident files live on an `emptyDir` volume in the lab; forward the stdout JSON line to an immutable log collector in production.
- **Hardening is still required.** Runtime containment must be paired with default-deny egress NetworkPolicies and `automountServiceAccountToken: false` on pods that do not need the Kubernetes API.

---

## Architecture

```
[Compromised Pod (ns: prod-apps)]
       |  (interactive shell, recon binary, ServiceAccount token read)
       v
[Linux Kernel (modern_ebpf)]
       |
       v
[Falco DaemonSet + custom rules] ---> [Falcosidekick]
                                             |  POST /webhook
                                             |  Header: X-Webhook-Secret
                                             v
                             [PodWarden Responder (Go)] (ns: podwarden-system)
```

```
cmd/
├── podwarden/main.go        # HTTP server entry-point (/webhook, /healthz, /readyz)
└── pwverify/main.go         # Offline verification of incident report signatures
internal/
├── config/                  # Environment configuration and validation
├── k8s/
│   ├── responder.go         # Forensics collector, HMAC signer/verifier, pod terminator
│   └── guard.go             # Alert deduplication and deletion circuit breaker
└── webhook/
    ├── handler.go           # Falcosidekick payload parser and authentication
    └── handler_test.go      # Unit tests (client-go fake clientset)
deploy/                      # Namespaces, RBAC, NetworkPolicy, Deployment
falco/                       # Custom rules (MITRE ATT&CK tagged) and Helm values
demo/                        # Vulnerable app and attack simulation script
```

Data flow:

1. The handler authenticates the request, validates the payload and filters on severity
2. Protected namespaces and duplicate alerts are dropped
3. `HandleAlert()` collects pod metadata and container logs
4. The pod is deleted with a UID precondition, unless `DRY_RUN` is set or the circuit breaker is open
5. The full report is signed and emitted (one JSON line on stdout, one file on disk)

---

## Requirements

- Kubernetes 1.31+ (the lab uses kind)
- Falco with the `modern_ebpf` driver (kernel 5.8+ with BTF) and Falcosidekick
- Go 1.23+ to build from source
- A CNI that enforces NetworkPolicy, otherwise `deploy/networkpolicy.yaml` is accepted but inert

---

## Deployment lab

Tested layout: Ubuntu 26.04 Server, Docker, `kubectl`, `kind` and `helm`.

### 1. Create the kind cluster

```bash
kind create cluster --name podwarden-lab
kubectl cluster-info --context kind-podwarden-lab
```

### 2. Build and load the controller image

```bash
make kind-load
```

The tag must match the `image:` in `deploy/deployment.yaml`.

### 3. Deploy namespaces, RBAC, secrets and controller

Generate the secrets once and reuse the webhook secret for Falcosidekick:

```bash
kubectl apply -f deploy/namespace.yaml
kubectl create namespace falco
kubectl apply -f deploy/rbac.yaml

WEBHOOK_SECRET="$(openssl rand -hex 24)"
HMAC_KEY="$(openssl rand -hex 32)"

kubectl create secret generic podwarden-secrets \
  --namespace podwarden-system \
  --from-literal=webhook-secret="${WEBHOOK_SECRET}" \
  --from-literal=hmac-signing-key="${HMAC_KEY}"

# Same secret, in the shape Falcosidekick expects (keeps it out of Helm values)
kubectl create secret generic falcosidekick-webhook \
  --namespace falco \
  --from-literal=WEBHOOK_CUSTOMHEADERS="X-Webhook-Secret:${WEBHOOK_SECRET}"

kubectl apply -f deploy/deployment.yaml
kubectl apply -f deploy/networkpolicy.yaml
kubectl rollout status deployment/podwarden-responder -n podwarden-system
```

### 4. Deploy Falco and Falcosidekick

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm install falco falcosecurity/falco \
  --namespace falco \
  -f falco/values.yaml \
  --set-file customRules."podwarden_rules\.yaml"=falco/podwarden_rules.yaml \
  --set falcosidekick.config.existingSecret=falcosidekick-webhook

kubectl rollout status daemonset/falco -n falco
```

### 5. Observe first, enforce later

```bash
kubectl set env deployment/podwarden-responder -n podwarden-system DRY_RUN=true
```

Reports are still produced and signed (`"action": "dry-run"`) but nothing is deleted. Set it back to `false` once the rules are quiet.

---

## Usage

### Attack simulation

```bash
kubectl apply -f demo/vulnerable-app.yaml
kubectl wait --for=condition=ready pod -l app=vulnerable-app -n prod-apps --timeout=60s

./demo/simulate_attack.sh          # ServiceAccount token theft
./demo/simulate_attack.sh wget     # forbidden recon binary
```

Expected flow:

1. The script reads `/var/run/secrets/kubernetes.io/serviceaccount/token` inside a `prod-apps` pod.
2. Falco captures the `openat` syscall and triggers `PodWarden K8s ServiceAccount Token Access` (`CRITICAL`).
3. PodWarden captures pod metadata and container logs, emits a signed incident report and deletes the pod.
4. The Deployment controller schedules a clean replacement replica.

### Incident report

One compact JSON line per incident is written to stdout (suitable for Loki, Fluent Bit, Vector or a SIEM), plus a formatted copy under `INCIDENT_DIR`. Abridged example:

```json
{
  "schema_version": 2,
  "incident_id": "pw-20260316T142305Z-a1b2c3-vulnerable-app-7d8f9c-x2k4p",
  "rule": "PodWarden K8s ServiceAccount Token Access",
  "priority": "Critical",
  "namespace": "prod-apps",
  "pod_name": "vulnerable-app-7d8f9c-x2k4p",
  "service_account": "default",
  "owners": ["ReplicaSet/vulnerable-app-7d8f9c"],
  "images": ["nginx:1.25-alpine"],
  "container_logs": { "app": "..." },
  "action": "deleted",
  "dry_run": false,
  "hmac_sha256": "9c1f..."
}
```

`action` is one of `deleted`, `dry-run`, `already-gone`, `delete-failed` or `skipped-rate-limited`.

### Verify a report offline

```bash
go run ./cmd/pwverify -key "${HMAC_KEY}" incident.json
```

The signature covers every field of the report, so editing the rule, the logs, the images or the action invalidates it.

---

## Detection rules

| Rule | Priority | Technique | Triggers on |
|------|----------|-----------|-------------|
| `PodWarden Interactive Shell Spawned` | ERROR | T1059.004 | A shell with a TTY (`kubectl exec -it`) |
| `PodWarden Forbidden Recon Binary` | CRITICAL | T1046, T1105 | `curl`, `wget`, `nc`, `ncat`, `netcat`, `nmap`, `socat` |
| `PodWarden K8s ServiceAccount Token Access` | CRITICAL | T1552.007 | Read of the ServiceAccount token directory |
| `PodWarden Sensitive File Read` | CRITICAL | T1003.008 | Read of `/etc/shadow` or `/etc/sudoers` |

Every rule triggers an automatic response, so they are deliberately narrow. Workloads that legitimately read their token can be allow-listed in `podwarden_sa_token_allowed_procs`.

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBHOOK_SECRET` | required (16+ chars) | Shared secret expected in `X-Webhook-Secret` |
| `HMAC_SIGNING_KEY` | required (32+ chars) | Key used to sign incident reports |
| `DRY_RUN` | `false` | Collect, sign and log, but never delete |
| `PROTECTED_NAMESPACES` | `kube-system,kube-public,kube-node-lease,podwarden-system,falco` | Namespaces PodWarden never acts on |
| `DEDUP_WINDOW` | `30s` | Ignore repeated alerts for the same pod (`0` disables) |
| `MAX_ACTIONS_PER_MINUTE` | `10` | Deletion circuit breaker (`0` disables) |
| `LOG_TAIL_LINES` | `50` | Log lines captured per container |
| `LISTEN_ADDR` | `:8080` | HTTP listen address |
| `INCIDENT_DIR` | `/var/log/podwarden/incidents` | Where formatted reports are written (best effort) |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

---

## Webhook responses

| Code | Meaning |
|------|---------|
| 200 | `processed`, `ignored` (low priority), `blocked` (protected namespace) or `duplicate` |
| 400 | Invalid JSON, or missing or malformed namespace/pod identity |
| 401 | Missing or wrong `X-Webhook-Secret` |
| 413 | Payload larger than 1 MiB |
| 500 | The report could not be produced |

`GET /healthz` is the liveness probe. `GET /readyz` returns 200 only if the Kubernetes API answers.

---

## Security design

- **Webhook authentication**: the `X-Webhook-Secret` header is compared in constant time (`crypto/subtle`, on SHA-256 digests so the length never leaks). Request bodies are capped at 1 MiB.
- **Input validation**: namespace and pod names must be valid DNS-1123 names before they reach the Kubernetes API or the filesystem.
- **Least-privilege RBAC**: `get`, `list` and `delete` on `pods`, `get` on `pods/log`. No cluster-admin and no secret access.
- **Network isolation**: a NetworkPolicy only lets the `falco` namespace reach the responder on port 8080.
- **Anti-self-DoS**: system namespaces are protected via `PROTECTED_NAMESPACES` and excluded from the Falco rules.
- **Blast-radius control**: per-pod alert deduplication and a deletion circuit breaker.
- **Safe deletion**: the pod UID captured during forensics is sent as a delete precondition, so a stale alert can never kill a recreated pod that reuses the name.
- **Forensics before termination**: metadata and logs are captured before the pod is deleted.
- **Tamper-evident reports**: the HMAC covers the whole report and is verifiable with `pwverify`.
- **Detached response context**: containment keeps running even if Falcosidekick times out and closes the connection. Graceful shutdown drains in-flight alerts.
- **Hardened runtime**: static binary (`CGO_ENABLED=0`) on `gcr.io/distroless/static-debian12:nonroot`, with `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault`, all capabilities dropped, and a namespace enforcing the `restricted` Pod Security Standard.

---

## Development

```bash
make build       # binaries in ./bin
make test        # unit tests with the race detector
make lint        # golangci-lint
make docker      # container image
make demo        # attack simulation
```

---

## Roadmap

- Quarantine mode (relabel and deny-all NetworkPolicy) to preserve the live filesystem
- Per-rule actions (`kill`, `quarantine`, `notify`) from a policy file
- Asymmetric signatures (Ed25519)
- Report shipping to S3 or MinIO with Object Lock
- Prometheus metrics and chat notifications
- Helm chart and signed images (cosign, SBOM)

---

## License

MIT, see [LICENSE](LICENSE).
