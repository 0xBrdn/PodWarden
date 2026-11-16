<div align="center">

# 🛡️ PodWarden

**Kill the compromised pod. Keep the evidence. Sign the report.**

Automated Kubernetes runtime incident response, written in Go.

[![CI](https://img.shields.io/github/actions/workflow/status/0xBrdn/PodWarden/ci.yml?branch=main&style=flat-square&label=CI)](https://github.com/0xBrdn/PodWarden/actions)
[![Go 1.23+](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.31+-326CE5?style=flat-square&logo=kubernetes&logoColor=white)](https://kubernetes.io/)
[![Falco eBPF](https://img.shields.io/badge/Falco-modern__ebpf-00AEC7?style=flat-square)](https://falco.org/)
[![Distroless](https://img.shields.io/badge/image-distroless%20nonroot-4285F4?style=flat-square&logo=google&logoColor=white)](https://github.com/GoogleContainerTools/distroless)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20tagged-E3262E?style=flat-square)](https://attack.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

</div>

PodWarden listens for high-severity eBPF syscall alerts emitted by Falco via Falcosidekick, captures container forensics (pod metadata and recent logs), terminates the compromised pod, and writes an **HMAC-SHA256-signed incident report** that you can verify offline.

Author: **0xBrdn**
License: MIT

---

## Why PodWarden?

Most runtime security stacks stop at *"send an alert to Slack"*. Someone reads it twenty minutes later, the attacker is long gone, and the logs went with the pod.

PodWarden closes that loop in seconds, **without losing the evidence**:

| | |
|---|---|
| ⚡ **Detect → contain** | A Falco alert becomes a pod termination through a single authenticated webhook. |
| 🔬 **Forensics first** | Metadata, owners, ServiceAccount and the last log lines of **every** container are captured *before* the pod is deleted. |
| ✍️ **Tamper-evident** | Each incident is signed with HMAC-SHA256 over the **entire** report. `pwverify` checks it offline. |
| 🧯 **Can't hurt you back** | Protected namespaces, alert dedup, a deletion circuit breaker, `DRY_RUN`, and UID-pinned deletes. |
| 🔒 **Boring to run** | One static binary, distroless/nonroot, read-only rootfs, least-privilege RBAC, NetworkPolicy included. |
| 🧪 **Tested** | Unit tests with the client-go fake clientset: auth, filtering, dedup, breaker, signing, tampering. |

---

## Architecture

```text
[Compromised Pod (ns: prod-apps)]
       |  (e.g., interactive shell, recon binary, ServiceAccount token read)
       v
[Linux Kernel (Ubuntu 26 / modern_ebpf)]
       |
       v
[Falco DaemonSet + Custom Rules] ---> [Falcosidekick]
                                             |  POST /webhook
                                             |  Header: X-Webhook-Secret
                                             v
                             [PodWarden Responder (Go)] (ns: podwarden-system)
                               ├── 1. Authenticate webhook secret (constant-time)
                               ├── 2. Filter severity (>= Error), validate names, check protected namespaces
                               ├── 3. Deduplicate alert bursts per pod
                               ├── 4. Collect pod metadata + last 50 log lines of every container
                               ├── 5. Terminate the pod (GracePeriodSeconds: 0, UID precondition)
                               │      └── circuit breaker: over budget => keep evidence, skip the kill
                               └── 6. Sign (HMAC-SHA256) + emit the report (stdout JSON line + file)
```

### Repository Layout

```text
PodWarden/
├── cmd/
│   ├── podwarden/main.go            # HTTP server entrypoint (/webhook, /healthz, /readyz), graceful shutdown
│   └── pwverify/main.go             # Offline CLI: verify the signature of an incident report
├── internal/
│   ├── config/                      # Environment configuration, validation & protected namespaces
│   ├── k8s/
│   │   ├── responder.go             # Forensics collector, HMAC signer/verifier & pod terminator
│   │   └── guard.go                 # Alert deduplication + deletion circuit breaker
│   └── webhook/
│       ├── handler.go               # Falcosidekick payload parser & auth middleware
│       └── handler_test.go          # Unit tests using client-go fake clientset
├── deploy/
│   ├── namespace.yaml               # podwarden-system (PSS: restricted) & prod-apps namespaces
│   ├── rbac.yaml                    # Least-privilege ServiceAccount, ClusterRole & Binding
│   ├── networkpolicy.yaml           # Only Falcosidekick can reach the responder
│   └── deployment.yaml              # Hardened non-root Deployment + emptyDir log volume
├── falco/
│   ├── podwarden_rules.yaml         # Custom eBPF detection rules (MITRE ATT&CK tagged)
│   └── values.yaml                  # Helm values for Falco (modern_ebpf) & Falcosidekick
├── demo/
│   ├── vulnerable-app.yaml          # Target Nginx/Alpine deployment (2 replicas)
│   └── simulate_attack.sh           # End-to-end token theft & active response verification
├── .github/workflows/ci.yml         # vet, race tests, golangci-lint, govulncheck, docker build
├── Makefile                         # build, test, cover, docker, kind-load, demo
└── Dockerfile                       # Multi-stage build (golang:1.23-alpine -> distroless)
```

---

## Detection Rules

Every rule is MITRE ATT&CK tagged and wired to an **automatic** response, so they are deliberately narrow.

| Rule | Priority | Technique | Triggers on |
|------|----------|-----------|-------------|
| `PodWarden Interactive Shell Spawned` | `ERROR` | T1059.004 | A shell **with a TTY** (`kubectl exec -it`, reverse shell upgraded to PTY) |
| `PodWarden Forbidden Recon Binary` | `CRITICAL` | T1046 / T1105 | `curl`, `wget`, `nc`, `ncat`, `netcat`, `nmap`, `socat` |
| `PodWarden K8s ServiceAccount Token Access` | `CRITICAL` | T1552.007 | Read of `/var/run/secrets/kubernetes.io/serviceaccount/*` |
| `PodWarden Sensitive File Read` | `CRITICAL` | T1003.008 | Read of `/etc/shadow` or `/etc/sudoers` |

> **Tune before you enforce.** Operators and controllers legitimately read their ServiceAccount token: add them to `podwarden_sa_token_allowed_procs`. Apps that call `curl`/`wget` from exec probes will trip the recon rule. Start with `DRY_RUN=true`.

---

## Deployment Lab (Ubuntu 26 Server + Kind)

### Prerequisites

- Ubuntu 26.04 Server (kernel with native BTF support for `modern_ebpf`)
- Docker, Go 1.23+, `kubectl`, `kind`, and `helm`
- A CNI that enforces `NetworkPolicy` (otherwise `deploy/networkpolicy.yaml` is accepted but inert)

### 1. Create the Kind cluster

```bash
kind create cluster --name podwarden-lab
kubectl cluster-info --context kind-podwarden-lab
```

### 2. Build and load the controller image

```bash
make kind-load
# or: docker build -t ghcr.io/0xbrdn/podwarden:0.2.0 . && kind load docker-image ghcr.io/0xbrdn/podwarden:0.2.0 --name podwarden-lab
```

> The tag must match the `image:` in `deploy/deployment.yaml`.

### 3. Deploy namespaces, RBAC, secrets, and controller

Generate the secrets **once** and reuse the webhook secret for Falcosidekick:

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

# Same secret, in the shape Falcosidekick expects (keeps it out of Helm values & history)
kubectl create secret generic falcosidekick-webhook \
  --namespace falco \
  --from-literal=WEBHOOK_CUSTOMHEADERS="X-Webhook-Secret:${WEBHOOK_SECRET}"

kubectl apply -f deploy/deployment.yaml
kubectl apply -f deploy/networkpolicy.yaml
kubectl rollout status deployment/podwarden-responder -n podwarden-system
```

### 4. Deploy Falco & Falcosidekick via Helm

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

### 5. (Recommended) Observe first, enforce later

```bash
kubectl set env deployment/podwarden-responder -n podwarden-system DRY_RUN=true
```

Reports are still produced and signed (`"action": "dry-run"`), but nothing is deleted. Flip it back to `false` once the rules are quiet.

---

## End-to-End Attack Simulation

Deploy the target workload in `prod-apps` and trigger a simulated ServiceAccount token exfiltration:

```bash
kubectl apply -f demo/vulnerable-app.yaml
kubectl wait --for=condition=ready pod -l app=vulnerable-app -n prod-apps --timeout=60s

./demo/simulate_attack.sh          # ServiceAccount token theft
./demo/simulate_attack.sh wget     # forbidden recon binary
```

Expected flow:

1. `simulate_attack.sh` reads `/var/run/secrets/kubernetes.io/serviceaccount/token` inside a `prod-apps` pod.
2. Falco captures the `openat` syscall in kernel space and triggers `PodWarden K8s ServiceAccount Token Access` (`CRITICAL`).
3. PodWarden captures pod metadata and container logs, emits a signed JSON incident report, and deletes the compromised pod (`GracePeriodSeconds: 0`).
4. The Kubernetes `Deployment` controller automatically schedules a clean replacement replica.

The script prints the measured *attack → pod gone* latency and the incident report.

---

## Incident Report

One compact JSON line per incident on **stdout** (ready for Loki / Fluent Bit / Vector / your SIEM), plus a pretty copy under `INCIDENT_DIR`.

```json
{
  "schema_version": 2,
  "incident_id": "pw-20260316T142305Z-a1b2c3-vulnerable-app-7d8f9c-x2k4p",
  "timestamp": "2026-03-16T14:23:05.412Z",
  "rule": "PodWarden K8s ServiceAccount Token Access",
  "priority": "Critical",
  "namespace": "prod-apps",
  "pod_name": "vulnerable-app-7d8f9c-x2k4p",
  "pod_uid": "5f1c0c1e-…",
  "node_name": "podwarden-lab-control-plane",
  "service_account": "default",
  "owners": ["ReplicaSet/vulnerable-app-7d8f9c"],
  "images": ["nginx:1.25-alpine"],
  "container_logs": { "app": "…last 50 lines…" },
  "action": "deleted",
  "dry_run": false,
  "hmac_sha256": "9c1f…"
}
```

*(Illustrative example, abridged.)*

`action` is one of `deleted`, `dry-run`, `already-gone`, `delete-failed` or `skipped-rate-limited`.

### Verify a report offline

```bash
go run ./cmd/pwverify -key "${HMAC_KEY}" incident.json
# VALID - signature matches        (exit 0)
# INVALID - signature mismatch ... (exit 1)
```

The signature covers **every field** of the report (rule, output, logs, images, action…), not just the headline ones: editing any of them invalidates it.

---

## Configuration

All configuration is done through environment variables.

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBHOOK_SECRET` | *required* (≥ 16 chars) | Shared secret expected in `X-Webhook-Secret` |
| `HMAC_SIGNING_KEY` | *required* (≥ 32 chars) | Key used to sign incident reports |
| `DRY_RUN` | `false` | Collect + sign + log, but never delete |
| `PROTECTED_NAMESPACES` | `kube-system,kube-public,kube-node-lease,podwarden-system,falco` | Namespaces PodWarden never acts on |
| `DEDUP_WINDOW` | `30s` | Ignore repeated alerts for the same pod (`0` disables) |
| `MAX_ACTIONS_PER_MINUTE` | `10` | Deletion circuit breaker (`0` disables) |
| `LOG_TAIL_LINES` | `50` | Log lines captured per container |
| `LISTEN_ADDR` | `:8080` | HTTP listen address |
| `INCIDENT_DIR` | `/var/log/podwarden/incidents` | Where pretty reports are written (best effort) |
| `LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

Endpoints: `POST /webhook` (authenticated), `GET /healthz` (liveness), `GET /readyz` (ready only if the Kubernetes API answers).

---

## Security Design & Safeguards

- **Webhook Authentication**: Every incoming POST request to `/webhook` must carry a valid `X-Webhook-Secret` header, compared in constant time (`crypto/subtle`, on SHA-256 digests so length never leaks). Unauthenticated requests are rejected with `401 Unauthorized`. Request bodies are capped at 1 MiB.
- **Input Validation**: Namespace and pod names from the payload must be valid DNS-1123 names before they touch the Kubernetes API or the filesystem (no path traversal in report filenames).
- **Least-Privilege RBAC**: The `podwarden-sa` `ClusterRole` grants strictly `get`, `list`, and `delete` on `pods` and `get` on `pods/log`. No cluster-admin or secret-read permissions are granted.
- **Network Isolation**: A `NetworkPolicy` only lets the `falco` namespace reach the responder on port 8080.
- **Anti-Self-DoS Protection**: System namespaces (`kube-system`, `kube-public`, `kube-node-lease`, `podwarden-system`, `falco`) are protected via `PROTECTED_NAMESPACES` and excluded from Falco rules, so false positives can't take down the control plane or the security stack itself.
- **Blast-Radius Control**: Alert bursts are deduplicated per pod, and a circuit breaker caps deletions per minute. When it opens, PodWarden keeps collecting and signing evidence but stops killing, and says so in `action`.
- **Safe Deletion**: The pod UID captured during forensics is sent as a delete precondition, so a recreated pod that reuses the same name is never killed by a stale alert.
- **Forensics Before Termination**: Pod metadata (image, labels, node, IP, owners, ServiceAccount) and the last log lines of every container are captured prior to deletion so evidence isn't lost when the container terminates.
- **Tamper-Evident Incident Reports**: Each JSON incident record includes an `hmac_sha256` signature over the whole report, derived from `HMAC_SIGNING_KEY`, verifiable by SIEM/SOAR or with `pwverify`.
- **Resilient by Design**: The response runs on a context detached from the HTTP request, so a Falcosidekick timeout cannot interrupt a containment half-way. Graceful shutdown drains in-flight alerts.
- **Hardened Container Runtime**: Compiled as a static Go binary (`CGO_ENABLED=0`) running on `gcr.io/distroless/static-debian12:nonroot` with `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault`, `capabilities.drop: ["ALL"]`, a dedicated `emptyDir` mount at `/var/log/podwarden`, and a namespace enforcing the `restricted` Pod Security Standard.

---

## Limitations & Threat Model

- **Asynchronous Detection Latency**: Because alerts travel from the kernel ring buffer through Falco, Falcosidekick, and an HTTP webhook, a fast automated payload can still exfiltrate data within milliseconds before the pod is killed. PodWarden reduces attacker dwell time and blocks interactive post-exploitation; it does not replace inline prevention.
- **ReplicaSet Respawn Loop**: Terminating a compromised pod causes its parent `Deployment` or `ReplicaSet` to spawn a fresh replica from the same image. If the underlying application vulnerability is not patched or isolated, an external attacker can re-exploit the new pod.
- **Egress & Token Hardening Required**: Runtime containment must be paired with default-deny egress `NetworkPolicy` manifests and `automountServiceAccountToken: false` on pods that do not require Kubernetes API access.
- **Ephemeral Local Storage**: Incident JSON files written to `/var/log/podwarden/incidents/` reside on an `emptyDir` volume for lab portability. The stdout JSON line is the primary channel: forward it to an external immutable log collector in production.
- **Filesystem Evidence Is Lost**: Killing a pod destroys its writable layer and memory. PodWarden preserves metadata and logs, not a disk or memory image (see the roadmap).
- **Breaker Trade-off**: An open circuit breaker deliberately favors availability over containment. Tune `MAX_ACTIONS_PER_MINUTE` to your fleet.
- **Shared-Key Signing**: HMAC proves integrity to whoever holds the key; it is not non-repudiation. Asymmetric signing is on the roadmap.
- **Secrets in Logs**: Captured container logs may contain sensitive data. Treat reports as sensitive artifacts.

---

## Testing

Run the unit test suite (uses `k8s.io/client-go/kubernetes/fake`):

```bash
make test        # go test -race -count=1 ./...
make cover       # with coverage summary
```

CI additionally runs `go vet`, `golangci-lint`, `govulncheck`, and a Docker build on every push and pull request.

---

## Roadmap

- [ ] **Quarantine mode**: relabel + deny-all `NetworkPolicy` instead of deleting, to preserve the live filesystem for analysis
- [ ] Per-rule actions (`kill` / `quarantine` / `notify`) via a policy file
- [ ] Asymmetric signatures (Ed25519) and public-key verification
- [ ] Push reports to S3 / MinIO with Object Lock
- [ ] Slack / Teams / PagerDuty notifications
- [ ] Prometheus metrics (`podwarden_incidents_total`, `podwarden_action_latency_seconds`)
- [ ] Helm chart and signed multi-arch images (cosign + SBOM)
- [ ] Namespace-level opt-in/opt-out via annotation

---

## FAQ

**Will it kill my legitimate workloads?**
Only if a rule matches them. That is why every rule is narrow, why `DRY_RUN` exists, why system namespaces are protected, and why the circuit breaker caps the damage of a bad rule.

**Why delete instead of isolate?**
Deletion is the simplest containment that works everywhere and the Deployment heals itself. Quarantine (keeping the live pod for analysis) is the first item of the roadmap.

**Does it work without Falco?**
PodWarden only needs a webhook that sends the Falco event shape (`priority`, `rule`, `output`, `output_fields` with `k8s.ns.name` and `k8s.pod.name`).

---

## License

MIT — see [LICENSE](LICENSE).
