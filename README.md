# PodWarden

[![Go 1.23+](https://img.shields.io/badge/Go-1.23+-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev/)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.31+-326CE5?style=flat-square&logo=kubernetes&logoColor=white)](https://kubernetes.io/)
[![Falco eBPF](https://img.shields.io/badge/Falco-modern__ebpf-00AEC7?style=flat-square)](https://falco.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)

Automated Kubernetes runtime incident response controller written in Go.

PodWarden listens for high-severity eBPF syscall alerts emitted by Falco via Falcosidekick, captures container forensics (pod metadata and recent logs), signs a tamper-evident incident report with HMAC-SHA256, and terminates compromised pods in real time.

Author: **0xBrdn**  
License: MIT

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
                               ├── 2. Filter severity (>= Error) & check protected namespaces
                               ├── 3. Collect pod metadata + last 50 container log lines
                               ├── 4. Write JSON forensic report + HMAC-SHA256 signature
                               └── 5. Terminate compromised pod (GracePeriodSeconds: 0)
```

### Repository Layout

```text
PodWarden/
├── cmd/podwarden/main.go            # HTTP server entrypoint (/webhook, /healthz, /readyz)
├── internal/
│   ├── config/config.go             # Environment configuration & protected namespaces
│   ├── k8s/responder.go             # Forensics collector, HMAC signer & pod terminator
│   └── webhook/
│       ├── handler.go               # Falcosidekick payload parser & auth middleware
│       └── handler_test.go          # Unit tests using client-go fake clientset
├── deploy/
│   ├── namespace.yaml               # podwarden-system & prod-apps namespaces
│   ├── rbac.yaml                    # Least-privilege ServiceAccount, ClusterRole & Binding
│   └── deployment.yaml              # Hardened non-root Deployment + emptyDir log volume
├── falco/
│   ├── podwarden_rules.yaml         # Custom eBPF detection rules (MITRE ATT&CK tagged)
│   └── values.yaml                  # Helm values for Falco (modern_ebpf) & Falcosidekick
├── demo/
│   ├── vulnerable-app.yaml          # Target Nginx/Alpine deployment (2 replicas)
│   └── simulate_attack.sh           # End-to-end token theft & active response verification
└── Dockerfile                       # Multi-stage build (golang:1.23-alpine -> distroless)
```

---

## Deployment Lab (Ubuntu 26 Server + Kind)

### Prerequisites

- Ubuntu 26.04 Server (kernel with native BTF support for `modern_ebpf`)
- Docker, Go 1.23+, `kubectl`, `kind`, and `helm`

### 1. Create the Kind cluster

```bash
kind create cluster --name podwarden-lab
kubectl cluster-info --context kind-podwarden-lab
```

### 2. Build and load the controller image

```bash
docker build -t ghcr.io/0xbrdn/podwarden:0.1.0 .
kind load docker-image ghcr.io/0xbrdn/podwarden:0.1.0 --name podwarden-lab
```

### 3. Deploy namespaces, RBAC, secrets, and controller

Create the namespaces and secrets **before** installing Falco so Falcosidekick can read `X-Webhook-Secret`:

```bash
kubectl apply -f deploy/namespace.yaml
kubectl apply -f deploy/rbac.yaml

kubectl create secret generic podwarden-secrets \
  --namespace podwarden-system \
  --from-literal=webhook-secret="$(openssl rand -hex 24)" \
  --from-literal=hmac-signing-key="$(openssl rand -hex 32)"

kubectl apply -f deploy/deployment.yaml
kubectl rollout status deployment/podwarden-responder -n podwarden-system
```

### 4. Deploy Falco & Falcosidekick via Helm

```bash
helm repo add falcosecurity [https://falcosecurity.github.io/charts](https://falcosecurity.github.io/charts)
helm repo update

helm install falco falcosecurity/falco \
  --namespace falco \
  --create-namespace \
  -f falco/values.yaml \
  --set-file customRules."podwarden_rules\.yaml"=falco/podwarden_rules.yaml \
  --set falcosidekick.config.webhook.customHeaders="X-Webhook-Secret:$(kubectl get secret podwarden-secrets -n podwarden-system -o jsonpath='{.data.webhook-secret}' | base64 -d)"

kubectl rollout status daemonset/falco -n falco
```

---

## End-to-End Attack Simulation

Deploy the target workload in `prod-apps` and trigger a simulated ServiceAccount token exfiltration:

```bash
kubectl apply -f demo/vulnerable-app.yaml
kubectl wait --for=condition=ready pod -l app=vulnerable-app -n prod-apps --timeout=60s

chmod +x demo/simulate_attack.sh
./demo/simulate_attack.sh
```

Expected flow:
1. `simulate_attack.sh` reads `/var/run/secrets/kubernetes.io/serviceaccount/token` inside a `prod-apps` pod.
2. Falco captures the `openat` syscall in kernel space and triggers `PodWarden K8s ServiceAccount Token Access` (`CRITICAL`).
3. PodWarden logs pod metadata and container logs, outputs a signed JSON incident report, and deletes the compromised pod (`GracePeriodSeconds: 0`).
4. The Kubernetes `Deployment` controller automatically schedules a clean replacement replica.

---

## Security Design & Safeguards

- **Webhook Authentication**: Every incoming POST request to `/webhook` must carry a valid `X-Webhook-Secret` header verified in constant time (`crypto/subtle`). Unauthenticated requests are rejected with `401 Unauthorized`.
- **Least-Privilege RBAC**: The `podwarden-sa` `ClusterRole` grants strictly `get`, `list`, and `delete` on `pods` and `get` on `pods/log`. No cluster-admin or secret-read permissions are granted.
- **Anti-Self-DoS Protection**: System namespaces (`kube-system`, `podwarden-system`, `falco`) are protected via `PROTECTED_NAMESPACES` and excluded from Falco rules to prevent attackers or false positives from terminating control-plane components.
- **Forensics Before Termination**: Pod metadata (image, labels, node, IP) and the last 50 container log lines are captured prior to pod deletion so forensic evidence is not lost when the container terminates.
- **Tamper-Evident Incident Reports**: Each JSON incident record includes an `hmac_sha256` signature derived from `HMAC_SIGNING_KEY` for downstream SIEM/SOAR verification.
- **Hardened Container Runtime**: Compiled as a static Go binary (`CGO_ENABLED=0`) running on `gcr.io/distroless/static-debian12:nonroot` with `readOnlyRootFilesystem: true`, `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault`, `capabilities.drop: ["ALL"]`, and a dedicated `emptyDir` mount at `/var/log/podwarden`.

---

## Limitations & Threat Model

- **Asynchronous Detection Latency**: Because alerts travel from the kernel ring buffer through Falco, Falcosidekick, and an HTTP webhook, a fast automated payload can still exfiltrate data within milliseconds before the pod is killed. PodWarden reduces attacker dwell time and blocks interactive post-exploitation; it does not replace inline prevention.
- **ReplicaSet Respawn Loop**: Terminating a compromised pod causes its parent `Deployment` or `ReplicaSet` to spawn a fresh replica from the same image. If the underlying application vulnerability is not patched or isolated, an external attacker can re-exploit the new pod.
- **Egress & Token Hardening Required**: Runtime containment must be paired with default-deny egress `NetworkPolicy` manifests and `automountServiceAccountToken: false` on pods that do not require Kubernetes API access.
- **Ephemeral Local Storage**: Incident JSON files written to `/var/log/podwarden/incidents/` reside on an `emptyDir` volume for lab portability. In production, structured stdout logs should be forwarded to an external immutable log collector.

---

## Testing

Run the unit test suite (uses `k8s.io/client-go/kubernetes/fake`):

```bash
go test -v ./...
```

---

## License

MIT — see [LICENSE](LICENSE).
