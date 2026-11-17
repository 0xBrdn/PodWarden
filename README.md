<h1 align="center">PodWarden</h1>

<p align="center">
  <b>Contain compromised pods, keep the evidence</b><br>
  an automated Kubernetes runtime incident response controller: Falco alert in, forensics captured, pod terminated, HMAC-signed report out.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-F5C518?style=for-the-badge" alt="License MIT"></a>
  <img src="https://img.shields.io/badge/Go-1.23+-00ADD8?style=for-the-badge&logo=go&logoColor=white" alt="Go 1.23+">
  <img src="https://img.shields.io/badge/Kubernetes-1.31+-326CE5?style=for-the-badge&logo=kubernetes&logoColor=white" alt="Kubernetes 1.31+">
  <img src="https://img.shields.io/badge/Falco-modern__ebpf-00AEC7?style=for-the-badge" alt="Falco modern_ebpf">
  <img src="https://img.shields.io/badge/Mode-Automated_response-2E7D32?style=for-the-badge" alt="Automated response">
  <img src="https://img.shields.io/badge/Reports-HMAC--SHA256_signed-0D47A1?style=for-the-badge" alt="HMAC-SHA256 signed reports">
  <img src="https://img.shields.io/badge/Platform-Linux-555555?style=for-the-badge&logo=linux&logoColor=white" alt="Linux">
</p>

<p align="center">
  <a href="#quick-start">Quick start</a> ·
  <a href="#features">Features</a> ·
  <a href="#detection-rules-and-response-logic">Detection</a> ·
  <a href="#limitations">Limitations</a> ·
  <a href="#responsible-use">Responsible use</a> ·
  <a href="#license">License</a>
</p>

PodWarden is a single static Go binary. It consumes high-severity eBPF syscall alerts emitted by Falco
through Falcosidekick, captures container forensics (pod metadata and recent logs), terminates the
compromised pod, and writes an HMAC-SHA256-signed incident report that can be verified offline. It is
meant to shorten attacker dwell time and preserve evidence, not to replace inline prevention: read the
[limitations](#limitations) before enforcing it on a real cluster.

New here? Run `make kind-load`, deploy the lab described in [Deployment lab](#deployment-lab), and start
with `DRY_RUN=true`. Reports are still produced and signed, but nothing is deleted.

## Why it exists

Most runtime security stacks stop at sending an alert to a chat channel. By the time someone reads it,
the attacker has moved on and the logs disappeared together with the pod. PodWarden closes that loop
automatically and keeps the evidence, so that containment does not cost you the investigation.

## Features

### From alert to containment in one webhook

A Falco alert becomes a pod termination through a single authenticated webhook. The handler checks the
shared secret, validates the payload, filters on severity (`emergency`, `alert`, `critical` and `error`
act; lower priorities are ignored) and hands the alert to the responder.

### Forensics before termination

Pod metadata, owners, ServiceAccount, images and the last log lines of every container are captured
before the pod is deleted. The pod UID read during forensics is sent as a delete precondition, so a stale
alert can never kill a recreated pod that reuses the same name.

### Tamper-evident incident reports

Each incident is signed with HMAC-SHA256 over the entire report. One compact JSON line goes to stdout
(suitable for Loki, Fluent Bit, Vector or a SIEM) and a formatted copy is written under `INCIDENT_DIR`.
`pwverify` checks the signature offline: editing the rule, the logs, the images or the action invalidates
it.

### Bounded blast radius

Protected namespaces, per-pod alert deduplication, a deletion circuit breaker, `DRY_RUN` and UID-pinned
deletes keep a noisy rule from taking your cluster down with it.

### Small attack surface

One static binary (`CGO_ENABLED=0`) on a distroless nonroot image, read-only root filesystem,
least-privilege RBAC and a NetworkPolicy that only lets the `falco` namespace reach the responder.

### HTTP API

| Endpoint | Method | Purpose |
| :--- | :--- | :--- |
| `/webhook` | POST | Receive Falcosidekick alerts (requires `X-Webhook-Secret`) |
| `/healthz` | GET | Liveness probe |
| `/readyz` | GET | Readiness probe, 200 only if the Kubernetes API answers |

| Code | Meaning |
| :--- | :--- |
| 200 | `processed`, `ignored` (low priority), `blocked` (protected namespace) or `duplicate` |
| 400 | Invalid JSON, or missing or malformed namespace/pod identity |
| 401 | Missing or wrong `X-Webhook-Secret` |
| 413 | Payload larger than 1 MiB |
| 500 | The report could not be produced |

## System architecture

```text
+-----------------------------------+
|   Compromised Pod (prod-apps)     |
|  - interactive shell              |
|  - recon binary                   |
|  - ServiceAccount token read      |
+-----------------+-----------------+
                  | syscalls
                  v
+-----------------------------------+
|     Linux Kernel (modern_ebpf)    |
+-----------------+-----------------+
                  | events
                  v
+-----------------------------------+
|  Falco DaemonSet + custom rules   |
|  - MITRE ATT&CK tagged rules      |
+-----------------+-----------------+
                  | alerts
                  v
+-----------------------------------+
|           Falcosidekick           |
+-----------------+-----------------+
                  | POST /webhook
                  | Header: X-Webhook-Secret
                  v
+-----------------------------------+
|  PodWarden Responder (Go)         |
|  ns: podwarden-system             |
|  - Auth + severity filter         |
|  - Dedup + circuit breaker        |
|  - Forensics collector            |
|  - UID-pinned pod terminator      |
|  - HMAC-SHA256 report signer      |
+-----------------------------------+
```

Data flow:

1. The handler authenticates the request, validates the payload and filters on severity.
2. Protected namespaces and duplicate alerts are dropped.
3. `HandleAlert()` collects pod metadata and container logs.
4. The pod is deleted with a UID precondition, unless `DRY_RUN` is set or the circuit breaker is open.
5. The full report is signed and emitted (one JSON line on stdout, one file on disk).

## Quick start

### Prerequisites

- Kubernetes 1.31+ (the lab uses kind)
- Falco with the `modern_ebpf` driver (kernel 5.8+ with BTF) and Falcosidekick
- Go 1.23+ to build from source
- A CNI that enforces NetworkPolicy, otherwise `deploy/networkpolicy.yaml` is accepted but inert

### Build and run the lab

```sh
make kind-load                       # build the image and load it into the kind lab cluster
kubectl apply -f deploy/namespace.yaml
# ... secrets, Falco: see "Deployment lab" below

kubectl apply -f demo/vulnerable-app.yaml
./demo/simulate_attack.sh
```

The script reads a ServiceAccount token inside a `prod-apps` pod, waits for PodWarden to terminate it,
prints the measured delay and shows the signed incident report.

### Deployment lab

Tested layout: Ubuntu 26.04 Server, Docker, `kubectl`, `kind` and `helm`.

**1. Create the kind cluster**

```sh
kind create cluster --name podwarden-lab
kubectl cluster-info --context kind-podwarden-lab
```

**2. Build and load the controller image**

```sh
make kind-load
```

The tag must match the `image:` in `deploy/deployment.yaml`.

**3. Deploy namespaces, RBAC, secrets and controller**

Generate the secrets once and reuse the webhook secret for Falcosidekick:

```sh
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

**4. Deploy Falco and Falcosidekick**

```sh
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update

helm install falco falcosecurity/falco \
  --namespace falco \
  -f falco/values.yaml \
  --set-file customRules."podwarden_rules\.yaml"=falco/podwarden_rules.yaml \
  --set falcosidekick.config.existingSecret=falcosidekick-webhook

kubectl rollout status daemonset/falco -n falco
```

**5. Observe first, enforce later**

```sh
kubectl set env deployment/podwarden-responder -n podwarden-system DRY_RUN=true
```

Reports are still produced and signed (`"action": "dry-run"`) but nothing is deleted. Set it back to
`false` once the rules are quiet.

### Attack simulation

```sh
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

Abridged example:

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

```sh
go run ./cmd/pwverify -key "${HMAC_KEY}" incident.json
```

### Tests

```sh
make test        # go test -race -count=1 ./...
make cover       # with coverage summary
```

## Detection rules and response logic

1. **Falco custom rules**

   Every rule triggers an automatic response, so they are deliberately narrow.

   | Rule | Priority | Technique | Triggers on |
   | :--- | :--- | :--- | :--- |
   | `PodWarden Interactive Shell Spawned` | ERROR | T1059.004 | A shell with a TTY (`kubectl exec -it`) |
   | `PodWarden Forbidden Recon Binary` | CRITICAL | T1046, T1105 | `curl`, `wget`, `nc`, `ncat`, `netcat`, `nmap`, `socat` |
   | `PodWarden K8s ServiceAccount Token Access` | CRITICAL | T1552.007 | Read of the ServiceAccount token directory |
   | `PodWarden Sensitive File Read` | CRITICAL | T1003.008 | Read of `/etc/shadow` or `/etc/sudoers` |

   Workloads that legitimately read their token can be allow-listed in `podwarden_sa_token_allowed_procs`.

2. **Severity filtering**
   - `emergency`, `alert`, `critical` and `error` act.
   - Lower priorities are ignored and answered with `ignored`.

3. **Guardrails before any deletion**
   - Pods in `PROTECTED_NAMESPACES` are never touched.
   - A repeated alert for the same pod inside `DEDUP_WINDOW` is dropped.
   - When more than `MAX_ACTIONS_PER_MINUTE` deletions have happened, the circuit breaker opens: evidence is
     still collected and signed, but nothing is killed (`skipped-rate-limited`).
   - `DRY_RUN=true` collects, signs and logs, but never deletes.

4. **Safe deletion**
   - The pod UID captured during forensics is sent as a delete precondition.
   - Namespace and pod names must be valid DNS-1123 names before they reach the Kubernetes API or the
     filesystem.

5. **Report signing**
   - The HMAC-SHA256 covers every field of the report and is verifiable offline with `pwverify`.

## Configuration

| Variable | Default | Description |
| :--- | :--- | :--- |
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

## Security design

| Area | Measure |
| :--- | :--- |
| Webhook authentication | `X-Webhook-Secret` compared in constant time (`crypto/subtle`, on SHA-256 digests so the length never leaks); bodies capped at 1 MiB |
| Input validation | Namespace and pod names must be valid DNS-1123 names |
| Least-privilege RBAC | `get`, `list` and `delete` on `pods`, `get` on `pods/log`; no cluster-admin, no secret access |
| Network isolation | A NetworkPolicy only lets the `falco` namespace reach the responder on port 8080 |
| Anti-self-DoS | System namespaces protected via `PROTECTED_NAMESPACES` and excluded from the Falco rules |
| Blast-radius control | Per-pod alert deduplication and a deletion circuit breaker |
| Safe deletion | Pod UID sent as a delete precondition, so a stale alert never kills a recreated pod |
| Forensics first | Metadata and logs captured before the pod is deleted |
| Tamper-evident reports | HMAC over the whole report, verifiable with `pwverify` |
| Detached response context | Containment keeps running if Falcosidekick times out; graceful shutdown drains in-flight alerts |
| Hardened runtime | Static binary on `gcr.io/distroless/static-debian12:nonroot`, `readOnlyRootFilesystem`, `allowPrivilegeEscalation: false`, `seccompProfile: RuntimeDefault`, all capabilities dropped, `restricted` Pod Security Standard |

## Validation

The unit tests use the client-go fake clientset and cover:

- Webhook authentication (missing and wrong secret, 1 MiB body limit)
- Severity filtering (`emergency`, `alert`, `critical`, `error` act; lower priorities are ignored)
- Protected namespaces and `DRY_RUN` never delete
- Malformed namespace or pod names (path traversal, uppercase, slashes) are rejected
- Alert deduplication and circuit breaker behaviour
- Report signing, verification and tamper detection on individual fields
- Configuration validation (missing or weak secrets, invalid durations)

CI also runs `go vet`, `golangci-lint`, `govulncheck` and a Docker build.

**How to read this.** The tests validate the logic against a fake Kubernetes API. They say nothing about
Falco detection quality or real-world latency. The end-to-end simulation (`demo/simulate_attack.sh`)
prints the attack-to-pod-gone delay measured on your own cluster; no latency figure is published here
because it depends on the node, the driver and the Falcosidekick configuration.

## Limitations

- **Detection is asynchronous.** Alerts travel from the kernel ring buffer through Falco, Falcosidekick
  and an HTTP webhook. A fast automated payload can exfiltrate data before the pod is killed. PodWarden
  reduces dwell time and blocks interactive post-exploitation; it does not replace inline prevention.
- **The Deployment respawns the pod.** Terminating a compromised pod makes its ReplicaSet start a fresh
  replica from the same image. If the underlying vulnerability is not patched or isolated, the new pod can
  be exploited again.
- **Filesystem evidence is lost.** Deleting a pod destroys its writable layer and memory. PodWarden keeps
  metadata and logs, not a disk or memory image. A quarantine mode is on the roadmap.
- **Rules need tuning.** Operators and controllers legitimately read their ServiceAccount token, and probes
  may call `curl` or `wget`. Start with `DRY_RUN=true` and allow-list known workloads before enforcing.
- **The circuit breaker favours availability.** When the deletion budget is exhausted, PodWarden keeps
  collecting and signing evidence but stops killing. Tune `MAX_ACTIONS_PER_MINUTE` to the size of the fleet.
- **HMAC is not non-repudiation.** The signature proves integrity to whoever holds the key. Asymmetric
  signatures are on the roadmap.
- **Reports are sensitive.** Captured container logs may contain secrets. Incident files live on an
  `emptyDir` volume in the lab; forward the stdout JSON line to an immutable log collector in production.
- **Hardening is still required.** Runtime containment must be paired with default-deny egress
  NetworkPolicies and `automountServiceAccountToken: false` on pods that do not need the Kubernetes API.

## Responsible use

PodWarden **deletes workloads automatically**. This section is a plain-language summary and **not legal
advice**; you are responsible for the rules that apply to you.

**You may**

- Run it on clusters that you own, or on which you hold the written authorization of the owner or operator.
- Test it in a lab (kind, a throwaway cluster) with the provided vulnerable app and attack simulation.
- Read, modify and redistribute the source code under the terms of the MIT license.

**You must not**

- Run the attack simulation, or any Falco-triggering activity, against clusters you do not own or are not
  authorized to assess.
- Enforce it (`DRY_RUN=false`) on production before the rules have been tuned in dry-run mode.
- Treat captured logs as free of personal data: they can contain secrets or personal data subject to
  data-protection law (GDPR in the EU). Restrict access and retention accordingly.

The software is provided without warranty, as stated in the license.

## Repository layout

| Path | Contents |
| :--- | :--- |
| `cmd/podwarden/` | HTTP server entry-point (`/webhook`, `/healthz`, `/readyz`) |
| `cmd/pwverify/` | Offline verification of incident report signatures |
| `internal/config/` | Environment configuration and validation |
| `internal/k8s/` | Forensics collector, HMAC signer and verifier, pod terminator, deduplication and circuit breaker |
| `internal/webhook/` | Falcosidekick payload parser, authentication and unit tests |
| `deploy/` | Namespaces, RBAC, NetworkPolicy, Deployment |
| `falco/` | Custom rules (MITRE ATT&CK tagged) and Helm values |
| `demo/` | Vulnerable app and attack simulation script |

## Development

```sh
make build       # binaries in ./bin
make test        # unit tests with the race detector
make lint        # golangci-lint
make docker      # container image
make demo        # attack simulation
```

## Roadmap

- Quarantine mode (relabel and deny-all NetworkPolicy) to preserve the live filesystem
- Per-rule actions (`kill`, `quarantine`, `notify`) from a policy file
- Asymmetric signatures (Ed25519)
- Report shipping to S3 or MinIO with Object Lock
- Prometheus metrics and chat notifications
- Helm chart and signed images (cosign, SBOM)

## Contributing

Issues and pull requests are welcome. Add or update tests (`make test`), run `make lint`, and describe
which rule, guardrail or behavior is affected. Report security problems privately to the maintainer
instead of opening a public issue.

## License

PodWarden is free software under the [MIT License](LICENSE).
