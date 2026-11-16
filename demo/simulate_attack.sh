#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# PodWarden attack simulation
# -----------------------------------------------------------------------------
# Usage: ./demo/simulate_attack.sh [token|wget]      (default: token)
#        TIMEOUT=20 ./demo/simulate_attack.sh        (seconds to wait for the kill)
#
# 1. Picks a running pod of Deployment/vulnerable-app in prod-apps
# 2. Runs a forbidden action inside it (ServiceAccount token read OR wget)
# 3. Measures how long PodWarden needs to terminate the pod
# 4. Prints the signed forensic report and the Deployment self-healing
#
# Needs: kubectl, a cluster running PodWarden + Falco, demo/vulnerable-app.yaml applied.
# Optional: jq (pretty report).
# -----------------------------------------------------------------------------
set -euo pipefail

NS="prod-apps"
DEPLOY="vulnerable-app"
TIMEOUT="${TIMEOUT:-15}"
ATTACK_TYPE="${1:-token}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*"; exit 1; }

now_ms() { echo $(( $(date +%s%N) / 1000000 )); }

# 1. Locate a live victim pod ------------------------------------------------
info "Looking for a running pod of Deployment/${DEPLOY} in ${NS}..."
POD=$(kubectl get pods -n "${NS}" -l app=vulnerable-app \
        --field-selector=status.phase=Running \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)
[[ -n "${POD}" ]] || error "No running pod found. Apply demo/vulnerable-app.yaml first."
info "Target pod: ${POD}"

START_UID=$(kubectl get pod -n "${NS}" "${POD}" -o jsonpath='{.metadata.uid}')

# 2. Simulate the attack -----------------------------------------------------
START_MS=$(now_ms)
case "${ATTACK_TYPE}" in
  token)
    info "Simulating ServiceAccount token theft (kubectl exec)..."
    # Triggers: PodWarden K8s ServiceAccount Token Access (CRITICAL)
    kubectl exec -n "${NS}" "${POD}" -- \
      sh -c 'head -c 40 /var/run/secrets/kubernetes.io/serviceaccount/token; echo "... (truncated)"' \
      || warn "exec ended early (the pod may already be dying)"
    ;;
  wget)
    info "Simulating a forbidden recon binary (wget)..."
    # Triggers: PodWarden Forbidden Recon Binary (CRITICAL)
    kubectl exec -n "${NS}" "${POD}" -- \
      sh -c 'wget -q -T 2 -O /dev/null http://example.com || true' \
      || warn "exec ended early (the pod may already be dying)"
    ;;
  *)
    error "Unknown attack type '${ATTACK_TYPE}'. Use 'token' or 'wget'."
    ;;
esac

# 3. Wait for PodWarden to kill the pod ---------------------------------------
info "Waiting up to ${TIMEOUT}s for PodWarden to terminate the pod..."
KILLED=false
DEADLINE_MS=$(( START_MS + TIMEOUT * 1000 ))
while (( $(now_ms) < DEADLINE_MS )); do
  CURRENT_UID=$(kubectl get pod -n "${NS}" "${POD}" -o jsonpath='{.metadata.uid}' 2>/dev/null || echo "GONE")
  if [[ "${CURRENT_UID}" != "${START_UID}" ]]; then
    KILLED=true
    break
  fi
  sleep 0.2
done
ELAPSED_MS=$(( $(now_ms) - START_MS ))

if [[ "${KILLED}" == "true" ]]; then
  info "Pod ${POD} terminated by PodWarden in ~${ELAPSED_MS} ms (attack -> pod gone)"
else
  error "Pod ${POD} still alive after ${TIMEOUT}s. Check: kubectl logs -n podwarden-system -l app.kubernetes.io/name=podwarden"
fi

# 4. Show the forensic report --------------------------------------------------
# PodWarden prints ONE compact JSON line per incident on stdout.
info "Incident report for ${POD}:"
echo
REPORT=$(kubectl logs -n podwarden-system -l app.kubernetes.io/name=podwarden --since=2m 2>/dev/null \
  | grep -F "\"pod_name\":\"${POD}\"" | grep -F '"incident_id"' | tail -1 || true)
if [[ -z "${REPORT}" ]]; then
  warn "Report not found in logs yet (check podwarden-system)."
elif command -v jq >/dev/null 2>&1; then
  echo "${REPORT}" | jq .
else
  echo "${REPORT}"
fi
echo

# 5. Self-healing --------------------------------------------------------------
info "Waiting for the Deployment to restore the desired replica count..."
kubectl rollout status deployment/"${DEPLOY}" -n "${NS}" --timeout=60s
info "Done. The compromised pod was killed and replaced automatically."
