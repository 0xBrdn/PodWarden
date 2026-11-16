#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# PodWarden attack simulation
# -----------------------------------------------------------------------------
# This script:
#   1. Picks a running pod from the vulnerable-app Deployment in prod-apps
#   2. Executes a "forbidden" action inside it (SA token read OR wget)
#   3. Waits ≤ 3 seconds for PodWarden to kill the pod
#   4. Prints the forensic incident report that was generated
#
# Prerequisites:
#   - Kind cluster with PodWarden + Falco running
#   - demo/vulnerable-app.yaml already applied
# -----------------------------------------------------------------------------
set -euo pipefail

NS="prod-apps"
DEPLOY="vulnerable-app"
TIMEOUT=3
POLL_INTERVAL=0.3

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[-]${NC} $*"; exit 1; }

# ---------------------------------------------------------------------------
# 1. Locate a live victim pod
# ---------------------------------------------------------------------------
info "Looking for a running pod of Deployment/${DEPLOY} in ${NS}..."
POD=$(kubectl get pods -n "${NS}" -l app=vulnerable-app \
        --field-selector=status.phase=Running \
        -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)

if [[ -z "${POD}" ]]; then
  error "No running pod found. Apply demo/vulnerable-app.yaml first."
fi
info "Target pod: ${POD}"

# Snapshot for later comparison
START_UID=$(kubectl get pod -n "${NS}" "${POD}" -o jsonpath='{.metadata.uid}')
START_TIME=$(date +%s)

# ---------------------------------------------------------------------------
# 2. Simulate the attack (two classic techniques)
# ---------------------------------------------------------------------------
ATTACK_TYPE=${1:-token}   # "token" | "wget"

case "${ATTACK_TYPE}" in
  token)
    info "Simulating ServiceAccount token theft via kubectl exec..."
    # This will trigger: PodWarden K8s ServiceAccount Token Access
    kubectl exec -n "${NS}" "${POD}" -- \
      sh -c 'cat /var/run/secrets/kubernetes.io/serviceaccount/token | head -c 40; echo "... (truncated)"' \
      || warn "exec finished (pod may already be dying)"
    ;;
  wget)
    info "Simulating forbidden recon binary (wget) via kubectl exec..."
    # This will trigger: PodWarden Forbidden Recon Binary
    kubectl exec -n "${NS}" "${POD}" -- \
      sh -c 'wget -q -O /dev/null http://example.com || true' \
      || warn "exec finished (pod may already be dying)"
    ;;
  *)
    error "Unknown attack type '${ATTACK_TYPE}'. Use 'token' or 'wget'."
    ;;
esac

# ---------------------------------------------------------------------------
# 3. Wait for PodWarden to kill the pod (≤ TIMEOUT seconds)
# ---------------------------------------------------------------------------
info "Waiting up to ${TIMEOUT}s for PodWarden to terminate the pod..."

ELAPSED=0
KILLED=false
while (( $(echo "${ELAPSED} < ${TIMEOUT}" | bc -l) )); do
  # Pod gone or UID changed (recreated by Deployment)
  CURRENT_UID=$(kubectl get pod -n "${NS}" "${POD}" -o jsonpath='{.metadata.uid}' 2>/dev/null || echo "GONE")
  if [[ "${CURRENT_UID}" != "${START_UID}" ]]; then
    KILLED=true
    break
  fi
  sleep "${POLL_INTERVAL}"
  ELAPSED=$(echo "${ELAPSED} + ${POLL_INTERVAL}" | bc)
done

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

if [[ "${KILLED}" == "true" ]]; then
  info "Pod ${POD} was terminated by PodWarden in ~${DURATION}s 🎉"
else
  error "Pod ${POD} is still alive after ${TIMEOUT}s – PodWarden did not react."
fi

# ---------------------------------------------------------------------------
# 4. Show the forensic report (from PodWarden logs / stdout)
# ---------------------------------------------------------------------------
info "Fetching latest incident report from PodWarden logs..."
echo
echo "========== PodWarden Incident Report (latest) =========="
kubectl logs -n podwarden-system -l app.kubernetes.io/name=podwarden \
  --tail=200 --since=30s 2>/dev/null \
  | grep -A 50 '"incident_id"' \
  | head -60 \
  || warn "Could not extract structured report from logs (check podwarden-system)."
echo "========================================================"
echo

# ---------------------------------------------------------------------------
# 5. Confirm the Deployment healed itself
# ---------------------------------------------------------------------------
info "Waiting for Deployment to restore desired replica count..."
kubectl rollout status deployment/"${DEPLOY}" -n "${NS}" --timeout=30s
info "Demo complete. The infected pod was killed and replaced automatically."
