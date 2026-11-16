package webhook

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/0xBrdn/PodWarden/internal/config"
	"github.com/0xBrdn/PodWarden/internal/k8s"
)

const (
	maxBodyBytes   = 1 << 20          // 1 MiB
	responseBudget = 20 * time.Second // upper bound for forensics + containment
)

// actionablePriorities are the Falco priorities that trigger an active response
// (Error and above). Falco priorities, from most to least severe: emergency,
// alert, critical, error, warning, notice, informational, debug.
var actionablePriorities = map[string]struct{}{
	"emergency": {},
	"alert":     {},
	"critical":  {},
	"error":     {},
}

// Kubernetes object names are DNS-1123 labels/subdomains. Validating them keeps
// attacker-influenced strings out of file paths and API calls.
var dns1123 = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?(\.[a-z0-9]([-a-z0-9]*[a-z0-9])?)*$`)

func validName(s string, maxLen int) bool {
	return len(s) > 0 && len(s) <= maxLen && dns1123.MatchString(s)
}

// FalcoEvent is the subset of the Falcosidekick webhook payload we rely on.
type FalcoEvent struct {
	Output       string                 `json:"output"`
	Priority     string                 `json:"priority"`
	Rule         string                 `json:"rule"`
	Time         string                 `json:"time"`
	OutputFields map[string]interface{} `json:"output_fields"`
}

type Handler struct {
	cfg       *config.Config
	responder *k8s.Responder
	logger    *slog.Logger
}

func NewHandler(cfg *config.Config, responder *k8s.Responder, logger *slog.Logger) *Handler {
	return &Handler{cfg: cfg, responder: responder, logger: logger}
}

func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /webhook", h.handleWebhook)
	mux.HandleFunc("GET /healthz", h.handleHealthz)
	mux.HandleFunc("GET /readyz", h.handleReadyz)
}

func (h *Handler) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReadyz reports ready only if the Kubernetes API answers: a responder
// that cannot reach the API server would silently fail to contain anything.
func (h *Handler) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := h.responder.Ready(ctx); err != nil {
		h.logger.Warn("readiness check failed", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "kubernetes api unreachable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// authorized compares the shared secret in constant time. Both sides are hashed
// first so the comparison length never depends on the secret's length.
func (h *Handler) authorized(r *http.Request) bool {
	if h.cfg.WebhookSecret == "" {
		return false
	}
	got := sha256.Sum256([]byte(r.Header.Get("X-Webhook-Secret")))
	want := sha256.Sum256([]byte(h.cfg.WebhookSecret))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

func (h *Handler) handleWebhook(w http.ResponseWriter, r *http.Request) {
	if !h.authorized(r) {
		h.logger.Warn("unauthorized webhook attempt", "remote", r.RemoteAddr)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			http.Error(w, "payload too large", http.StatusRequestEntityTooLarge)
			return
		}
		h.logger.Error("failed to read body", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}

	var evt FalcoEvent
	if err := json.Unmarshal(body, &evt); err != nil {
		h.logger.Error("invalid JSON payload", "error", err)
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	if _, ok := actionablePriorities[strings.ToLower(evt.Priority)]; !ok {
		h.logger.Debug("ignoring low-priority event", "priority", evt.Priority, "rule", evt.Rule)
		writeJSON(w, http.StatusOK, map[string]string{"status": "ignored", "reason": "priority"})
		return
	}

	ns, _ := evt.OutputFields["k8s.ns.name"].(string)
	pod, _ := evt.OutputFields["k8s.pod.name"].(string)
	if ns == "" || pod == "" {
		h.logger.Warn("missing k8s.ns.name or k8s.pod.name in output_fields", "rule", evt.Rule)
		http.Error(w, "missing kubernetes identity fields", http.StatusBadRequest)
		return
	}
	if !validName(ns, 63) || !validName(pod, 253) {
		h.logger.Warn("rejected malformed kubernetes identity", "rule", evt.Rule)
		http.Error(w, "malformed kubernetes identity fields", http.StatusBadRequest)
		return
	}

	if h.cfg.IsProtected(ns) {
		h.logger.Warn("BLOCKED action on protected namespace (anti-self-DoS)",
			"namespace", ns, "pod", pod, "rule", evt.Rule)
		writeJSON(w, http.StatusOK, map[string]string{"status": "blocked", "reason": "protected_namespace"})
		return
	}

	h.logger.Info("actionable alert received",
		"rule", evt.Rule, "priority", evt.Priority, "namespace", ns, "pod", pod)

	// Detach from the request: if Falcosidekick times out and hangs up, we must
	// still finish what we started (forensics + containment + signed report).
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), responseBudget)
	defer cancel()

	report, err := h.responder.HandleAlert(ctx, evt.Rule, evt.Priority, evt.Output, ns, pod)
	switch {
	case errors.Is(err, k8s.ErrDuplicate):
		h.logger.Info("duplicate alert ignored", "namespace", ns, "pod", pod, "rule", evt.Rule)
		writeJSON(w, http.StatusOK, map[string]string{"status": "duplicate"})
	case err != nil:
		h.logger.Error("responder failed", "error", err, "pod", pod, "ns", ns)
		http.Error(w, "internal error", http.StatusInternalServerError)
	default:
		writeJSON(w, http.StatusOK, map[string]string{
			"status":      "processed",
			"incident_id": report.IncidentID,
			"action":      report.Action,
		})
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
