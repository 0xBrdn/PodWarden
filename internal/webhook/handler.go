package webhook

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/0xBrdn/PodWarden/internal/config"
	"github.com/0xBrdn/PodWarden/internal/k8s"
)

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
	mux.HandleFunc("GET /readyz", h.handleHealthz)
}

func (h *Handler) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

func (h *Handler) handleWebhook(w http.ResponseWriter, r *http.Request) {
	secret := r.Header.Get("X-Webhook-Secret")
	if secret == "" || secret != h.cfg.WebhookSecret {
		h.logger.Warn("unauthorized webhook attempt", "remote", r.RemoteAddr)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		h.logger.Error("failed to read body", "error", err)
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var evt FalcoEvent
	if err := json.Unmarshal(body, &evt); err != nil {
		h.logger.Error("invalid JSON payload", "error", err)
		http.Error(w, "invalid json", http.StatusBadRequest)
		return
	}

	prio := strings.ToLower(evt.Priority)
	if prio != "critical" && prio != "error" {
		h.logger.Debug("ignoring low-priority event", "priority", evt.Priority, "rule", evt.Rule)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ignored","reason":"priority"}`))
		return
	}

	ns, _ := evt.OutputFields["k8s.ns.name"].(string)
	pod, _ := evt.OutputFields["k8s.pod.name"].(string)
	if ns == "" || pod == "" {
		h.logger.Warn("missing k8s.ns.name or k8s.pod.name in output_fields", "rule", evt.Rule)
		http.Error(w, "missing kubernetes identity fields", http.StatusBadRequest)
		return
	}

	if h.cfg.IsProtected(ns) {
		h.logger.Warn("BLOCKED action on protected namespace (anti-self-DoS)",
			"namespace", ns, "pod", pod, "rule", evt.Rule)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"blocked","reason":"protected_namespace"}`))
		return
	}

	h.logger.Info("actionable alert received",
		"rule", evt.Rule, "priority", evt.Priority, "namespace", ns, "pod", pod)

	if err := h.responder.HandleAlert(r.Context(), evt.Rule, evt.Priority, evt.Output, ns, pod); err != nil {
		h.logger.Error("responder failed", "error", err, "pod", pod, "ns", ns)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"processed"}`))
}
