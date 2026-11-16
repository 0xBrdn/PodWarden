package webhook_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/0xBrdn/PodWarden/internal/config"
	"github.com/0xBrdn/PodWarden/internal/k8s"
	"github.com/0xBrdn/PodWarden/internal/webhook"
)

const testSecret = "test-webhook-secret-42"
const testHMACKey = "test-hmac-signing-key-32bytes!!"

func newTestConfig(t *testing.T, dryRun bool) *config.Config {
	t.Helper()
	tmpDir := t.TempDir()
	return &config.Config{
		WebhookSecret:  testSecret,
		HMACSigningKey: testHMACKey,
		ProtectedNamespaces: map[string]struct{}{
			"kube-system":      {},
			"podwarden-system": {},
		},
		DryRun:      dryRun,
		ListenAddr:  ":0",
		IncidentDir: filepath.Join(tmpDir, "incidents"),
	}
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func makeFalcoPayload(rule, priority, ns, pod string) []byte {
	evt := map[string]interface{}{
		"output":   "PodWarden test alert",
		"priority": priority,
		"rule":     rule,
		"time":     time.Now().UTC().Format(time.RFC3339),
		"output_fields": map[string]interface{}{
			"k8s.ns.name":  ns,
			"k8s.pod.name": pod,
		},
	}
	b, _ := json.Marshal(evt)
	return b
}

func TestWebhookUnauthorized(t *testing.T) {
	cfg := newTestConfig(t, false)
	cs := fake.NewSimpleClientset()
	responder := k8s.NewResponderWithClientset(cfg, newTestLogger(), cs)
	h := webhook.NewHandler(cfg, responder, newTestLogger())

	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(makeFalcoPayload(
		"PodWarden Interactive Shell Spawned", "Critical", "prod-apps", "evil-pod")))
	req.Header.Set("X-Webhook-Secret", "wrong-secret")

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d – body: %s", rr.Code, rr.Body.String())
	}
}

func TestProtectedNamespaceIsNeverDeleted(t *testing.T) {
	cfg := newTestConfig(t, false)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "coredns-xyz",
			Namespace: "kube-system",
			Labels:    map[string]string{"k8s-app": "kube-dns"},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "coredns", Image: "coredns/coredns:1.11"}},
		},
		Status: corev1.PodStatus{PodIP: "10.0.0.10", Phase: corev1.PodRunning},
	}
	cs := fake.NewSimpleClientset(pod)
	responder := k8s.NewResponderWithClientset(cfg, newTestLogger(), cs)
	h := webhook.NewHandler(cfg, responder, newTestLogger())

	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(makeFalcoPayload(
		"PodWarden Interactive Shell Spawned", "Critical", "kube-system", "coredns-xyz")))
	req.Header.Set("X-Webhook-Secret", testSecret)

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 (blocked), got %d – body: %s", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte(`"blocked"`)) {
		t.Fatalf("expected blocked response, got: %s", rr.Body.String())
	}

	// Pod must still exist
	_, err := cs.CoreV1().Pods("kube-system").Get(context.Background(), "coredns-xyz", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("protected pod was deleted – anti-self-DoS failed: %v", err)
	}
}

func TestCriticalAlertDeletesPodInProdApps(t *testing.T) {
	cfg := newTestConfig(t, false)

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "vulnerable-app-7d8f9",
			Namespace: "prod-apps",
			Labels: map[string]string{
				"app": "vulnerable-app",
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{Name: "nginx", Image: "nginx:1.25-alpine"},
			},
			NodeName: "kind-worker",
		},
		Status: corev1.PodStatus{
			PodIP: "10.244.1.15",
			Phase: corev1.PodRunning,
		},
	}
	cs := fake.NewSimpleClientset(pod)
	responder := k8s.NewResponderWithClientset(cfg, newTestLogger(), cs)
	h := webhook.NewHandler(cfg, responder, newTestLogger())

	mux := http.NewServeMux()
	h.Register(mux)

	payload := makeFalcoPayload(
		"PodWarden Forbidden Recon Binary",
		"Critical",
		"prod-apps",
		"vulnerable-app-7d8f9",
	)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(payload))
	req.Header.Set("X-Webhook-Secret", testSecret)

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d – body: %s", rr.Code, rr.Body.String())
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte(`"processed"`)) {
		t.Fatalf("expected processed response, got: %s", rr.Body.String())
	}

	// Pod must have been deleted
	_, err := cs.CoreV1().Pods("prod-apps").Get(context.Background(), "vulnerable-app-7d8f9", metav1.GetOptions{})
	if err == nil {
		t.Fatal("compromised pod still exists – deletion failed")
	}

	// Incident report must have been written
	entries, err := os.ReadDir(cfg.IncidentDir)
	if err != nil {
		t.Fatalf("incident dir not created: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("no incident report written")
	}

	// Verify report content
	data, err := os.ReadFile(filepath.Join(cfg.IncidentDir, entries[0].Name()))
	if err != nil {
		t.Fatalf("cannot read report: %v", err)
	}
	var report k8s.IncidentReport
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatalf("invalid report JSON: %v", err)
	}
	if report.Action != "deleted" {
		t.Errorf("expected action=deleted, got %q", report.Action)
	}
	if report.Namespace != "prod-apps" || report.PodName != "vulnerable-app-7d8f9" {
		t.Errorf("wrong identity in report: %+v", report)
	}
	if report.HMACSignature == "" {
		t.Error("missing HMAC signature")
	}
	if len(report.Images) == 0 || report.Images[0] != "nginx:1.25-alpine" {
		t.Errorf("expected image nginx:1.25-alpine, got %v", report.Images)
	}
}

func TestLowPriorityIsIgnored(t *testing.T) {
	cfg := newTestConfig(t, false)
	cs := fake.NewSimpleClientset()
	responder := k8s.NewResponderWithClientset(cfg, newTestLogger(), cs)
	h := webhook.NewHandler(cfg, responder, newTestLogger())

	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(makeFalcoPayload(
		"Some Warning Rule", "Warning", "prod-apps", "some-pod")))
	req.Header.Set("X-Webhook-Secret", testSecret)

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !bytes.Contains(rr.Body.Bytes(), []byte(`"ignored"`)) {
		t.Fatalf("expected ignored response, got: %s", rr.Body.String())
	}
}

func TestDryRunDoesNotDelete(t *testing.T) {
	cfg := newTestConfig(t, true) // DRY_RUN=true

	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "safe-pod",
			Namespace: "prod-apps",
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "busybox"}},
		},
	}
	cs := fake.NewSimpleClientset(pod)
	responder := k8s.NewResponderWithClientset(cfg, newTestLogger(), cs)
	h := webhook.NewHandler(cfg, responder, newTestLogger())

	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodPost, "/webhook", bytes.NewReader(makeFalcoPayload(
		"PodWarden Interactive Shell Spawned", "Critical", "prod-apps", "safe-pod")))
	req.Header.Set("X-Webhook-Secret", testSecret)

	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	// Pod must still exist
	_, err := cs.CoreV1().Pods("prod-apps").Get(context.Background(), "safe-pod", metav1.GetOptions{})
	if err != nil {
		t.Fatalf("pod was deleted despite DRY_RUN=true: %v", err)
	}
}

func TestHealthz(t *testing.T) {
	cfg := newTestConfig(t, false)
	cs := fake.NewSimpleClientset()
	responder := k8s.NewResponderWithClientset(cfg, newTestLogger(), cs)
	h := webhook.NewHandler(cfg, responder, newTestLogger())

	mux := http.NewServeMux()
	h.Register(mux)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}
