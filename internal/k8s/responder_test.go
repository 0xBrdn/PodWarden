package k8s_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/0xBrdn/PodWarden/internal/k8s"
)

const key = "test-hmac-signing-key-32bytes-long!!"

func sampleReport() k8s.IncidentReport {
	return k8s.IncidentReport{
		SchemaVersion: k8s.SchemaVersion,
		IncidentID:    "pw-20260101T000000Z-abc123-pod",
		Timestamp:     time.Date(2026, 1, 1, 0, 0, 0, 123456789, time.UTC),
		Rule:          "PodWarden Forbidden Recon Binary",
		Priority:      "Critical",
		Output:        "Forbidden recon binary executed",
		Namespace:     "prod-apps",
		PodName:       "pod",
		Images:        []string{"nginx:1.25-alpine"},
		Labels:        map[string]string{"app": "demo", "tier": "web"},
		ContainerLogs: map[string]string{"app": "GET / 200\n"},
		Action:        k8s.ActionDeleted,
	}
}

func marshalSigned(t *testing.T, r k8s.IncidentReport, k string) []byte {
	t.Helper()
	r.HMACSignature = k8s.Sign(r, k)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSignVerifyRoundTrip(t *testing.T) {
	ok, err := k8s.VerifyReport(marshalSigned(t, sampleReport(), key), key)
	if err != nil || !ok {
		t.Fatalf("valid report must verify, ok=%v err=%v", ok, err)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	signed := marshalSigned(t, sampleReport(), key)

	var m map[string]any
	if err := json.Unmarshal(signed, &m); err != nil {
		t.Fatal(err)
	}

	// Every one of these fields must be covered by the signature.
	tampered := map[string]any{
		"action":         k8s.ActionDryRun,
		"output":         "nothing happened here",
		"namespace":      "kube-system",
		"container_logs": map[string]any{"app": "cleaned"},
		"images":         []any{"evil:latest"},
	}
	for field, value := range tampered {
		t.Run(field, func(t *testing.T) {
			c := make(map[string]any, len(m))
			for k, v := range m {
				c[k] = v
			}
			c[field] = value
			b, _ := json.Marshal(c)
			ok, err := k8s.VerifyReport(b, key)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if ok {
				t.Fatalf("tampering with %q went undetected", field)
			}
		})
	}
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	ok, err := k8s.VerifyReport(marshalSigned(t, sampleReport(), key), "another-key-another-key-another-key")
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("report must not verify with a different key")
	}
}

func TestVerifyBadInput(t *testing.T) {
	if _, err := k8s.VerifyReport([]byte("not json"), key); err == nil {
		t.Error("expected error on invalid JSON")
	}
	if _, err := k8s.VerifyReport([]byte(`{"hmac_sha256":"zz"}`), key); err == nil {
		t.Error("expected error on invalid signature encoding")
	}
}
