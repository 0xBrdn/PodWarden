package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/0xBrdn/PodWarden/internal/config"
)

const (
	goodSecret = "0123456789abcdef0123"
	goodKey    = "0123456789abcdef0123456789abcdef0123"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("WEBHOOK_SECRET", goodSecret)
	t.Setenv("HMAC_SIGNING_KEY", goodKey)

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.DedupWindow != 30*time.Second {
		t.Errorf("DedupWindow = %v, want 30s", cfg.DedupWindow)
	}
	if cfg.MaxActionsPerMinute != 10 {
		t.Errorf("MaxActionsPerMinute = %d, want 10", cfg.MaxActionsPerMinute)
	}
	for _, ns := range []string{"kube-system", "podwarden-system", "falco"} {
		if !cfg.IsProtected(ns) {
			t.Errorf("%s should be protected by default", ns)
		}
	}
	if cfg.IsProtected("prod-apps") {
		t.Error("prod-apps must not be protected by default")
	}
}

func TestLoadRejectsWeakOrMissingSecrets(t *testing.T) {
	cases := []struct {
		name, secret, key, want string
	}{
		{"missing secret", "", goodKey, "WEBHOOK_SECRET"},
		{"short secret", "short", goodKey, "WEBHOOK_SECRET"},
		{"missing key", goodSecret, "", "HMAC_SIGNING_KEY"},
		{"short key", goodSecret, "short", "HMAC_SIGNING_KEY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("WEBHOOK_SECRET", tc.secret)
			t.Setenv("HMAC_SIGNING_KEY", tc.key)
			_, err := config.Load()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected error mentioning %s, got %v", tc.want, err)
			}
		})
	}
}

func TestLoadRejectsInvalidDuration(t *testing.T) {
	t.Setenv("WEBHOOK_SECRET", goodSecret)
	t.Setenv("HMAC_SIGNING_KEY", goodKey)
	t.Setenv("DEDUP_WINDOW", "not-a-duration")
	if _, err := config.Load(); err == nil {
		t.Fatal("expected an error for invalid DEDUP_WINDOW")
	}
}
