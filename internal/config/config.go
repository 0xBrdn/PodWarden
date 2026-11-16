package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	minWebhookSecretLen = 16
	minHMACKeyLen       = 32
)

// Config holds all runtime configuration loaded from environment variables.
type Config struct {
	WebhookSecret       string
	HMACSigningKey      string
	ProtectedNamespaces map[string]struct{}
	DryRun              bool
	ListenAddr          string
	IncidentDir         string

	// DedupWindow ignores repeated alerts for the same namespace/pod within
	// this window (Falco often emits bursts). 0 disables deduplication.
	DedupWindow time.Duration
	// MaxActionsPerMinute is the circuit breaker: above this number of pod
	// deletions per minute, PodWarden keeps collecting evidence but stops
	// killing. 0 disables the breaker.
	MaxActionsPerMinute int
	// LogTailLines is the number of log lines captured per container.
	LogTailLines int64
}

// Load reads the configuration from the environment and validates it.
func Load() (*Config, error) {
	cfg := &Config{
		WebhookSecret:  os.Getenv("WEBHOOK_SECRET"),
		HMACSigningKey: os.Getenv("HMAC_SIGNING_KEY"),
		ListenAddr:     getEnvOr("LISTEN_ADDR", ":8080"),
		IncidentDir:    getEnvOr("INCIDENT_DIR", "/var/log/podwarden/incidents"),
	}

	if cfg.WebhookSecret == "" {
		return nil, fmt.Errorf("WEBHOOK_SECRET environment variable is required")
	}
	if len(cfg.WebhookSecret) < minWebhookSecretLen {
		return nil, fmt.Errorf("WEBHOOK_SECRET must be at least %d characters", minWebhookSecretLen)
	}
	if cfg.HMACSigningKey == "" {
		return nil, fmt.Errorf("HMAC_SIGNING_KEY environment variable is required")
	}
	if len(cfg.HMACSigningKey) < minHMACKeyLen {
		return nil, fmt.Errorf("HMAC_SIGNING_KEY must be at least %d characters", minHMACKeyLen)
	}

	protected := getEnvOr("PROTECTED_NAMESPACES",
		"kube-system,kube-public,kube-node-lease,podwarden-system,falco")
	cfg.ProtectedNamespaces = make(map[string]struct{})
	for _, ns := range strings.Split(protected, ",") {
		ns = strings.TrimSpace(ns)
		if ns != "" {
			cfg.ProtectedNamespaces[ns] = struct{}{}
		}
	}

	cfg.DryRun = strings.EqualFold(os.Getenv("DRY_RUN"), "true")

	var err error
	if cfg.DedupWindow, err = time.ParseDuration(getEnvOr("DEDUP_WINDOW", "30s")); err != nil {
		return nil, fmt.Errorf("invalid DEDUP_WINDOW: %w", err)
	}
	if cfg.MaxActionsPerMinute, err = strconv.Atoi(getEnvOr("MAX_ACTIONS_PER_MINUTE", "10")); err != nil {
		return nil, fmt.Errorf("invalid MAX_ACTIONS_PER_MINUTE: %w", err)
	}
	if cfg.LogTailLines, err = strconv.ParseInt(getEnvOr("LOG_TAIL_LINES", "50"), 10, 64); err != nil {
		return nil, fmt.Errorf("invalid LOG_TAIL_LINES: %w", err)
	}

	return cfg, nil
}

func getEnvOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// IsProtected reports whether actions on the namespace are forbidden.
func (c *Config) IsProtected(ns string) bool {
	_, ok := c.ProtectedNamespaces[ns]
	return ok
}
