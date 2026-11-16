package config

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// Config holds all runtime configuration loaded from environment variables.
type Config struct {
	WebhookSecret       string
	HMACSigningKey      string
	ProtectedNamespaces map[string]struct{}
	DryRun              bool
	ListenAddr          string
	IncidentDir         string
}

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
	if cfg.HMACSigningKey == "" {
		return nil, fmt.Errorf("HMAC_SIGNING_KEY environment variable is required")
	}

	protected := getEnvOr("PROTECTED_NAMESPACES", "kube-system,podwarden-system")
	cfg.ProtectedNamespaces = make(map[string]struct{})
	for _, ns := range strings.Split(protected, ",") {
		ns = strings.TrimSpace(ns)
		if ns != "" {
			cfg.ProtectedNamespaces[ns] = struct{}{}
		}
	}

	cfg.DryRun = strings.EqualFold(os.Getenv("DRY_RUN"), "true")
	return cfg, nil
}

func getEnvOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func (c *Config) IsProtected(ns string) bool {
	_, ok := c.ProtectedNamespaces[ns]
	return ok
}

func Now() string {
	return time.Now().UTC().Format("20060102T150405Z")
}
