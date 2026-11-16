// Command podwarden is the active-response controller: it receives Falco alerts
// through Falcosidekick, collects forensics, signs an incident report and
// terminates the compromised pod.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/0xBrdn/PodWarden/internal/config"
	"github.com/0xBrdn/PodWarden/internal/k8s"
	"github.com/0xBrdn/PodWarden/internal/webhook"
)

// version is injected at build time: -ldflags "-X main.version=1.2.3".
var version = "dev"

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel()}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	responder, err := k8s.NewResponder(cfg, logger)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	webhook.NewHandler(cfg, responder, logger).Register(mux)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      40 * time.Second, // > webhook response budget (20s)
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("PodWarden started",
			"version", version,
			"addr", cfg.ListenAddr,
			"dry_run", cfg.DryRun,
			"dedup_window", cfg.DedupWindow.String(),
			"max_actions_per_minute", cfg.MaxActionsPerMinute,
			"protected_namespaces", len(cfg.ProtectedNamespaces),
		)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("shutdown signal received, draining in-flight alerts")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func logLevel() slog.Level {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(os.Getenv("LOG_LEVEL"))); err != nil {
		return slog.LevelInfo
	}
	return lvl
}
