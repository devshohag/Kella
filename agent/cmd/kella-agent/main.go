// kella-agent runs on customer servers. See docs/SPEC.md §8.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/devshohag/kella/agent/internal/agent"
	"github.com/devshohag/kella/agent/internal/config"
)

func main() {
	cfgPath := flag.String("config", "/etc/kella/agent.yaml", "path to agent.yaml")
	version := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *version {
		fmt.Println(agent.Version)
		return
	}

	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		slog.Error("config", "err", err)
		os.Exit(1)
	}
	a, err := agent.New(cfg)
	if err != nil {
		slog.Error("init", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	slog.Info("kella-agent starting", "version", agent.Version, "cloud", cfg.CloudURL, "dryRun", cfg.Actions.DryRun)
	if err := a.Run(ctx); err != nil {
		slog.Error("agent stopped", "err", err)
		os.Exit(1)
	}
}
