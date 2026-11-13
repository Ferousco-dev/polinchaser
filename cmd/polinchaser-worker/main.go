// Command polinchaser-worker runs queued scan jobs.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/Ferousco-dev/polinchaser/internal/config"
	"github.com/Ferousco-dev/polinchaser/internal/db"
	"github.com/Ferousco-dev/polinchaser/internal/worker"
)

func main() {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		slog.Error("invalid configuration", "err", err)
		os.Exit(1)
	}
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("service", "worker")
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Error("database", "err", err)
		os.Exit(1)
	}
	defer pool.Close()
	if _, err := db.Migrate(ctx, pool); err != nil {
		log.Error("migrate", "err", err)
		os.Exit(1)
	}
	if err := worker.Run(ctx, cfg, pool, log); err != nil {
		log.Error("worker", "err", err)
		os.Exit(1)
	}
}
