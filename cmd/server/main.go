package main

import (
	"log/slog"
	"os"

	"github.com/nydhy/aegis-llm/internal/config"
	"github.com/nydhy/aegis-llm/internal/proxy"
)

func main() {
	cfg := config.Load()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	srv := proxy.NewServer(cfg)
	slog.Info("aegis-llm starting", "port", cfg.Port)

	if err := srv.Run(":" + cfg.Port); err != nil {
		slog.Error("server failed", "err", err)
		os.Exit(1)
	}
}
