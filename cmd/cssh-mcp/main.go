package main

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"cssh/internal/app"
	"cssh/internal/config"
	"cssh/internal/mcp"
)

func main() {
	configPath := os.Getenv("CSSH_CONFIG")
	if configPath == "" {
		configPath = "~/.csbridge/config.toml"
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load config failed: %v\n", err)
		os.Exit(1)
	}
	svc := app.NewService(cfg)

	var shutdownOnce sync.Once
	shutdown := func() { shutdownOnce.Do(svc.Shutdown) }

	// Ensure all SSH master connections are closed on exit.
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		// First signal: graceful shutdown (may block if closeMaster is slow).
		go shutdown()
		<-sigCh
		// Second signal: force exit immediately.
		os.Exit(1)
	}()

	server := mcp.NewServer(svc, cfg)
	if err := server.Run(); err != nil {
		shutdown()
		fmt.Fprintf(os.Stderr, "mcp server stopped: %v\n", err)
		os.Exit(1)
	}
	shutdown()
}
