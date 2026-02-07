package main

import (
	"fmt"
	"os"

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
	server := mcp.NewServer(svc)
	if err := server.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "mcp server stopped: %v\n", err)
		os.Exit(1)
	}
}
