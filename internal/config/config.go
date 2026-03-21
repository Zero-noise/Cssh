package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"cssh/internal/model"
)

const defaultConfigBody = `# Cssh runtime configuration
# This file uses a small TOML subset: key = value

default_shell = "bash -lc"
default_timeout_sec = 120
allow_public_host = true
security_profile_default = "easy_safe"
sudo_enabled = true
allow_root_login = false
`

// NormalizeSecurityProfile validates and normalizes a security_profile value.
// Empty string returns "easy_safe". Unknown values return an error.
func NormalizeSecurityProfile(v string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(v))
	switch mode {
	case "", "easy_safe":
		return "easy_safe", nil
	case "ops_strict":
		return "ops_strict", nil
	default:
		return "", fmt.Errorf("unknown security_profile %q; valid values: easy_safe, ops_strict", v)
	}
}

func ExpandHome(p string) string {
	if p == "" {
		return p
	}
	if p[0] != '~' {
		return p
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	if p == "~" {
		return h
	}
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(h, p[2:])
	}
	return p
}

func EnsureDirs(base string) error {
	runtimeDir := filepath.Join(base, "runtime")
	logsDir := filepath.Join(base, "logs")
	if err := os.MkdirAll(runtimeDir, 0o700); err != nil {
		return err
	}
	if err := os.MkdirAll(logsDir, 0o700); err != nil {
		return err
	}
	return nil
}

func Load(configPath string) (model.Config, error) {
	configPath = ExpandHome(configPath)
	base := filepath.Dir(configPath)
	cfg := model.Config{
		DefaultShell:           "bash -lc",
		DefaultTimeoutSec:      120,
		AllowPublicHost:        true,
		RuntimeDir:             filepath.Join(base, "runtime"),
		LogsDir:                filepath.Join(base, "logs"),
		ProfilesFile:           filepath.Join(base, "profiles.json"),
		SecurityProfileDefault: "easy_safe",
		SudoEnabled:           true,
		AllowRootLogin:         false,
	}

	if err := os.MkdirAll(base, 0o700); err != nil {
		return cfg, err
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if err := os.WriteFile(configPath, []byte(defaultConfigBody), 0o600); err != nil {
			return cfg, err
		}
	}

	f, err := os.Open(configPath)
	if err != nil {
		return cfg, err
	}
	defer f.Close()

	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, "\"")
		switch key {
		case "default_shell":
			if val != "" {
				cfg.DefaultShell = val
			}
		case "default_timeout_sec":
			n, err := strconv.Atoi(val)
			if err == nil && n > 0 {
				cfg.DefaultTimeoutSec = n
			}
		case "allow_public_host":
			cfg.AllowPublicHost = strings.EqualFold(val, "true")
		case "security_profile_default":
			if strings.TrimSpace(val) != "" {
				cfg.SecurityProfileDefault = strings.TrimSpace(val)
			}
		case "sudo_enabled":
			cfg.SudoEnabled = strings.EqualFold(val, "true")
		case "allow_root_login":
			cfg.AllowRootLogin = strings.EqualFold(val, "true")
		case "profiles_file":
			if val != "" {
				cfg.ProfilesFile = ExpandHome(val)
			}
		case "runtime_dir":
			if val != "" {
				cfg.RuntimeDir = ExpandHome(val)
			}
		case "logs_dir":
			if val != "" {
				cfg.LogsDir = ExpandHome(val)
			}
		}
	}
	if err := s.Err(); err != nil {
		return cfg, fmt.Errorf("scan config: %w", err)
	}
	normalized, err := NormalizeSecurityProfile(cfg.SecurityProfileDefault)
	if err != nil {
		return cfg, fmt.Errorf("config: %w", err)
	}
	cfg.SecurityProfileDefault = normalized

	if err := os.MkdirAll(cfg.RuntimeDir, 0o700); err != nil {
		return cfg, err
	}
	if err := os.MkdirAll(cfg.LogsDir, 0o700); err != nil {
		return cfg, err
	}
	return cfg, nil
}
