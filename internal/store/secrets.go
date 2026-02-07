package store

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
)

type SecretStore interface {
	Set(profileID, kind, value string) error
	Get(profileID, kind string) (string, error)
	Delete(profileID, kind string) error
}

type OSSecretStore struct{}

func NewSecretStore() SecretStore {
	return &OSSecretStore{}
}

func (s *OSSecretStore) Set(profileID, kind, value string) error {
	switch runtime.GOOS {
	case "darwin":
		return runCmd("security", "add-generic-password", "-a", profileID, "-s", serviceName(kind), "-w", value, "-U")
	case "linux":
		cmd := exec.Command("secret-tool", "store", "--label=cssh", "service", "cssh", "profile", profileID, "kind", kind)
		cmd.Stdin = strings.NewReader(value)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("secret-tool store: %w: %s", err, strings.TrimSpace(stderr.String()))
		}
		return nil
	default:
		return errors.New("unsupported os for secret storage")
	}
}

func (s *OSSecretStore) Get(profileID, kind string) (string, error) {
	switch runtime.GOOS {
	case "darwin":
		out, err := runCmdOutput("security", "find-generic-password", "-a", profileID, "-s", serviceName(kind), "-w")
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(out), nil
	case "linux":
		out, err := runCmdOutput("secret-tool", "lookup", "service", "cssh", "profile", profileID, "kind", kind)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(out), nil
	default:
		return "", errors.New("unsupported os for secret storage")
	}
}

func (s *OSSecretStore) Delete(profileID, kind string) error {
	switch runtime.GOOS {
	case "darwin":
		return runCmd("security", "delete-generic-password", "-a", profileID, "-s", serviceName(kind))
	case "linux":
		return runCmd("secret-tool", "clear", "service", "cssh", "profile", profileID, "kind", kind)
	default:
		return errors.New("unsupported os for secret storage")
	}
}

func serviceName(kind string) string {
	return "cssh-" + kind
}

func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func runCmdOutput(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}
