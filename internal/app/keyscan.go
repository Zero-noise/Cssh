package app

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// SSHKeyInfo describes a discovered SSH private key.
type SSHKeyInfo struct {
	Path            string `json:"path"`
	Name            string `json:"name"`
	NeedsPassphrase bool   `json:"needs_passphrase"`
	InAgent         bool   `json:"in_agent"`
	Algorithm       string `json:"algorithm"`
	Error           string `json:"error,omitempty"`
}

// ScanSSHKeys scans dir for SSH private key files and returns info for each.
// dir must be under $HOME for safety.
func ScanSSHKeys(dir string) ([]SSHKeyInfo, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("cannot determine home directory: %w", err)
	}
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, fmt.Errorf("invalid directory: %w", err)
	}
	if !strings.HasPrefix(absDir, homeDir) {
		return nil, fmt.Errorf("scan directory must be under home directory (%s)", homeDir)
	}

	entries, err := os.ReadDir(absDir)
	if err != nil {
		return nil, fmt.Errorf("read directory %s: %w", absDir, err)
	}

	var keys []SSHKeyInfo
	for _, entry := range entries {
		filePath := filepath.Join(absDir, entry.Name())
		if !isPrivateKeyFile(filePath, entry) {
			continue
		}
		info := SSHKeyInfo{
			Path: filePath,
			Name: entry.Name(),
		}
		info.Algorithm = detectKeyAlgorithm(filePath)

		needsPass, err := CheckKeyPassphrase(filePath)
		if err != nil {
			info.Error = err.Error()
		} else {
			info.NeedsPassphrase = needsPass
		}

		inAgent, _ := IsKeyLoadedInAgent(filePath)
		info.InAgent = inAgent

		keys = append(keys, info)
	}
	return keys, nil
}

// CheckKeyPassphrase returns true if the key requires a passphrase.
// Uses ssh-keygen -y -P "" to probe.
func CheckKeyPassphrase(keyPath string) (bool, error) {
	cmd := exec.Command("ssh-keygen", "-y", "-P", "", "-f", keyPath)
	cmd.Stdin = nil
	err := cmd.Run()
	if err == nil {
		return false, nil // no passphrase needed
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		if exitErr.ExitCode() != 0 {
			return true, nil // passphrase required
		}
	}
	return false, fmt.Errorf("ssh-keygen check failed: %w", err)
}

// IsKeyLoadedInAgent checks if a key's fingerprint is in the ssh-agent.
func IsKeyLoadedInAgent(keyPath string) (bool, error) {
	// Get the key's fingerprint
	keyFP, err := exec.Command("ssh-keygen", "-l", "-f", keyPath).Output()
	if err != nil {
		return false, fmt.Errorf("ssh-keygen fingerprint: %w", err)
	}
	fpParts := strings.Fields(strings.TrimSpace(string(keyFP)))
	if len(fpParts) < 2 {
		return false, fmt.Errorf("unexpected ssh-keygen output")
	}
	fingerprint := fpParts[1] // e.g. SHA256:xxxx

	// List agent keys
	agentOut, err := exec.Command("ssh-add", "-l").Output()
	if err != nil {
		return false, nil // agent not running or empty
	}

	scanner := bufio.NewScanner(strings.NewReader(string(agentOut)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, fingerprint) {
			return true, nil
		}
	}
	return false, nil
}

// isPrivateKeyFile checks if a dir entry is likely an SSH private key.
func isPrivateKeyFile(filePath string, entry os.DirEntry) bool {
	name := entry.Name()

	// Skip known non-key files
	if strings.HasSuffix(name, ".pub") ||
		name == "known_hosts" ||
		name == "known_hosts.old" ||
		name == "config" ||
		name == "authorized_keys" ||
		strings.HasPrefix(name, ".") {
		return false
	}

	// Use Lstat to detect symlinks — skip them for security
	info, err := os.Lstat(filePath)
	if err != nil {
		return false
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if info.IsDir() {
		return false
	}
	// Skip files > 100KB
	if info.Size() > 100*1024 {
		return false
	}

	// Read first line to check for PEM header
	f, err := os.Open(filePath)
	if err != nil {
		return false
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "-----BEGIN") {
			return true
		}
		// OpenSSH format
		if strings.HasPrefix(line, "openssh-key-v1") {
			return true
		}
	}
	return false
}

// detectKeyAlgorithm determines the key algorithm from ssh-keygen output.
func detectKeyAlgorithm(keyPath string) string {
	out, err := exec.Command("ssh-keygen", "-l", "-f", keyPath).Output()
	if err != nil {
		return "unknown"
	}
	text := strings.ToLower(string(out))
	// Output format: "2048 SHA256:xxx user@host (RSA)"
	for _, alg := range []string{"ed25519", "ecdsa", "rsa", "dsa"} {
		if strings.Contains(text, alg) {
			return alg
		}
	}
	return "unknown"
}
