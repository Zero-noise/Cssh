//go:build integration

package sshbridge

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"cssh/internal/model"
)

func TestTransferWithDockerOpenSSH(t *testing.T) {
	if os.Getenv("CSSH_E2E") != "1" {
		t.Skip("set CSSH_E2E=1 to run docker-based transfer e2e")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is unavailable")
	}
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen is unavailable")
	}
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Skip("ssh client is unavailable")
	}
	if err := exec.Command("docker", "version").Run(); err != nil {
		t.Skipf("docker is unavailable: %v", err)
	}

	tmp := t.TempDir()
	keyPath := filepath.Join(tmp, "id_ed25519")
	if out, err := runCmd("ssh-keygen", "-t", "ed25519", "-N", "", "-f", keyPath); err != nil {
		t.Fatalf("ssh-keygen failed: %v (%s)", err, out)
	}
	pubKeyBytes, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatalf("read public key: %v", err)
	}
	pubKey := strings.TrimSpace(string(pubKeyBytes))

	containerName := fmt.Sprintf("cssh-e2e-%d", time.Now().UnixNano())
	t.Cleanup(func() {
		_, _ = runCmd("docker", "rm", "-f", containerName)
	})

	if out, err := runCmd(
		"docker", "run", "-d", "--rm",
		"--name", containerName,
		"-e", "PUBLIC_KEY="+pubKey,
		"-e", "USER_NAME=tester",
		"-e", "PASSWORD_ACCESS=false",
		"-e", "SUDO_ACCESS=false",
		"-p", "127.0.0.1::2222",
		"lscr.io/linuxserver/openssh-server:latest",
	); err != nil {
		t.Fatalf("docker run failed: %v (%s)", err, out)
	}

	portOut, err := runCmd("docker", "port", containerName, "2222/tcp")
	if err != nil {
		t.Fatalf("docker port failed: %v (%s)", err, portOut)
	}
	port, err := parseMappedPort(portOut)
	if err != nil {
		t.Fatalf("parse mapped port: %v (%q)", err, portOut)
	}

	waitForSSHReady(t, keyPath, port)

	m := NewManager(filepath.Join(tmp, "runtime"), "bash -lc", 30)
	conn, err := m.Connect(model.Connection{
		Host:           "127.0.0.1",
		Port:           port,
		Username:       "tester",
		AuthPriority:   []string{"key"},
		KeyPath:        keyPath,
		WorkspaceRoots: []string{"/tmp"},
	})
	if err != nil {
		t.Fatalf("connect failed: %v", err)
	}
	t.Cleanup(func() { _ = m.Disconnect(conn.ID) })

	localUpload := filepath.Join(tmp, "upload.txt")
	payload := []byte("cssh integration transfer payload\n")
	if err := os.WriteFile(localUpload, payload, 0o644); err != nil {
		t.Fatalf("write upload file: %v", err)
	}
	remotePath := "/tmp/cssh-e2e-transfer.txt"
	upRes, err := m.UploadFile(conn.ID, localUpload, remotePath, 30, false, nil)
	if err != nil {
		t.Fatalf("upload failed: %v", err)
	}
	if upRes.Protocol == "" {
		t.Fatalf("upload protocol should be populated")
	}

	localDownload := filepath.Join(tmp, "download.txt")
	downRes, err := m.DownloadFile(conn.ID, remotePath, localDownload, 30, false, nil)
	if err != nil {
		t.Fatalf("download failed: %v", err)
	}
	if downRes.Protocol == "" {
		t.Fatalf("download protocol should be populated")
	}

	got, err := os.ReadFile(localDownload)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("download mismatch: got=%q want=%q", string(got), string(payload))
	}
}

func waitForSSHReady(t *testing.T, keyPath string, port int) {
	t.Helper()
	var lastErr error
	for i := 0; i < 40; i++ {
		cmd := exec.Command(
			"ssh",
			"-o", "StrictHostKeyChecking=accept-new",
			"-o", "BatchMode=yes",
			"-o", "ConnectTimeout=2",
			"-i", keyPath,
			"-p", strconv.Itoa(port),
			"tester@127.0.0.1",
			"true",
		)
		if err := cmd.Run(); err == nil {
			return
		} else {
			lastErr = err
		}
		time.Sleep(1 * time.Second)
	}
	t.Fatalf("ssh server did not become ready: %v", lastErr)
}

func parseMappedPort(out string) (int, error) {
	line := strings.TrimSpace(out)
	if line == "" {
		return 0, fmt.Errorf("empty docker port output")
	}
	lastColon := strings.LastIndex(line, ":")
	if lastColon < 0 || lastColon+1 >= len(line) {
		return 0, fmt.Errorf("unexpected docker port output")
	}
	port, err := strconv.Atoi(strings.TrimSpace(line[lastColon+1:]))
	if err != nil {
		return 0, err
	}
	return port, nil
}

func runCmd(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := strings.TrimSpace(stdout.String())
	errOut := strings.TrimSpace(stderr.String())
	if err != nil && errOut != "" {
		return out + " " + errOut, err
	}
	return out, err
}
