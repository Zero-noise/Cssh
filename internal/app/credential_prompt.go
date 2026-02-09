package app

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"cssh/internal/errorsx"
	"cssh/internal/model"
)

type CredentialPromptInput struct {
	ProfileID string
	Fields    []string // "password", "key_passphrase", "sudo_password"
	Mode      string   // auto|terminal|web
}

var allowedCredentialFields = map[string]struct{}{
	"password":       {},
	"key_passphrase": {},
	"sudo_password":  {},
}

func (s *Service) CredentialPrompt(in CredentialPromptInput) (map[string]any, error) {
	if strings.TrimSpace(in.ProfileID) == "" {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "profile_id is required")
	}
	profile, err := s.profiles.Get(strings.TrimSpace(in.ProfileID))
	if err != nil {
		return nil, err
	}
	if profile == nil {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "profile not found: "+in.ProfileID)
	}

	fields := in.Fields
	if len(fields) == 0 {
		fields = inferCredentialFields(profile)
	}
	fields, invalid := normalizeCredentialFields(fields)
	if len(in.Fields) > 0 && len(invalid) > 0 {
		return nil, errorsx.New(errorsx.CodeInvalidParams, "invalid fields: "+strings.Join(invalid, ", "))
	}
	if len(fields) == 0 {
		return map[string]any{
			"saved":         false,
			"profile_id":    profile.ID,
			"secrets_saved": map[string]bool{},
			"method":        "none",
			"message":       "No credential fields needed for this profile's auth_priority.",
		}, nil
	}

	mode := normalizePromptMode(in.Mode)
	if mode == "terminal" {
		if !canUseTerminalPrompt() {
			return map[string]any{
				"saved":      false,
				"profile_id": profile.ID,
				"method":     "manual",
				"message":    "Terminal credential prompt is unavailable in this MCP session. Use prompt_mode=web, or run csshctl secret set-* manually.",
			}, nil
		}
		result, err := s.credentialPromptTerminal(profile, fields)
		if err == nil {
			return result, nil
		}
	}
	if mode == "web" || mode == "auto" {
		if hasDisplay() {
			result, err := s.credentialPromptWeb(profile, fields)
			if err == nil {
				return result, nil
			}
		}
		if hasDisplay() {
			result, err := s.credentialPromptEditor(profile, fields)
			if err == nil {
				return result, nil
			}
		}
	}
	if mode == "auto" {
		if canUseTerminalPrompt() {
			result, err := s.credentialPromptTerminal(profile, fields)
			if err == nil {
				return result, nil
			}
		}
	}

	return map[string]any{
		"saved":      false,
		"profile_id": profile.ID,
		"method":     "manual",
		"message":    manualCredentialInstructions(profile.ID, fields),
	}, nil
}

func normalizePromptMode(v string) string {
	mode := strings.ToLower(strings.TrimSpace(v))
	switch mode {
	case "terminal", "web":
		return mode
	default:
		return "auto"
	}
}

func canUseTerminalPrompt() bool {
	inInfo, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	outInfo, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	inTTY := (inInfo.Mode() & os.ModeCharDevice) != 0
	outTTY := (outInfo.Mode() & os.ModeCharDevice) != 0
	return inTTY && outTTY
}

func inferCredentialFields(p *model.Profile) []string {
	var fields []string
	for _, a := range p.AuthPriority {
		switch a {
		case "password":
			fields = append(fields, "password")
		case "key":
			fields = append(fields, "key_passphrase")
		}
	}
	return fields
}

func normalizeCredentialFields(fields []string) ([]string, []string) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(fields))
	invalid := make([]string, 0)
	for _, f := range fields {
		key := strings.TrimSpace(strings.ToLower(f))
		if key == "" {
			continue
		}
		if _, ok := allowedCredentialFields[key]; !ok {
			invalid = append(invalid, key)
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, key)
	}
	return out, invalid
}

func manualCredentialInstructions(profileID string, fields []string) string {
	cmds := make([]string, 0, len(fields))
	for _, f := range fields {
		switch f {
		case "password":
			cmds = append(cmds, "csshctl secret set-password --profile "+profileID)
		case "key_passphrase":
			cmds = append(cmds, "csshctl secret set-key-passphrase --profile "+profileID)
		case "sudo_password":
			cmds = append(cmds, "csshctl secret set-sudo-password --profile "+profileID)
		}
	}
	if len(cmds) == 0 {
		return "Could not open browser or editor. Use csshctl secret commands to set credentials manually."
	}
	return "Could not open browser or editor. Set credentials manually with: " + strings.Join(cmds, " ; ")
}

func (s *Service) credentialPromptWeb(profile *model.Profile, fields []string) (map[string]any, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	defer listener.Close()

	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	nonce := hex.EncodeToString(nonceBytes)

	resultCh := make(chan map[string]bool, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		data := credFormData{
			Profile: profile,
			Fields:  fields,
			Nonce:   nonce,
		}
		if err := credFormTmpl.Execute(w, data); err != nil {
			http.Error(w, "template error", http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		submittedNonce := r.FormValue("nonce")
		if subtle.ConstantTimeCompare([]byte(submittedNonce), []byte(nonce)) != 1 {
			http.Error(w, "invalid nonce", http.StatusForbidden)
			return
		}

		saved := map[string]bool{}
		for _, f := range fields {
			val := r.FormValue(f)
			if strings.TrimSpace(val) == "" {
				saved[f] = false
				continue
			}
			if err := s.secrets.Set(profile.ID, f, val); err != nil {
				errCh <- fmt.Errorf("save %s: %w", f, err)
				http.Error(w, "save failed", http.StatusInternalServerError)
				return
			}
			saved[f] = true
		}

		savedCount := countSavedFields(saved)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		switch {
		case savedCount == len(fields):
			fmt.Fprint(w, credSuccessHTML)
		case savedCount == 0:
			fmt.Fprint(w, credNoChangesHTML)
		default:
			fmt.Fprint(w, credPartialHTML)
		}
		resultCh <- saved
	})

	server := &http.Server{Handler: mux}
	go func() {
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()

	url := fmt.Sprintf("http://127.0.0.1:%d", listener.Addr().(*net.TCPAddr).Port)
	if err := openBrowser(url); err != nil {
		return nil, fmt.Errorf("open browser: %w", err)
	}

	select {
	case saved := <-resultCh:
		savedCount := countSavedFields(saved)
		return map[string]any{
			"saved":         savedCount > 0,
			"profile_id":    profile.ID,
			"secrets_saved": saved,
			"method":        "web_form",
			"connect_hint": map[string]any{
				"tool":      "ssh_connect",
				"arguments": map[string]any{"profile_id": profile.ID},
			},
		}, nil
	case err := <-errCh:
		return nil, err
	case <-time.After(5 * time.Minute):
		return nil, fmt.Errorf("credential prompt timed out after 5 minutes")
	}
}

func (s *Service) credentialPromptEditor(profile *model.Profile, fields []string) (map[string]any, error) {
	tmpFile, err := os.CreateTemp("", "cssh-creds-*.txt")
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)

	if err := os.Chmod(tmpPath, 0o600); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("chmod: %w", err)
	}

	var tmplBuf strings.Builder
	tmplBuf.WriteString("# CSSH Credential Entry\n")
	tmplBuf.WriteString(fmt.Sprintf("# Profile: %s (%s)\n", profile.Name, profile.ID))
	tmplBuf.WriteString(fmt.Sprintf("# Host: %s:%d  User: %s\n", profile.Host, profile.Port, profile.Username))
	tmplBuf.WriteString("# Enter credentials below, save and close the editor.\n")
	tmplBuf.WriteString("# Lines starting with # are ignored.\n\n")
	for _, f := range fields {
		tmplBuf.WriteString(f + ":\n")
	}

	if _, err := tmpFile.WriteString(tmplBuf.String()); err != nil {
		tmpFile.Close()
		return nil, fmt.Errorf("write template: %w", err)
	}
	tmpFile.Close()

	switch runtime.GOOS {
	case "darwin":
		cmd := exec.Command("open", "-t", "-W", tmpPath)
		if err := cmd.Run(); err != nil {
			return nil, fmt.Errorf("open editor: %w", err)
		}
	case "linux":
		cmd := exec.Command("xdg-open", tmpPath)
		if err := cmd.Start(); err != nil {
			return nil, fmt.Errorf("xdg-open: %w", err)
		}
		// poll mtime for changes
		initialInfo, err := os.Stat(tmpPath)
		if err != nil {
			return nil, fmt.Errorf("stat temp file: %w", err)
		}
		initialMtime := initialInfo.ModTime()
		deadline := time.Now().Add(5 * time.Minute)
		for time.Now().Before(deadline) {
			time.Sleep(1 * time.Second)
			info, err := os.Stat(tmpPath)
			if err != nil {
				continue
			}
			if info.ModTime().After(initialMtime) {
				// give user a moment to finish saving
				time.Sleep(1 * time.Second)
				break
			}
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("editor prompt timed out after 5 minutes")
		}
	default:
		return nil, fmt.Errorf("unsupported OS for editor prompt: %s", runtime.GOOS)
	}

	content, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, fmt.Errorf("read temp file: %w", err)
	}

	saved := map[string]bool{}
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	for scanner.Scan() {
		line := scanner.Text()
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if val == "" {
			continue
		}
		validField := false
		for _, f := range fields {
			if f == key {
				validField = true
				break
			}
		}
		if !validField {
			continue
		}
		if err := s.secrets.Set(profile.ID, key, val); err != nil {
			return nil, fmt.Errorf("save %s: %w", key, err)
		}
		saved[key] = true
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan temp file: %w", err)
	}

	for _, f := range fields {
		if _, ok := saved[f]; !ok {
			saved[f] = false
		}
	}

	return map[string]any{
		"saved":         countSavedFields(saved) > 0,
		"profile_id":    profile.ID,
		"secrets_saved": saved,
		"method":        "editor",
		"connect_hint": map[string]any{
			"tool":      "ssh_connect",
			"arguments": map[string]any{"profile_id": profile.ID},
		},
	}, nil
}

func (s *Service) credentialPromptTerminal(profile *model.Profile, fields []string) (map[string]any, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open tty: %w", err)
	}
	defer tty.Close()

	_, _ = fmt.Fprintf(tty, "\n[cssh] credential prompt\n")
	_, _ = fmt.Fprintf(tty, "profile: %s (%s)\n", profile.Name, profile.ID)
	_, _ = fmt.Fprintf(tty, "host: %s:%d user: %s\n", profile.Host, profile.Port, profile.Username)

	saved := map[string]bool{}
	reader := bufio.NewReader(tty)
	for _, f := range fields {
		label := fieldLabel(f)
		val, err := readSecretFromTTY(reader, tty, label)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(val) == "" {
			saved[f] = false
			continue
		}
		if err := s.secrets.Set(profile.ID, f, val); err != nil {
			return nil, fmt.Errorf("save %s: %w", f, err)
		}
		saved[f] = true
	}
	return map[string]any{
		"saved":         countSavedFields(saved) > 0,
		"profile_id":    profile.ID,
		"secrets_saved": saved,
		"method":        "terminal_prompt",
		"connect_hint": map[string]any{
			"tool":      "ssh_connect",
			"arguments": map[string]any{"profile_id": profile.ID},
		},
	}, nil
}

func fieldLabel(name string) string {
	switch name {
	case "password":
		return "SSH Password"
	case "key_passphrase":
		return "Key Passphrase"
	case "sudo_password":
		return "Sudo Password"
	default:
		return name
	}
}

func readSecretFromTTY(reader *bufio.Reader, tty *os.File, label string) (string, error) {
	echoDisabled := disableTTYEcho(tty)
	defer func() {
		if echoDisabled {
			_ = enableTTYEcho(tty)
			_, _ = fmt.Fprintln(tty)
		}
	}()
	_, _ = fmt.Fprintf(tty, "%s (leave empty to skip): ", label)
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", fmt.Errorf("read %s: %w", label, err)
	}
	return strings.TrimSpace(line), nil
}

func disableTTYEcho(tty *os.File) bool {
	cmd := exec.Command("stty", "-echo")
	cmd.Stdin = tty
	cmd.Stdout = tty
	cmd.Stderr = tty
	return cmd.Run() == nil
}

func enableTTYEcho(tty *os.File) error {
	cmd := exec.Command("stty", "echo")
	cmd.Stdin = tty
	cmd.Stdout = tty
	cmd.Stderr = tty
	return cmd.Run()
}

func hasDisplay() bool {
	switch runtime.GOOS {
	case "darwin":
		if os.Getenv("SSH_CONNECTION") != "" && os.Getenv("DISPLAY") == "" {
			return false
		}
		return true
	case "linux":
		return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
	default:
		return false
	}
}

func countSavedFields(saved map[string]bool) int {
	n := 0
	for _, ok := range saved {
		if ok {
			n++
		}
	}
	return n
}

func openBrowser(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "linux":
		return exec.Command("xdg-open", url).Start()
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

type credFormData struct {
	Profile *model.Profile
	Fields  []string
	Nonce   string
}

var credFormTmpl = template.Must(template.New("cred").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CSSH — Credential Entry</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 16px rgba(0,0,0,.1);max-width:480px;width:100%;padding:32px}
h1{font-size:20px;margin-bottom:8px;color:#1a1a1a}
.context{background:#f7f8fa;border-radius:8px;padding:12px 16px;margin:12px 0 24px;font-size:13px;color:#555;line-height:1.6}
.context span{color:#333;font-weight:500}
.field{margin-bottom:20px}
.field label{display:block;font-size:14px;font-weight:500;margin-bottom:6px;color:#333}
.input-wrap{position:relative}
.input-wrap input{width:100%;padding:10px 42px 10px 12px;border:1px solid #d0d5dd;border-radius:8px;font-size:14px;outline:none;transition:border-color .2s}
.input-wrap input:focus{border-color:#2563eb;box-shadow:0 0 0 3px rgba(37,99,235,.1)}
.toggle{position:absolute;right:8px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:#888;font-size:13px;padding:4px 6px}
.toggle:hover{color:#333}
button[type=submit]{width:100%;padding:12px;background:#2563eb;color:#fff;border:none;border-radius:8px;font-size:15px;font-weight:500;cursor:pointer;transition:background .2s}
button[type=submit]:hover{background:#1d4ed8}
.note{margin-top:16px;font-size:12px;color:#888;text-align:center;line-height:1.5}
</style>
</head>
<body>
<div class="card">
<h1>SSH Credential Entry</h1>
<div class="context">
Host: <span>{{.Profile.Host}}:{{.Profile.Port}}</span><br>
Username: <span>{{.Profile.Username}}</span><br>
Auth Mode: <span>{{range $i, $v := .Profile.AuthPriority}}{{if $i}}, {{end}}{{$v}}{{end}}</span>
</div>
<form method="POST" action="/submit">
<input type="hidden" name="nonce" value="{{.Nonce}}">
{{range .Fields}}
<div class="field">
<label>{{if eq . "password"}}Password{{else if eq . "key_passphrase"}}Key Passphrase{{else if eq . "sudo_password"}}Sudo Password{{else}}{{.}}{{end}}</label>
<div class="input-wrap">
<input type="password" name="{{.}}" id="f_{{.}}" autocomplete="off">
<button type="button" class="toggle" onclick="toggleVis('f_{{.}}',this)">Show</button>
</div>
</div>
{{end}}
<button type="submit">Save to Keychain</button>
</form>
<p class="note">Credentials are saved directly to the system keychain.<br>AI will never see any passwords.</p>
</div>
<script>
function toggleVis(id,btn){var el=document.getElementById(id);if(el.type==='password'){el.type='text';btn.textContent='Hide'}else{el.type='password';btn.textContent='Show'}}
</script>
</body>
</html>`))

const credSuccessHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CSSH — Saved</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 16px rgba(0,0,0,.1);max-width:400px;width:100%;padding:40px;text-align:center}
.ok{font-size:48px;margin-bottom:16px}
h1{font-size:20px;color:#1a1a1a;margin-bottom:8px}
p{color:#666;font-size:14px}
</style>
</head>
<body>
<div class="card">
<div class="ok">&#10003;</div>
<h1>Credentials Saved</h1>
<p>You can close this page now.</p>
</div>
<script>setTimeout(function(){window.close()},2000)</script>
</body>
</html>`

const credNoChangesHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CSSH — No Credentials Saved</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 16px rgba(0,0,0,.1);max-width:440px;width:100%;padding:36px;text-align:center}
h1{font-size:20px;color:#1a1a1a;margin-bottom:10px}
p{color:#666;font-size:14px;line-height:1.6}
</style>
</head>
<body>
<div class="card">
<h1>No Credentials Saved</h1>
<p>No non-empty credential values were submitted.<br>Fill at least one field and submit again.</p>
</div>
</body>
</html>`

const credPartialHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CSSH — Partially Saved</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:12px;box-shadow:0 2px 16px rgba(0,0,0,.1);max-width:440px;width:100%;padding:36px;text-align:center}
h1{font-size:20px;color:#1a1a1a;margin-bottom:10px}
p{color:#666;font-size:14px;line-height:1.6}
</style>
</head>
<body>
<div class="card">
<h1>Credentials Partially Saved</h1>
<p>Some fields were saved, but at least one field was left empty.</p>
</div>
<script>setTimeout(function(){window.close()},2500)</script>
</body>
</html>`
