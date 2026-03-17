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
	"cssh/internal/resolve"
	"cssh/internal/util"
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
	traceID := util.NewID("trace")
	writeAudit := func(status, detail string) {
		_ = s.audit.Write(model.AuditEvent{
			Timestamp: time.Now().UTC(),
			TraceID:   traceID,
			Type:      "ssh_credentials_prompt",
			Status:    status,
			Detail:    detail,
		})
	}
	if strings.TrimSpace(in.ProfileID) == "" {
		err := errorsx.New(errorsx.CodeInvalidParams, "profile_id is required")
		writeAudit("error", err.Error())
		return nil, err
	}
	profile, err := s.profiles.Get(strings.TrimSpace(in.ProfileID))
	if err != nil {
		writeAudit("error", err.Error())
		return nil, err
	}
	if profile == nil {
		err := errorsx.New(errorsx.CodeInvalidParams, "profile not found: "+in.ProfileID)
		writeAudit("error", err.Error())
		return nil, err
	}

	fields := in.Fields
	if len(fields) == 0 {
		fields = inferCredentialFields(profile)
	}
	fields, invalid := normalizeCredentialFields(fields)
	if len(in.Fields) > 0 && len(invalid) > 0 {
		err := errorsx.New(errorsx.CodeInvalidParams, "invalid fields: "+strings.Join(invalid, ", "))
		writeAudit("error", err.Error())
		return nil, err
	}
	if len(fields) == 0 {
		resp := map[string]any{
			"saved":         false,
			"profile_id":    profile.ID,
			"secrets_saved": map[string]bool{},
			"method":        "none",
			"message":       "No credential fields needed for this profile's auth_priority.",
		}
		writeAudit("ok", "method=none profile_id="+profile.ID)
		return resp, nil
	}

	mode := normalizePromptMode(in.Mode)
	if mode == "terminal" {
		if !canUseTerminalPrompt() {
			resp := manualCredentialPromptResult(profile.ID, fields)
			writeAudit("ok", "method=manual profile_id="+profile.ID)
			return resp, nil
		}
		result, err := s.credentialPromptTerminal(profile, fields)
		if err == nil {
			writeAudit("ok", "method=terminal profile_id="+profile.ID)
			return result, nil
		}
		resp := manualCredentialPromptResult(profile.ID, fields)
		writeAudit("ok", "method=manual profile_id="+profile.ID)
		return resp, nil
	}
	if mode == "web" || mode == "auto" {
		if hasDisplay() {
			result, err := s.credentialPromptWeb(profile, fields)
			if err == nil {
				writeAudit("ok", "method=web profile_id="+profile.ID)
				return result, nil
			}
		}
	}

	resp := manualCredentialPromptResult(profile.ID, fields)
	writeAudit("ok", "method=manual profile_id="+profile.ID)
	return resp, nil
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
	cmds := manualCredentialCommands(profileID, fields)
	if len(cmds) == 0 {
		return "Could not open browser. Use " + resolve.QuotedPath() + " secret set-* manually."
	}
	return "Web credential prompt is unavailable. Run the command(s): " + strings.Join(cmds, " ; ") + ". Run them in another terminal tab/window to continue without restarting; or run them after closing this session, then restart Claude Code/Codex and resume this conversation."
}

func manualCredentialCommands(profileID string, fields []string) []string {
	ctl := resolve.QuotedPath()
	cmds := make([]string, 0, len(fields))
	for _, f := range fields {
		switch f {
		case "password":
			cmds = append(cmds, ctl+" secret set-password --profile "+profileID)
		case "key_passphrase":
			cmds = append(cmds, ctl+" secret set-key-passphrase --profile "+profileID)
		case "sudo_password":
			cmds = append(cmds, ctl+" secret set-sudo-password --profile "+profileID)
		}
	}
	return cmds
}

func manualCredentialPromptResult(profileID string, fields []string) map[string]any {
	cmds := manualCredentialCommands(profileID, fields)
	return map[string]any{
		"saved":           false,
		"profile_id":      profileID,
		"method":          "manual",
		"manual_commands": cmds,
		"message":         manualCredentialInstructions(profileID, fields),
	}
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
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f5f5;display:flex;justify-content:center;align-items:center;min-height:100vh;padding:16px}
.card{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.08);max-width:420px;width:100%;padding:24px}
h1{font-size:15px;font-weight:600;color:#111;margin-bottom:12px}
.ctx{font-size:12px;color:#666;margin-bottom:16px;line-height:1.5}
.ctx b{color:#333;font-weight:500}
.field{margin-bottom:14px}
.field label{display:block;font-size:13px;font-weight:500;margin-bottom:4px;color:#333}
.iw{position:relative}
.iw input{width:100%;padding:7px 36px 7px 10px;border:1px solid #ddd;border-radius:6px;font-size:13px;outline:none}
.iw input:focus{border-color:#333}
.tog{position:absolute;right:6px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:#aaa;font-size:11px;padding:2px 4px}
.tog:hover{color:#555}
.sub{width:100%;padding:9px;background:#222;color:#fff;border:none;border-radius:6px;font-size:13px;font-weight:500;cursor:pointer}
.sub:hover{background:#000}
.note{margin-top:12px;font-size:11px;color:#aaa;text-align:center;line-height:1.4}
</style>
</head>
<body>
<div class="card">
<h1>SSH Credential Entry</h1>
<div class="ctx">
<b>{{.Profile.Host}}:{{.Profile.Port}}</b> &middot; {{.Profile.Username}} &middot; {{range $i, $v := .Profile.AuthPriority}}{{if $i}}, {{end}}{{$v}}{{end}}
</div>
<form method="POST" action="/submit">
<input type="hidden" name="nonce" value="{{.Nonce}}">
{{range .Fields}}
<div class="field">
<label>{{if eq . "password"}}Password{{else if eq . "key_passphrase"}}Key Passphrase{{else if eq . "sudo_password"}}Sudo Password{{else}}{{.}}{{end}}</label>
<div class="iw">
<input type="password" name="{{.}}" id="f_{{.}}" autocomplete="off">
<button type="button" class="tog" onclick="toggleVis('f_{{.}}',this)">Show</button>
</div>
</div>
{{end}}
<button type="submit" class="sub">Save to Keychain</button>
</form>
<p class="note">Credentials saved to system keychain. AI never sees them.</p>
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
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f5f5;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.08);max-width:320px;width:100%;padding:32px;text-align:center}
.ok{font-size:36px;margin-bottom:12px}
h1{font-size:15px;font-weight:600;color:#111;margin-bottom:6px}
p{color:#888;font-size:12px}
</style>
</head>
<body>
<div class="card">
<div class="ok">&#10003;</div>
<h1>Credentials Saved</h1>
<p>You can close this page.</p>
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
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f5f5;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.08);max-width:320px;width:100%;padding:32px;text-align:center}
h1{font-size:15px;font-weight:600;color:#111;margin-bottom:8px}
p{color:#888;font-size:12px;line-height:1.5}
</style>
</head>
<body>
<div class="card">
<h1>No Credentials Saved</h1>
<p>No values were submitted. Fill at least one field and submit again.</p>
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
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f5f5;display:flex;justify-content:center;align-items:center;min-height:100vh}
.card{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.08);max-width:320px;width:100%;padding:32px;text-align:center}
h1{font-size:15px;font-weight:600;color:#111;margin-bottom:8px}
p{color:#888;font-size:12px;line-height:1.5}
</style>
</head>
<body>
<div class="card">
<h1>Partially Saved</h1>
<p>Some fields were saved, but at least one was left empty.</p>
</div>
<script>setTimeout(function(){window.close()},2500)</script>
</body>
</html>`
