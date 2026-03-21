package app

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cssh/internal/errorsx"
	"cssh/internal/model"
	"cssh/internal/resolve"
	"cssh/internal/util"
)

// KeySetupInput describes the parameters for the SSH key setup web form.
type KeySetupInput struct {
	ProfileID string
	ScanDir   string // default "~/.ssh/"
	Mode      string // auto|terminal|web
	Notify    func(string) // optional; called with user-facing messages (e.g. web URL)
}

// KeySetup opens a web form (or returns manual instructions) for selecting
// an SSH key for a profile. It follows the same pattern as CredentialPrompt.
func (s *Service) KeySetup(in KeySetupInput) (map[string]any, error) {
	traceID := util.NewID("trace")
	writeAudit := func(status, detail string) {
		_ = s.audit.Write(model.AuditEvent{
			Timestamp: time.Now().UTC(),
			TraceID:   traceID,
			Type:      "ssh_key_setup",
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

	scanDir := strings.TrimSpace(in.ScanDir)
	if scanDir == "" {
		scanDir = "~/.ssh/"
	}
	// Expand ~ to home directory for internal use
	if strings.HasPrefix(scanDir, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			scanDir = filepath.Join(home, scanDir[2:])
		}
	}

	mode := normalizePromptMode(in.Mode)
	if mode == "web" || mode == "auto" {
		if hasDisplay() {
			result, err := s.keySetupWeb(profile, scanDir, in.Notify)
			if err == nil {
				writeAudit("ok", "method=web profile_id="+profile.ID)
				return result, nil
			}
		}
	}

	resp := manualKeySetupResult(profile.ID)
	writeAudit("ok", "method=manual profile_id="+profile.ID)
	return resp, nil
}

func manualKeySetupResult(profileID string) map[string]any {
	ctl := resolve.QuotedPath()
	return map[string]any{
		"saved":  false,
		"method": "manual",
		"manual_commands": []string{
			ctl + " key scan --dir ~/.ssh/",
			ctl + " profile edit --id " + profileID + " --key-path <path>",
			ctl + " secret set-key-passphrase --profile " + profileID,
		},
		"message": "Web key setup unavailable. Run the commands above in another terminal.",
	}
}

func (s *Service) keySetupWeb(profile *model.Profile, scanDir string, notify func(string)) (map[string]any, error) {
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

	resultCh := make(chan map[string]any, 1)
	errCh := make(chan error, 1)

	mux := http.NewServeMux()

	// GET / — renders the key selection HTML page
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		html := keySetupHTML(profile, scanDir, nonce)
		fmt.Fprint(w, html)
	})

	// GET /scan?dir=PATH — JSON API that calls ScanSSHKeys(dir)
	mux.HandleFunc("/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		dir := r.URL.Query().Get("dir")
		if dir == "" {
			dir = scanDir
		}
		// Expand ~ prefix
		if strings.HasPrefix(dir, "~/") {
			if home, err := os.UserHomeDir(); err == nil {
				dir = filepath.Join(home, dir[2:])
			}
		}
		// Safety: dir must be under $HOME
		home, err := os.UserHomeDir()
		if err != nil {
			http.Error(w, "cannot determine home directory", http.StatusInternalServerError)
			return
		}
		absDir, err := filepath.Abs(dir)
		if err != nil || !strings.HasPrefix(absDir, home) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": "scan directory must be under home directory",
			})
			return
		}

		keys, err := ScanSSHKeys(dir)
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error": err.Error(),
			})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": keys,
			"dir":  absDir,
		})
	})

	// POST /submit — accepts key_path + passphrase + nonce
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

		keyPath := strings.TrimSpace(r.FormValue("key_path"))
		passphrase := r.FormValue("passphrase")

		if keyPath == "" {
			http.Error(w, "key_path is required", http.StatusBadRequest)
			return
		}

		// Update profile with the selected key path
		profile.KeyPath = keyPath
		if err := s.profiles.Upsert(*profile); err != nil {
			errCh <- fmt.Errorf("save profile key_path: %w", err)
			http.Error(w, "save failed", http.StatusInternalServerError)
			return
		}

		// Store passphrase if provided
		passphraseSaved := false
		if strings.TrimSpace(passphrase) != "" {
			if err := s.secrets.Set(profile.ID, "key_passphrase", passphrase); err != nil {
				errCh <- fmt.Errorf("save key_passphrase: %w", err)
				http.Error(w, "save failed", http.StatusInternalServerError)
				return
			}
			passphraseSaved = true
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, keySetupSuccessHTML)

		resultCh <- map[string]any{
			"saved":            true,
			"profile_id":       profile.ID,
			"key_path":         keyPath,
			"passphrase_saved": passphraseSaved,
			"method":           "web_form",
			"connect_hint": map[string]any{
				"tool":      "ssh_connect",
				"arguments": map[string]any{"profile_id": profile.ID},
			},
		}
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
	if notify != nil {
		notify("Key setup page opened at " + url)
	}

	select {
	case result := <-resultCh:
		return result, nil
	case err := <-errCh:
		return nil, err
	case <-time.After(5 * time.Minute):
		return nil, fmt.Errorf("key setup timed out after 5 minutes")
	}
}

func keySetupHTML(profile *model.Profile, defaultDir, nonce string) string {
	// Collapse home dir back to ~ for display
	displayDir := defaultDir
	if home, err := os.UserHomeDir(); err == nil {
		if strings.HasPrefix(displayDir, home) {
			displayDir = "~" + displayDir[len(home):]
		}
	}
	// Escape values for safe embedding in HTML
	host := htmlEscape(profile.Host)
	port := fmt.Sprintf("%d", profile.Port)
	username := htmlEscape(profile.Username)
	escapedDir := htmlEscape(displayDir)
	escapedNonce := htmlEscape(nonce)

	return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CSSH — SSH Key Setup</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f5f5f5;display:flex;justify-content:center;align-items:center;min-height:100vh;padding:16px}
.card{background:#fff;border-radius:8px;box-shadow:0 1px 4px rgba(0,0,0,.08);max-width:420px;width:100%;padding:24px}
h1{font-size:15px;font-weight:600;color:#111;margin-bottom:12px}
.ctx{font-size:12px;color:#666;margin-bottom:16px;line-height:1.5}
.ctx b{color:#333;font-weight:500}
.scan-row{display:flex;gap:6px;margin-bottom:12px}
.scan-row input{flex:1;padding:7px 10px;border:1px solid #ddd;border-radius:6px;font-size:13px;outline:none}
.scan-row input:focus{border-color:#333}
.btn{padding:7px 14px;background:#222;color:#fff;border:none;border-radius:6px;font-size:13px;font-weight:500;cursor:pointer}
.btn:hover{background:#000}
.btn:disabled{background:#aaa;cursor:not-allowed}
.spinner{display:none;text-align:center;padding:16px;color:#999;font-size:13px}
.spinner.active{display:block}
.spinner::before{content:"";display:block;width:20px;height:20px;margin:0 auto 8px;border:2px solid #e5e5e5;border-top-color:#555;border-radius:50%;animation:spin .6s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.key-list{margin-bottom:14px;max-height:210px;overflow-y:auto;scrollbar-width:thin;scrollbar-color:#ddd transparent}
.key-list::-webkit-scrollbar{width:4px}
.key-list::-webkit-scrollbar-track{background:transparent}
.key-list::-webkit-scrollbar-thumb{background:#ddd;border-radius:2px}
.key-list::-webkit-scrollbar-thumb:hover{background:#bbb}
.kc{display:flex;align-items:center;padding:8px 10px;border:1px solid #e5e5e5;border-radius:6px;margin-bottom:5px;cursor:pointer;transition:border-color .1s,background .1s}
.kc:hover{background:#fafafa}
.kc.sel{border-color:#222;background:#fafafa}
.kc input[type=radio]{margin-right:10px;accent-color:#222;flex-shrink:0}
.ki{flex:1;min-width:0}
.kn{font-size:13px;font-weight:500;color:#222}
.km{font-size:11px;color:#888;margin-top:2px}
.km .tag{color:#555;font-weight:500}
.km .st-ok{color:#555}
.km .st-agent{color:#555}
.km .st-warn{color:#b45309}
.empty{text-align:center;padding:20px;color:#999;font-size:13px;border:1px dashed #ddd;border-radius:6px;margin-bottom:14px}
.field{margin-bottom:14px}
.field label{display:block;font-size:13px;font-weight:500;margin-bottom:4px;color:#333}
.iw{position:relative}
.iw input{width:100%;padding:7px 36px 7px 10px;border:1px solid #ddd;border-radius:6px;font-size:13px;outline:none}
.iw input:focus{border-color:#333}
.iw input:disabled{background:#f9f9f9;color:#bbb}
.tog{position:absolute;right:6px;top:50%;transform:translateY(-50%);background:none;border:none;cursor:pointer;color:#aaa;font-size:11px;padding:2px 4px}
.tog:hover{color:#555}
.sub{width:100%;padding:9px;background:#222;color:#fff;border:none;border-radius:6px;font-size:13px;font-weight:500;cursor:pointer}
.sub:hover{background:#000}
.sub:disabled{background:#aaa;cursor:not-allowed}
.note{margin-top:12px;font-size:11px;color:#aaa;text-align:center;line-height:1.4}
</style>
</head>
<body>
<div class="card">
<h1>SSH Key Setup</h1>
<div class="ctx">
<b>` + host + `:` + port + `</b> &middot; ` + username + `
</div>

<div class="scan-row">
<input type="text" id="scanDir" value="` + escapedDir + `" placeholder="~/.ssh/">
<button type="button" class="btn" id="scanBtn" onclick="doScan()">Scan</button>
</div>

<div class="spinner" id="spinner">Scanning...</div>
<div id="keyList"></div>

<form method="POST" action="/submit" id="keyForm" onsubmit="return validateForm()">
<input type="hidden" name="nonce" value="` + escapedNonce + `">
<input type="hidden" name="key_path" id="selectedKeyPath" value="">

<div class="field">
<label>Passphrase</label>
<div class="iw">
<input type="password" name="passphrase" id="passphrase" autocomplete="off" disabled placeholder="Select a key first">
<button type="button" class="tog" onclick="toggleVis('passphrase',this)">Show</button>
</div>
</div>

<button type="submit" class="sub" id="submitBtn" disabled>Save &amp; Continue</button>
</form>
<p class="note">Key path saved to profile. Passphrase stored in system keychain.<br>AI never sees either.</p>
</div>

<script>
var currentKeys = [];
var selectedKey = null;

function doScan() {
	var dir = document.getElementById('scanDir').value.trim();
	if (!dir) dir = '~/.ssh/';
	var btn = document.getElementById('scanBtn');
	var spinner = document.getElementById('spinner');
	var list = document.getElementById('keyList');
	btn.disabled = true;
	spinner.className = 'spinner active';
	list.innerHTML = '';
	selectedKey = null;
	updatePassphraseState();
	updateSubmitState();

	fetch('/scan?dir=' + encodeURIComponent(dir))
		.then(function(r) { return r.json(); })
		.then(function(data) {
			btn.disabled = false;
			spinner.className = 'spinner';
			if (data.error) {
				list.innerHTML = '<div class="empty">' + escapeHtml(data.error) + '</div>';
				return;
			}
			currentKeys = data.keys || [];
			renderKeys();
		})
		.catch(function(err) {
			btn.disabled = false;
			spinner.className = 'spinner';
			list.innerHTML = '<div class="empty">Scan failed: ' + escapeHtml(err.message) + '</div>';
		});
}

function renderKeys() {
	var list = document.getElementById('keyList');
	if (currentKeys.length === 0) {
		list.innerHTML = '<div class="empty">No SSH keys found in this directory.</div>';
		return;
	}
	var html = '<div class="key-list">';
	for (var i = 0; i < currentKeys.length; i++) {
		var k = currentKeys[i];
		var status = '';
		if (!k.needs_passphrase) {
			status = '<span class="st-ok">no passphrase</span>';
		} else if (k.in_agent) {
			status = '<span class="st-agent">in agent</span>';
		} else {
			status = '<span class="st-warn">passphrase needed</span>';
		}
		html += '<div class="kc" onclick="selectKey(' + i + ')" id="kc_' + i + '">';
		html += '<input type="radio" name="key_sel" id="kr_' + i + '">';
		html += '<div class="ki">';
		html += '<div class="kn">' + escapeHtml(k.name) + '</div>';
		html += '<div class="km"><span class="tag">' + escapeHtml(k.algorithm) + '</span> &middot; ' + status + '</div>';
		html += '</div></div>';
	}
	html += '</div>';
	list.innerHTML = html;
}

function selectKey(idx) {
	selectedKey = idx;
	document.getElementById('selectedKeyPath').value = currentKeys[idx].path;
	for (var i = 0; i < currentKeys.length; i++) {
		document.getElementById('kc_' + i).className = i === idx ? 'kc sel' : 'kc';
		document.getElementById('kr_' + i).checked = i === idx;
	}
	updatePassphraseState();
	updateSubmitState();
}

function updatePassphraseState() {
	var el = document.getElementById('passphrase');
	if (selectedKey === null) { el.disabled = true; el.placeholder = 'Select a key first'; el.value = ''; return; }
	var k = currentKeys[selectedKey];
	if (!k.needs_passphrase) { el.disabled = true; el.placeholder = 'Not required'; el.value = ''; }
	else if (k.in_agent) { el.disabled = false; el.placeholder = 'Optional (key in agent)'; }
	else { el.disabled = false; el.placeholder = 'Enter passphrase'; }
}

function updateSubmitState() { document.getElementById('submitBtn').disabled = (selectedKey === null); }

function validateForm() {
	if (selectedKey === null) return false;
	return true;
}

function toggleVis(id, btn) {
	var el = document.getElementById(id);
	if (el.type === 'password') { el.type = 'text'; btn.textContent = 'Hide'; }
	else { el.type = 'password'; btn.textContent = 'Show'; }
}

function escapeHtml(s) {
	var d = document.createElement('div');
	d.appendChild(document.createTextNode(s));
	return d.innerHTML;
}

document.addEventListener('DOMContentLoaded', function() { doScan(); });
</script>
</body>
</html>`
}

func htmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}

const keySetupSuccessHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>CSSH — Key Saved</title>
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
<h1>SSH Key Saved</h1>
<p>You can close this page.</p>
</div>
<script>setTimeout(function(){window.close()},2000)</script>
</body>
</html>`
