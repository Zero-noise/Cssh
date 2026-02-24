package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"cssh/internal/app"
	"cssh/internal/config"
	"cssh/internal/model"
)

func main() {
	configPath := os.Getenv("CSSH_CONFIG")
	if configPath == "" {
		configPath = "~/.csbridge/config.toml"
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		fatal(err)
	}
	svc := app.NewService(cfg)

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "profile":
		handleProfile(svc, cfg, os.Args[2:])
	case "secret":
		handleSecret(svc, os.Args[2:])
	case "approvals":
		handleApprovals(svc, os.Args[2:])
	case "approve":
		handleApproveReject(svc, true, os.Args[2:])
	case "reject":
		handleApproveReject(svc, false, os.Args[2:])
	case "migrate":
		handleMigrate(svc, cfg, os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`csshctl commands:
  profile add --id ID --name NAME --host HOST --user USER [--port 22] [--workspace-roots /a,/b] [--auth-priority key,password] [--key-path PATH] [--allow-public=false] [--security-profile easy_safe] [--allow-root-user=false] [--max-auto-risk L2] [--allow-reboot=false] [--allow-disk-ops=false] [--deny-patterns pat1,pat2]
  profile list
  profile show --id ID
  profile remove --id ID

  secret set-password --profile ID [--value VALUE]
  secret delete-password --profile ID
  secret set-key-passphrase --profile ID [--value VALUE]
  secret delete-key-passphrase --profile ID
  secret set-sudo-password --profile ID [--value VALUE]
  secret delete-sudo-password --profile ID

  approvals list [--status pending|approved|rejected]
  approve APPROVAL_ID [--by NAME] [-y]
  reject APPROVAL_ID [--by NAME] [--reason TEXT]

  migrate security
`)
}

func handleProfile(svc *app.Service, cfg model.Config, args []string) {
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}
	store := svc.ProfileStore()
	switch args[0] {
	case "add":
		fs := flag.NewFlagSet("profile add", flag.ExitOnError)
		id := fs.String("id", "", "profile id")
		name := fs.String("name", "", "profile display name")
		host := fs.String("host", "", "ssh host")
		port := fs.Int("port", 22, "ssh port")
		user := fs.String("user", "", "ssh username")
		workspaceRoots := fs.String("workspace-roots", "/", "comma separated roots")
		authPriority := fs.String("auth-priority", "key,password", "auth priority")
		keyPath := fs.String("key-path", "~/.ssh/id_rsa", "ssh private key path")
		allowPublic := fs.Bool("allow-public", false, "allow public host")
		securityProfile := fs.String("security-profile", cfg.SecurityProfileDefault, "security profile (easy_safe|ops_strict)")
		allowRootUser := fs.Bool("allow-root-user", false, "allow root username in this profile")
		maxAutoRisk := fs.String("max-auto-risk", "", "max risk level to auto-execute (L1 or L2)")
		allowReboot := fs.Bool("allow-reboot", false, "allow shutdown/reboot commands without approval")
		allowDiskOps := fs.Bool("allow-disk-ops", false, "allow disk operations (mkfs, dd, etc.) without approval")
		denyPatternsStr := fs.String("deny-patterns", "", "comma separated regex patterns to deny")
		_ = fs.Parse(args[1:])
		if *id == "" || *host == "" || *user == "" {
			fatal(fmt.Errorf("id, host, user are required"))
		}
		roots := splitCSV(*workspaceRoots)
		if len(roots) == 0 {
			roots = []string{"/"}
		}
		p := model.Profile{
			ID:                *id,
			Name:              strings.TrimSpace(*name),
			Host:              *host,
			Port:              *port,
			Username:          *user,
			AuthPriority:      splitCSV(*authPriority),
			KeyPath:           config.ExpandHome(*keyPath),
			WorkspaceRoots:    roots,
			AllowPublicHost:   *allowPublic,
			SecurityProfile:   normalizeSecurityProfile(*securityProfile, cfg.SecurityProfileDefault),
			AllowRootUser:     *allowRootUser,
			MaxAutoRisk:       strings.TrimSpace(*maxAutoRisk),
			AllowReboot:       *allowReboot,
			AllowDiskOps:      *allowDiskOps,
			DenyPatterns:      splitCSV(*denyPatternsStr),
			ToolPolicyVersion: 2,
		}
		if len(p.AuthPriority) == 0 {
			p.AuthPriority = []string{"key", "password"}
		}
		applySecurityProfileDefaults(&p)
		if err := store.Upsert(p); err != nil {
			fatal(err)
		}
		printJSON(map[string]any{"ok": true, "profile": p})
	case "list":
		items, err := store.List()
		if err != nil {
			fatal(err)
		}
		printJSON(items)
	case "show":
		fs := flag.NewFlagSet("profile show", flag.ExitOnError)
		id := fs.String("id", "", "profile id")
		_ = fs.Parse(args[1:])
		if *id == "" {
			fatal(fmt.Errorf("id is required"))
		}
		p, err := store.Get(*id)
		if err != nil {
			fatal(err)
		}
		if p == nil {
			fatal(fmt.Errorf("profile not found"))
		}
		printJSON(p)
	case "remove":
		fs := flag.NewFlagSet("profile remove", flag.ExitOnError)
		id := fs.String("id", "", "profile id")
		_ = fs.Parse(args[1:])
		if *id == "" {
			fatal(fmt.Errorf("id is required"))
		}
		if err := store.Delete(*id); err != nil {
			fatal(err)
		}
		printJSON(map[string]any{"ok": true, "deleted": *id})
	default:
		usage()
		os.Exit(1)
	}
}

func handleSecret(svc *app.Service, args []string) {
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}
	sec := svc.SecretStore()
	switch args[0] {
	case "set-password":
		fs := flag.NewFlagSet("secret set-password", flag.ExitOnError)
		profileID := fs.String("profile", "", "profile id")
		value := fs.String("value", "", "password value")
		_ = fs.Parse(args[1:])
		if *profileID == "" {
			fatal(fmt.Errorf("--profile is required"))
		}
		pwd := *value
		if pwd == "" {
			pwd = readLine("Password: ")
		}
		if err := sec.Set(*profileID, "password", pwd); err != nil {
			fatal(err)
		}
		printJSON(map[string]any{"ok": true})
	case "delete-password":
		fs := flag.NewFlagSet("secret delete-password", flag.ExitOnError)
		profileID := fs.String("profile", "", "profile id")
		_ = fs.Parse(args[1:])
		if *profileID == "" {
			fatal(fmt.Errorf("--profile is required"))
		}
		if err := sec.Delete(*profileID, "password"); err != nil {
			fatal(err)
		}
		printJSON(map[string]any{"ok": true})
	case "set-key-passphrase":
		fs := flag.NewFlagSet("secret set-key-passphrase", flag.ExitOnError)
		profileID := fs.String("profile", "", "profile id")
		value := fs.String("value", "", "key passphrase value")
		_ = fs.Parse(args[1:])
		if *profileID == "" {
			fatal(fmt.Errorf("--profile is required"))
		}
		passphrase := *value
		if passphrase == "" {
			passphrase = readLine("Key passphrase: ")
		}
		if err := sec.Set(*profileID, "key_passphrase", passphrase); err != nil {
			fatal(err)
		}
		printJSON(map[string]any{"ok": true})
	case "delete-key-passphrase":
		fs := flag.NewFlagSet("secret delete-key-passphrase", flag.ExitOnError)
		profileID := fs.String("profile", "", "profile id")
		_ = fs.Parse(args[1:])
		if *profileID == "" {
			fatal(fmt.Errorf("--profile is required"))
		}
		if err := sec.Delete(*profileID, "key_passphrase"); err != nil {
			fatal(err)
		}
		printJSON(map[string]any{"ok": true})
	case "set-sudo-password":
		fs := flag.NewFlagSet("secret set-sudo-password", flag.ExitOnError)
		profileID := fs.String("profile", "", "profile id")
		value := fs.String("value", "", "sudo password value")
		_ = fs.Parse(args[1:])
		if *profileID == "" {
			fatal(fmt.Errorf("--profile is required"))
		}
		pwd := *value
		if pwd == "" {
			pwd = readLine("Sudo password: ")
		}
		if err := sec.Set(*profileID, "sudo_password", pwd); err != nil {
			fatal(err)
		}
		printJSON(map[string]any{"ok": true})
	case "delete-sudo-password":
		fs := flag.NewFlagSet("secret delete-sudo-password", flag.ExitOnError)
		profileID := fs.String("profile", "", "profile id")
		_ = fs.Parse(args[1:])
		if *profileID == "" {
			fatal(fmt.Errorf("--profile is required"))
		}
		if err := sec.Delete(*profileID, "sudo_password"); err != nil {
			fatal(err)
		}
		printJSON(map[string]any{"ok": true})
	default:
		usage()
		os.Exit(1)
	}
}

func handleApprovals(svc *app.Service, args []string) {
	if len(args) == 0 || args[0] != "list" {
		usage()
		os.Exit(1)
	}
	fs := flag.NewFlagSet("approvals list", flag.ExitOnError)
	status := fs.String("status", "", "pending|approved|rejected")
	_ = fs.Parse(args[1:])
	items, err := svc.Approvals().List(*status)
	if err != nil {
		fatal(err)
	}
	printJSON(items)
}

func handleApproveReject(svc *app.Service, approve bool, args []string) {
	if len(args) == 0 {
		fatal(fmt.Errorf("approval id is required"))
	}
	id := args[0]
	fs := flag.NewFlagSet("approval", flag.ExitOnError)
	actor := fs.String("by", os.Getenv("USER"), "operator")
	reason := fs.String("reason", "", "reject reason")
	autoYes := fs.Bool("y", false, "skip confirmation prompt")
	_ = fs.Parse(args[1:])

	// Fetch and display the approval request context
	req, err := svc.Approvals().Get(id)
	if err != nil {
		fatal(err)
	}
	if req == nil {
		fatal(fmt.Errorf("approval id not found"))
	}

	fmt.Fprintf(os.Stderr, "\n--- Approval Request ---\n")
	fmt.Fprintf(os.Stderr, "  ID:         %s\n", req.ID)
	fmt.Fprintf(os.Stderr, "  Host:       %s\n", req.Host)
	fmt.Fprintf(os.Stderr, "  Username:   %s\n", req.Username)
	fmt.Fprintf(os.Stderr, "  Command:    %s\n", req.Command)
	fmt.Fprintf(os.Stderr, "  Risk Level: %s\n", req.RiskLevel)
	fmt.Fprintf(os.Stderr, "  Deny Class: %s\n", req.DenyClass)
	fmt.Fprintf(os.Stderr, "  Status:     %s\n", req.Status)
	fmt.Fprintf(os.Stderr, "  Created:    %s\n", req.CreatedAt.Format(time.RFC3339))
	fmt.Fprintf(os.Stderr, "------------------------\n\n")

	if !*autoYes {
		action := "Approve"
		if !approve {
			action = "Reject"
		}
		answer := readLine(fmt.Sprintf("%s? [y/N]: ", action))
		if !strings.EqualFold(answer, "y") && !strings.EqualFold(answer, "yes") {
			fmt.Fprintf(os.Stderr, "Cancelled.\n")
			os.Exit(0)
		}
	}

	status := model.ApprovalApproved
	if !approve {
		status = model.ApprovalRejected
	}
	updated, err := svc.Approvals().Resolve(id, status, *actor, *reason)
	if err != nil {
		fatal(err)
	}
	if updated == nil {
		fatal(fmt.Errorf("approval id not found"))
	}
	printJSON(updated)
}

func handleMigrate(svc *app.Service, cfg model.Config, args []string) {
	if len(args) == 0 || args[0] != "security" {
		usage()
		os.Exit(1)
	}
	items, err := svc.ProfileStore().List()
	if err != nil {
		fatal(err)
	}
	updated := 0
	warnings := make([]map[string]any, 0)
	for _, p := range items {
		changed := false
		if strings.TrimSpace(p.SecurityProfile) == "" {
			p.SecurityProfile = normalizeSecurityProfile("", cfg.SecurityProfileDefault)
			changed = true
		}
		if p.ToolPolicyVersion == 0 {
			p.ToolPolicyVersion = 2
			changed = true
		}
		if changed {
			if err := svc.ProfileStore().Upsert(p); err != nil {
				fatal(err)
			}
			updated++
		}
		if hasRootPath(p.WorkspaceRoots) {
			warnings = append(warnings, map[string]any{"profile_id": p.ID, "warning": "workspace_roots contains '/'"})
		}
		if p.AllowRootUser {
			warnings = append(warnings, map[string]any{"profile_id": p.ID, "warning": "allow_root_user=true"})
		}
		if p.AllowPublicHost {
			warnings = append(warnings, map[string]any{"profile_id": p.ID, "warning": "allow_public_host=true"})
		}
	}
	printJSON(map[string]any{
		"ok":               true,
		"profiles_total":   len(items),
		"profiles_updated": updated,
		"warnings":         warnings,
	})
}

// applySecurityProfileDefaults sets policy field defaults based on security_profile.
// ops_strict defaults to MaxAutoRisk="L1" (every L2 command requires approval).
func applySecurityProfileDefaults(p *model.Profile) {
	if strings.EqualFold(p.SecurityProfile, "ops_strict") && strings.TrimSpace(p.MaxAutoRisk) == "" {
		p.MaxAutoRisk = "L1"
	}
}

func normalizeSecurityProfile(v, fallback string) string {
	mode := strings.ToLower(strings.TrimSpace(v))
	if mode == "" {
		mode = strings.ToLower(strings.TrimSpace(fallback))
	}
	switch mode {
	case "", "easy_safe":
		return "easy_safe"
	case "ops_strict":
		return "ops_strict"
	default:
		return mode
	}
}

func hasRootPath(roots []string) bool {
	for _, r := range roots {
		if strings.TrimSpace(r) == "/" {
			return true
		}
	}
	return false
}

func splitCSV(s string) []string {
	items := strings.Split(strings.TrimSpace(s), ",")
	out := make([]string, 0, len(items))
	for _, it := range items {
		v := strings.TrimSpace(it)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	os.Stdout.Write(b)
	os.Stdout.Write([]byte("\n"))
}

func readLine(prompt string) string {
	fmt.Fprint(os.Stderr, prompt)
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	return strings.TrimSpace(line)
}

func fatal(err error) {
	printJSON(map[string]any{
		"ok":    false,
		"error": err.Error(),
		"at":    time.Now().UTC().Format(time.RFC3339),
	})
	os.Exit(1)
}
