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
		handleProfile(svc, os.Args[2:])
	case "secret":
		handleSecret(svc, os.Args[2:])
	case "approvals":
		handleApprovals(svc, os.Args[2:])
	case "approve":
		handleApproveReject(svc, true, os.Args[2:])
	case "reject":
		handleApproveReject(svc, false, os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`csshctl commands:
  profile add --id ID --name NAME --host HOST --user USER [--port 22] [--workspace-roots /a,/b] [--auth-priority key,password] [--key-path PATH] [--allow-public=false]
  profile list
  profile show --id ID
  profile remove --id ID

  secret set-password --profile ID [--value VALUE]
  secret delete-password --profile ID
  secret set-key-passphrase --profile ID [--value VALUE]
  secret delete-key-passphrase --profile ID

  approvals list [--status pending|approved|rejected]
  approve APPROVAL_ID [--by NAME]
  reject APPROVAL_ID [--by NAME] [--reason TEXT]
`)
}

func handleProfile(svc *app.Service, args []string) {
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
		_ = fs.Parse(args[1:])
		if *id == "" || *host == "" || *user == "" {
			fatal(fmt.Errorf("id, host, user are required"))
		}
		roots := splitCSV(*workspaceRoots)
		if len(roots) == 0 {
			roots = []string{"/"}
		}
		p := model.Profile{
			ID:              *id,
			Name:            strings.TrimSpace(*name),
			Host:            *host,
			Port:            *port,
			Username:        *user,
			AuthPriority:    splitCSV(*authPriority),
			KeyPath:         config.ExpandHome(*keyPath),
			WorkspaceRoots:  roots,
			AllowPublicHost: *allowPublic,
		}
		if len(p.AuthPriority) == 0 {
			p.AuthPriority = []string{"key", "password"}
		}
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
	_ = fs.Parse(args[1:])

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
