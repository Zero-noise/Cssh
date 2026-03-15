package model

import "time"

type AuthMode string

const (
	AuthModeKey      AuthMode = "key"
	AuthModePassword AuthMode = "password"
)

type Profile struct {
	ID                string   `json:"id"`
	Name              string   `json:"name,omitempty"`
	NotePath          string   `json:"note_path,omitempty"`
	Host              string   `json:"host"`
	Port              int      `json:"port"`
	Username          string   `json:"username"`
	AuthPriority      []string `json:"auth_priority"`
	KeyPath           string   `json:"key_path,omitempty"`
	WorkspaceRoots    []string `json:"workspace_roots"`
	AllowPublicHost   bool     `json:"allow_public_host"`
	SecurityProfile   string   `json:"security_profile,omitempty"`
	AllowRootUser     bool     `json:"allow_root_user,omitempty"`
	ToolPolicyVersion int      `json:"tool_policy_version,omitempty"`
	MaxAutoRisk       string   `json:"max_auto_risk,omitempty"`
	AllowReboot       bool     `json:"allow_reboot,omitempty"`
	AllowDiskOps      bool     `json:"allow_disk_ops,omitempty"`
	DenyPatterns      []string `json:"deny_patterns,omitempty"`
	GrantTTLSec       int      `json:"grant_ttl_sec,omitempty"` // 0 = session-scoped (default), >0 = TTL in seconds
}

type Config struct {
	DefaultShell           string `json:"default_shell"`
	DefaultTimeoutSec      int    `json:"default_timeout_sec"`
	AllowPublicHost        bool   `json:"allow_public_host"`
	RuntimeDir             string `json:"runtime_dir"`
	LogsDir                string `json:"logs_dir"`
	ProfilesFile           string `json:"profiles_file"`
	SecurityProfileDefault string `json:"security_profile_default"`
	ConnectRequireProfile  bool   `json:"connect_require_profile"`
	SudoEnabled            bool   `json:"sudo_enabled"`
	AllowRootLogin         bool   `json:"allow_root_login"`
}

type ConnectionInput struct {
	ProfileID       string   `json:"profile_id,omitempty"`
	ProfileName     string   `json:"profile_name,omitempty"`
	Host            string   `json:"host,omitempty"`
	Port            int      `json:"port,omitempty"`
	Username        string   `json:"username,omitempty"`
	AuthMode        string   `json:"auth_mode,omitempty"`
	KeyRef          string   `json:"key_ref,omitempty"`
	PasswordRef     string   `json:"password_ref,omitempty"`
	WorkspaceRoots  []string `json:"workspace_roots,omitempty"`
	LimitDir        string   `json:"limit_dir,omitempty"`
	AllowPublicHost *bool    `json:"allow_public_host,omitempty"`
}

type Connection struct {
	ID              string
	ProfileID       string
	Host            string
	Port            int
	Username        string
	AuthPriority    []string
	KeyPath         string
	KeyPassphrase   string
	Password        string
	SudoPassword    string
	WorkspaceRoots  []string
	LimitDir        string
	AllowPublicHost bool
	SecurityProfile string
	AllowRootUser   bool
	MaxAutoRisk     string
	AllowReboot     bool
	AllowDiskOps    bool
	DenyPatterns    []string
	GrantTTLSec     int
	CnotePath       string
	Cnote           string
	ControlPath     string
	AuthMethod      string
	Generation      uint64
	CreatedAt       time.Time
}

type Session struct {
	ID           string
	ConnectionID string
	CWD          string
	Shell        string
	CreatedAt    time.Time
}

type RiskLevel string

const (
	RiskL0 RiskLevel = "L0"
	RiskL1 RiskLevel = "L1"
	RiskL2 RiskLevel = "L2"
)

type DenyClass string

const (
	DenyAlways      DenyClass = "deny_always"
	DenyNeedApprove DenyClass = "deny_need_approve"
	DenyNone        DenyClass = "deny_none"
)

type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalRejected ApprovalStatus = "rejected"
)

type ApprovalRequest struct {
	ID           string         `json:"id"`
	CreatedAt    time.Time      `json:"created_at"`
	ResolvedAt   *time.Time     `json:"resolved_at,omitempty"`
	Status       ApprovalStatus `json:"status"`
	Command      string         `json:"command"`
	ConnectionID string         `json:"connection_id"`
	SessionID    string         `json:"session_id,omitempty"`
	Host         string         `json:"host,omitempty"`
	Username     string         `json:"username,omitempty"`
	RiskLevel    RiskLevel      `json:"risk_level"`
	DenyClass    DenyClass      `json:"deny_class,omitempty"`
	Capability   string         `json:"capability,omitempty"`
	CommandTpl   string         `json:"command_template,omitempty"`
	CommandHash  string         `json:"command_template_hash,omitempty"`
	Reason       string         `json:"reason"`
	RequestedBy  string         `json:"requested_by"`
	ApprovedBy   string         `json:"approved_by,omitempty"`
	RejectReason string         `json:"reject_reason,omitempty"`
	UsedAt       *time.Time     `json:"used_at,omitempty"`
	Reusable     bool           `json:"reusable,omitempty"`
	Generation   uint64         `json:"generation,omitempty"`
}

type PrivilegeGrantStatus string

const (
	PrivilegeGrantActive  PrivilegeGrantStatus = "active"
	PrivilegeGrantRevoked PrivilegeGrantStatus = "revoked"
	PrivilegeGrantExpired PrivilegeGrantStatus = "expired"
)

type PrivilegeGrant struct {
	ID           string               `json:"id"`
	CreatedAt    time.Time            `json:"created_at"`
	ExpiresAt    time.Time            `json:"expires_at"`
	RevokedAt    *time.Time           `json:"revoked_at,omitempty"`
	Status       PrivilegeGrantStatus `json:"status"`
	ConnectionID string               `json:"connection_id"`
	Capability   string               `json:"capability"`
	CommandHash  string               `json:"command_template_hash"`
	RiskLevel    RiskLevel            `json:"risk_level"`
	ApprovedBy   string               `json:"approved_by,omitempty"`
	Source       string               `json:"source,omitempty"`
}

type AuditEvent struct {
	Timestamp       time.Time `json:"timestamp"`
	TraceID         string    `json:"trace_id"`
	Type            string    `json:"type"`
	ConnectionID    string    `json:"connection_id,omitempty"`
	SessionID       string    `json:"session_id,omitempty"`
	Host            string    `json:"host,omitempty"`
	Command         string    `json:"command,omitempty"`
	RiskLevel       string    `json:"risk_level,omitempty"`
	ApprovalID      string    `json:"approval_id,omitempty"`
	ApprovedBy      string    `json:"approved_by,omitempty"`
	Status          string    `json:"status,omitempty"`
	ExitCode        int       `json:"exit_code,omitempty"`
	DurationMS      int64     `json:"duration_ms,omitempty"`
	FilePath        string    `json:"file_path,omitempty"`
	Detail          string    `json:"detail,omitempty"`
	SecurityProfile string    `json:"security_profile,omitempty"`
	Capability      string    `json:"capability,omitempty"`
	CommandHash     string    `json:"command_template_hash,omitempty"`
	GrantID         string    `json:"grant_id,omitempty"`
	ConfirmMode     string    `json:"confirm_mode,omitempty"`
}
