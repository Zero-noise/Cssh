package errorsx

import "fmt"

type CsshError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *CsshError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func New(code, message string) error {
	return &CsshError{Code: code, Message: message}
}

const (
	CodeInvalidParams       = "INVALID_PARAMS"
	CodeAuthFailed          = "AUTH_FAILED"
	CodePathForbidden       = "PATH_FORBIDDEN"
	CodeApprovalRequired    = "APPROVAL_REQUIRED"
	CodeApprovalRejected    = "APPROVAL_REJECTED"
	CodeConnectionMissing   = "CONNECTION_NOT_FOUND"
	CodeSessionMissing      = "SESSION_NOT_FOUND"
	CodeExecTimeout         = "EXEC_TIMEOUT"
	CodeFileExists          = "FILE_EXISTS"
	CodeChecksumMismatch    = "CHECKSUM_MISMATCH"
	CodeChecksumUnavailable = "CHECKSUM_UNAVAILABLE"
	CodeProfileConflict     = "PROFILE_CONFLICT"
	CodeConnectionDead      = "CONNECTION_DEAD"
	CodeInternal            = "INTERNAL"
)
