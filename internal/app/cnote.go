package app

import (
	"strings"
	"time"

	"cssh/internal/errorsx"
	"cssh/internal/model"
	"cssh/internal/util"
)

func (s *Service) Cnote(action, profileID, profileName, content string) (map[string]any, error) {
	traceID := util.NewID("trace")
	writeAudit := func(status, detail string) {
		_ = s.audit.Write(model.AuditEvent{
			Timestamp: time.Now().UTC(),
			TraceID:   traceID,
			Type:      "ssh_cnote",
			Status:    status,
			Detail:    detail,
		})
	}

	act := strings.ToLower(strings.TrimSpace(action))
	if act == "" {
		act = "get"
	}
	switch act {
	case "get", "set", "append", "clear":
	default:
		err := errorsx.New(errorsx.CodeInvalidParams, "action must be one of: get, set, append, clear")
		writeAudit("error", err.Error())
		return nil, err
	}

	profile, err := s.resolveProfileRef(profileID, profileName)
	if err != nil {
		writeAudit("error", err.Error())
		return nil, err
	}
	if err := s.persistProfileCnotePath(profile); err != nil {
		writeAudit("error", err.Error())
		return nil, err
	}

	path := s.ensureProfileCnotePath(profile)
	var note string
	switch act {
	case "get":
		note, err = s.cnotes.Read(path)
	case "set":
		note = strings.TrimSpace(content)
		err = s.cnotes.Set(path, noteWithTrailingNewline(note))
	case "append":
		if strings.TrimSpace(content) == "" {
			err = errorsx.New(errorsx.CodeInvalidParams, "content is required for action=append")
			break
		}
		note, err = s.cnotes.Append(path, content)
	case "clear":
		note = ""
		err = s.cnotes.Set(path, "")
	}
	if err != nil {
		writeAudit("error", err.Error())
		return nil, err
	}
	if act == "get" {
		note = strings.TrimRight(note, "\n")
	}
	if act == "append" {
		note = strings.TrimRight(note, "\n")
	}

	resp := map[string]any{
		"profile_id":    profile.ID,
		"profile_name":  profile.Name,
		"cnote_path":    path,
		"cnote":         note,
		"cnote_present": strings.TrimSpace(note) != "",
	}
	switch act {
	case "set":
		resp["recorded"] = note
		resp["updated"] = true
	case "append":
		resp["recorded"] = strings.TrimSpace(content)
		resp["updated"] = true
	case "clear":
		resp["updated"] = true
	}

	writeAudit("ok", "action="+act+" profile_id="+profile.ID)
	return resp, nil
}

func noteWithTrailingNewline(content string) string {
	if content == "" {
		return ""
	}
	return content + "\n"
}
