package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"cssh/internal/model"
)

type Logger struct {
	logsDir string
	mu      sync.Mutex
}

func NewLogger(logsDir string) *Logger {
	return &Logger{logsDir: logsDir}
}

func (l *Logger) Write(ev model.AuditEvent) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := os.MkdirAll(l.logsDir, 0o700); err != nil {
		return err
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	filename := "audit-" + ev.Timestamp.UTC().Format("20060102") + ".jsonl"
	path := filepath.Join(l.logsDir, filename)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(ev)
}
