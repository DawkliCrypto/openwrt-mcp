package main

import (
	"encoding/json"
	"os"
	"path"
	"strings"
	"sync"
	"time"
)

// Redaction is owned by the recorder, never by callers, so a new tool cannot
// accidentally leak a plaintext secret into the log by forgetting to scrub it.
//
// Note the deliberate omission of a bare "key": keyId / publicKey / pubkey are safe
// identifiers and redacting them would make the log useless for debugging. The
// router-specific additions over Haven's list are psk, wgkey and private_key.
var secretKeySubstrings = []string{
	"password", "passwd", "secret", "token", "credential",
	"apikey", "api_key", "privatekey", "private_key", "passphrase",
	"psk", "wgkey", "encryption_key",
}

const redacted = "<redacted>"

func redact(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if isSecretKey(k) {
				out[k] = redacted
			} else {
				out[k] = redact(val)
			}
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = redact(val)
		}
		return out
	default:
		return v
	}
}

func isSecretKey(k string) bool {
	lk := strings.ToLower(k)
	for _, s := range secretKeySubstrings {
		if strings.Contains(lk, s) {
			return true
		}
	}
	return false
}

type Outcome string

const (
	OutcomeOK     Outcome = "OK"
	OutcomeDenied Outcome = "DENIED" // first-class: "we said no" is not the same as "it broke"
	OutcomeError  Outcome = "ERROR"
)

type AuditEvent struct {
	Time     string  `json:"time"`
	Client   string  `json:"client"`
	Tool     string  `json:"tool,omitempty"`
	Scope    string  `json:"scope,omitempty"`
	Args     any     `json:"args,omitempty"`
	Outcome  Outcome `json:"outcome"`
	Summary  string  `json:"summary,omitempty"`
	Error    string  `json:"error,omitempty"`
	Duration int64   `json:"duration_ms"`
}

type Auditor struct {
	mu    sync.Mutex
	path  string
	maxMB int
}

func NewAuditor(p string, maxMB int) *Auditor { return &Auditor{path: p, maxMB: maxMB} }

// Record never returns an error and never blocks the request path on failure:
// auditing must not be able to break the thing it is auditing.
func (a *Auditor) Record(e AuditEvent) {
	if e.Args != nil {
		e.Args = redact(e.Args)
	}
	e.Summary = truncate(e.Summary, 240)
	e.Error = truncate(e.Error, 240)
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := os.MkdirAll(path.Dir(a.path), 0o700); err != nil {
		return
	}
	a.rotateLocked()
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}

func (a *Auditor) rotateLocked() {
	st, err := os.Stat(a.path)
	if err != nil || st.Size() < int64(a.maxMB)*1024*1024 {
		return
	}
	_ = os.Rename(a.path, a.path+".1") // one generation is enough; eMMC is 64GB but logs are not the point
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func nowISO() string { return time.Now().UTC().Format(time.RFC3339) }
