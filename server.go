package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type Server struct {
	configPath string
	statePath  string
	audit      *Auditor
	tokens     *TokenStore

	mu      sync.RWMutex
	config  *Config
	cfgTime time.Time
	servers map[string]*mcp.Server // per authenticated client name
	pending map[string]*pendingApply
}

// cfg returns the current policy set, re-reading the config file when it has changed on
// disk so that `openwrt-mcp allow` and hand edits take effect without a restart. A file
// that fails to parse is ignored and the previous good config is kept -- a syntax error
// must not silently drop every policy (which would fail closed and look like a bug) nor
// leave a half-parsed one in place.
func (s *Server) cfg() *Config {
	if st, err := os.Stat(s.configPath); err == nil {
		s.mu.RLock()
		stale := !st.ModTime().Equal(s.cfgTime)
		s.mu.RUnlock()
		if stale {
			if fresh, err := LoadConfig(s.configPath); err == nil {
				s.mu.Lock()
				s.config, s.cfgTime = fresh, st.ModTime()
				s.mu.Unlock()
				log.Printf("openwrt-mcp: reloaded config (%d policies)", len(fresh.Policies))
			} else {
				s.mu.Lock()
				s.cfgTime = st.ModTime() // don't retry the same broken file every call
				s.mu.Unlock()
				log.Printf("openwrt-mcp: config reload failed, keeping previous policies: %v", err)
			}
		}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.config
}

func NewServer(configPath, statePath string) (*Server, error) {
	cfg, err := LoadConfig(configPath)
	if err != nil {
		return nil, err
	}
	tokens, err := LoadTokens(path.Join(statePath, "tokens"))
	if err != nil {
		return nil, err
	}
	s := &Server{
		configPath: configPath,
		statePath:  statePath,
		config:     cfg,
		tokens:     tokens,
		audit:      NewAuditor(cfg.AuditPath, cfg.AuditMaxMB),
		servers:    map[string]*mcp.Server{},
		pending:    map[string]*pendingApply{},
	}
	s.recoverPending()
	return s, nil
}

// ---------------------------------------------------------------- http

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/mcp", s.authenticate(mcp.NewStreamableHTTPHandler(s.getServer, nil)))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		// AGPL-3.0 §13: this is a network service, so it offers its own source.
		fmt.Fprintf(w, "openwrt-mcp %s ok\nsource: %s\n", version, sourceURL)
	})
	return mux
}

// authenticate enforces the bearer token on every request. There is deliberately no
// loopback auto-trust: any process on the router can reach 127.0.0.1, and an `ssh -R`
// can make remote traffic arrive there too, so reachability is never treated as proof
// of identity. Origin is recorded for audit attribution only.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Browser defence: a page in a local browser must not be able to drive the router.
		if o := r.Header.Get("Origin"); o != "" && !isLoopbackOrigin(o) {
			http.Error(w, "forbidden origin", http.StatusForbidden)
			return
		}
		raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		client, ok := s.tokens.Resolve(strings.TrimSpace(raw))
		if !ok {
			s.audit.Record(AuditEvent{
				Time: nowISO(), Client: "<unauthenticated>", Outcome: OutcomeDenied,
				Error: "bad or missing bearer token from " + r.RemoteAddr,
			})
			w.Header().Set("WWW-Authenticate", `Bearer realm="openwrt-mcp"`)
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = client
		next.ServeHTTP(w, r)
	})
}

func (s *Server) getServer(r *http.Request) *mcp.Server {
	raw := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	client, ok := s.tokens.Resolve(raw)
	if !ok {
		return nil // unreachable: authenticate() already rejected it
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if srv, ok := s.servers[client]; ok {
		return srv
	}
	srv := s.newServerForClient(client)
	s.servers[client] = srv
	return srv
}

func isLoopbackOrigin(o string) bool {
	o = strings.TrimPrefix(strings.TrimPrefix(o, "https://"), "http://")
	if h, _, err := net.SplitHostPort(o); err == nil {
		o = h
	}
	return o == "localhost" || net.ParseIP(o).IsLoopback()
}

func (s *Server) Serve() error {
	cfg := s.cfg()
	// Refuse to bind anything but loopback. This is a deliberate hard stop rather than a
	// default: reaching the router is SSH's job, and a mis-edited config must not silently
	// expose a root-equivalent RPC surface to the LAN.
	host, _, err := net.SplitHostPort(cfg.Listen)
	if err != nil {
		return fmt.Errorf("bad listen address %q: %w", cfg.Listen, err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("listen address %q is not loopback; openwrt-mcp refuses to bind a routable address (reach it with: ssh -L %s:%s root@router)", cfg.Listen, cfg.Listen, cfg.Listen)
	}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	log.Printf("openwrt-mcp %s listening on %s (%d policies, %d paired clients)",
		version, cfg.Listen, len(cfg.Policies), len(s.tokens.Clients()))
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		MaxHeaderBytes:    64 << 10,
	}
	return srv.Serve(ln)
}

// ---------------------------------------------------------------- uci apply/rollback
//
// rpcd's own apply/rollback (ubus call uci apply {"rollback":true}) is the obvious thing
// to use and was the first choice, but it is unreachable here: every uci write method
// requires a ubus_rpc_session, and session.login needs a username+password. Using it would
// mean storing the router's root password in a file on the router -- a worse hole than the
// one the rollback closes. Verified on OpenWrt 21.02 / rpcd 2022-02-19:
//   ubus call uci apply '{}'                          -> Invalid argument  (no session)
//   ubus call uci apply '{"ubus_rpc_session":"0..0"}' -> No response       (null session lacks write ACL)
//
// So we snapshot /etc/config ourselves, arm a timer, and restore unless confirmed. The
// pending record is written to disk so that a daemon restart mid-window still rolls back:
// on startup an unconfirmed apply is always reverted, because "we lost track of it" is
// exactly when you want the conservative answer.

type pendingApply struct {
	Token    string    `json:"token"`
	Snapshot string    `json:"snapshot"`
	Deadline time.Time `json:"deadline"`
	Configs  []string  `json:"configs"`

	timer *time.Timer
}

func (s *Server) pendingPath() string { return path.Join(s.statePath, "pending.json") }

func (s *Server) uciApply(ctx context.Context, in uciApplyIn) (string, string, error) {
	if len(in.Changes) == 0 {
		return "", "", fmt.Errorf("changes must not be empty")
	}
	timeout := clampSec(in.Timeout, 90, 600)

	s.mu.Lock()
	busy := len(s.pending) > 0
	s.mu.Unlock()
	if busy {
		return "", "", fmt.Errorf("an apply is already pending confirmation; call uci_confirm or wait for it to roll back")
	}

	// Refuse to start on top of somebody else's uncommitted edits -- committing those
	// as a side effect would apply changes nobody asked us for.
	if out, err := run(ctx, defaultCmdTimeout, "uci", "changes"); err == nil && strings.TrimSpace(out) != "" {
		return "", "", fmt.Errorf("refusing to apply: uncommitted UCI changes already exist:\n%s", out)
	}

	// Work out which configs are affected before snapshotting: the snapshot covers only
	// those files, never the whole of /etc/config. A whole-tree restore would silently
	// clobber an unrelated change made by another process during the confirmation window.
	configs := map[string]bool{}
	for _, c := range in.Changes {
		if c.Config == "" || c.Section == "" || c.Option == "" {
			return "", "", fmt.Errorf("each change needs config, section and option")
		}
		if strings.ContainsAny(c.Config, "/.") {
			return "", "", fmt.Errorf("bad config name %q", c.Config)
		}
		configs[c.Config] = true
	}
	var names []string
	for c := range configs {
		if _, err := os.Stat("/etc/config/" + c); err != nil {
			return "", "", fmt.Errorf("no such UCI config %q", c)
		}
		names = append(names, c)
	}
	sort.Strings(names)

	token := randToken()
	snapshot := path.Join(os.TempDir(), "openwrt-mcp-rollback-"+token+".tar.gz")
	if out, err := run(ctx, defaultCmdTimeout,
		append([]string{"tar", "-czf", snapshot, "-C", "/etc/config"}, names...)...); err != nil {
		return "", "", fmt.Errorf("snapshot failed: %w\n%s", err, out)
	}

	for _, c := range in.Changes {
		key := fmt.Sprintf("%s.%s.%s", c.Config, c.Section, c.Option)
		var argv []string
		if c.Delete {
			argv = []string{"uci", "delete", key}
		} else {
			argv = []string{"uci", "set", key + "=" + c.Value}
		}
		if out, err := run(ctx, defaultCmdTimeout, argv...); err != nil {
			_, _ = run(ctx, defaultCmdTimeout, "uci", "revert", c.Config)
			_ = os.Remove(snapshot)
			return "", "", fmt.Errorf("staging %s failed: %w\n%s", key, err, out)
		}
	}

	for _, c := range names {
		if out, err := run(ctx, defaultCmdTimeout, "uci", "commit", c); err != nil {
			s.restoreSnapshot(ctx, snapshot, names)
			return "", "", fmt.Errorf("commit %s failed: %w\n%s", c, err, out)
		}
	}
	reloadOut, _ := run(ctx, defaultCmdTimeout, "ubus", "call", "uci", "reload_config", "{}")

	p := &pendingApply{Token: token, Snapshot: snapshot, Deadline: time.Now().Add(timeout), Configs: names}
	s.mu.Lock()
	p.timer = time.AfterFunc(timeout, func() { s.rollback(token, "timeout") })
	s.pending[token] = p
	s.mu.Unlock()
	s.savePending()

	return fmt.Sprintf(
		"Applied %d change(s) to %s and reloaded.\n\n"+
			"ROLLBACK ARMED: this reverts automatically at %s (in %s) unless you call\n"+
			"  uci_confirm {\"token\": \"%s\"}\n\n"+
			"Verify the router is still reachable and behaving BEFORE confirming.\n%s",
		len(in.Changes), strings.Join(names, ", "),
		p.Deadline.Format(time.RFC3339), timeout, token, reloadOut,
	), fmt.Sprintf("applied %d change(s), rollback armed %s", len(in.Changes), timeout), nil
}

func (s *Server) uciConfirm(ctx context.Context, token string) (string, string, error) {
	s.mu.Lock()
	p, ok := s.pending[token]
	if ok {
		if p.timer != nil {
			p.timer.Stop()
		}
		delete(s.pending, token)
	}
	s.mu.Unlock()
	if !ok {
		return "", "", fmt.Errorf("no pending apply with token %q (it may have already rolled back)", token)
	}
	_ = os.Remove(p.Snapshot)
	s.savePending()
	return fmt.Sprintf("Confirmed. Rollback cancelled; changes to %s are permanent.", strings.Join(p.Configs, ", ")),
		"confirmed " + token, nil
}

func (s *Server) rollback(token, reason string) {
	s.mu.Lock()
	p, ok := s.pending[token]
	delete(s.pending, token)
	s.mu.Unlock()
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	err := s.restoreSnapshot(ctx, p.Snapshot, p.Configs)
	s.savePending()
	outcome, msg := OutcomeOK, fmt.Sprintf("rolled back %s (%s)", strings.Join(p.Configs, ", "), reason)
	if err != nil {
		outcome, msg = OutcomeError, "ROLLBACK FAILED: "+err.Error()
	}
	log.Printf("openwrt-mcp: %s", msg)
	s.audit.Record(AuditEvent{Time: nowISO(), Client: "<system>", Tool: "uci_rollback", Outcome: outcome, Summary: msg})
}

func (s *Server) restoreSnapshot(ctx context.Context, snapshot string, configs []string) error {
	if _, err := os.Stat(snapshot); err != nil {
		return fmt.Errorf("snapshot %s missing: %w", snapshot, err)
	}
	if out, err := run(ctx, defaultCmdTimeout, "tar", "-xzf", snapshot, "-C", "/etc/config"); err != nil {
		return fmt.Errorf("restore failed: %w\n%s", err, out)
	}
	for _, c := range configs {
		_, _ = run(ctx, defaultCmdTimeout, "uci", "revert", c)
	}
	if out, err := run(ctx, defaultCmdTimeout, "ubus", "call", "uci", "reload_config", "{}"); err != nil {
		return fmt.Errorf("reload after restore failed: %w\n%s", err, out)
	}
	_ = os.Remove(snapshot)
	return nil
}

func (s *Server) savePending() {
	s.mu.RLock()
	list := make([]*pendingApply, 0, len(s.pending))
	for _, p := range s.pending {
		list = append(list, p)
	}
	s.mu.RUnlock()
	b, err := json.Marshal(list)
	if err != nil {
		return
	}
	_ = os.MkdirAll(s.statePath, 0o700)
	_ = os.WriteFile(s.pendingPath(), b, 0o600)
}

// recoverPending rolls back any apply that was still unconfirmed when we stopped.
// A restart during the confirmation window means nobody ever vouched for the change.
func (s *Server) recoverPending() {
	b, err := os.ReadFile(s.pendingPath())
	if err != nil {
		return
	}
	var list []*pendingApply
	if json.Unmarshal(b, &list) != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	for _, p := range list {
		log.Printf("openwrt-mcp: unconfirmed apply %s found at startup, rolling back", p.Token)
		if err := s.restoreSnapshot(ctx, p.Snapshot, p.Configs); err != nil {
			log.Printf("openwrt-mcp: recovery rollback failed: %v", err)
		}
	}
	_ = os.Remove(s.pendingPath())
}
