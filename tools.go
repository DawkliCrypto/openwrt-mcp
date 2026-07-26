package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const defaultCmdTimeout = 30 * time.Second

// run executes argv directly -- never through a shell -- so there is no quoting or
// injection surface regardless of what the model puts in the arguments.
func run(ctx context.Context, timeout time.Duration, argv ...string) (string, error) {
	if timeout <= 0 {
		timeout = defaultCmdTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	out := stdout.String()
	if e := strings.TrimSpace(stderr.String()); e != "" {
		if out != "" {
			out += "\n"
		}
		out += e
	}
	if ctx.Err() == context.DeadlineExceeded {
		return out, fmt.Errorf("timed out after %s", timeout)
	}
	return out, err
}

func textResult(s string) *mcp.CallToolResult {
	if strings.TrimSpace(s) == "" {
		s = "(no output)"
	}
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

func errResult(s string) *mcp.CallToolResult {
	return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: s}}}
}

// ---------------------------------------------------------------- tool inputs

type ubusListIn struct {
	Filter string `json:"filter,omitempty" jsonschema:"optional ubus object path prefix, e.g. 'network' or 'gl-clients'. Omit to list every object on the bus."`
}

type ubusCallIn struct {
	Object string         `json:"object" jsonschema:"ubus object name, e.g. 'network.interface.lan' or 'iwinfo'"`
	Method string         `json:"method" jsonschema:"method to call on that object, e.g. 'status'"`
	Args   map[string]any `json:"args,omitempty" jsonschema:"JSON arguments for the method; omit for none"`
}

type UCIChange struct {
	Config  string `json:"config" jsonschema:"UCI config name, e.g. 'network'"`
	Section string `json:"section" jsonschema:"section name, e.g. 'lan' or '@wifi-iface[0]'"`
	Option  string `json:"option" jsonschema:"option name, e.g. 'ipaddr'"`
	Value   string `json:"value,omitempty" jsonschema:"new value; ignored when delete is true"`
	Delete  bool   `json:"delete,omitempty" jsonschema:"delete the option instead of setting it"`
}

type uciApplyIn struct {
	Changes []UCIChange `json:"changes" jsonschema:"the set of UCI options to change, applied together"`
	Timeout int         `json:"timeout,omitempty" jsonschema:"seconds before automatic rollback if uci_confirm is not called (default 90, max 600)"`
}

type uciConfirmIn struct {
	Token string `json:"token" jsonschema:"the confirm_token returned by uci_apply"`
}

type execIn struct {
	Argv    []string `json:"argv" jsonschema:"command and arguments, executed directly without a shell. argv[0] is the policy scope."`
	Timeout int      `json:"timeout,omitempty" jsonschema:"seconds before the command is killed (default 30, max 300)"`
}

type logreadIn struct {
	Lines   int    `json:"lines,omitempty" jsonschema:"how many recent lines to return (default 100, max 2000)"`
	Pattern string `json:"pattern,omitempty" jsonschema:"only return lines containing this substring"`
}

// ---------------------------------------------------------------- registration

// newServerForClient builds an MCP server whose handlers are closed over one authenticated
// client name. Identity therefore comes from the validated bearer token at connection time
// and can never be spoofed by a tool argument or a self-asserted clientInfo.name.
func (s *Server) newServerForClient(client string) *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "openwrt-mcp", Version: version}, nil)

	addTool(s, srv, client, "ubus_list",
		"List ubus objects and their methods with argument signatures. This is the discovery tool: "+
			"call it first to learn what this router can actually do, rather than assuming a fixed catalogue. "+
			"Always permitted (introspection only, returns no configuration data).",
		func(in ubusListIn) []string { return nil },
		func(ctx context.Context, in ubusListIn) (string, string, error) {
			argv := []string{"ubus", "-v", "list"}
			if in.Filter != "" {
				argv = append(argv, in.Filter)
			}
			out, err := run(ctx, defaultCmdTimeout, argv...)
			return out, "listed ubus objects", err
		})

	addTool(s, srv, client, "ubus_call",
		"Call any ubus method on the router. This is the main tool -- netifd, wireless, dnsmasq, "+
			"iwinfo, luci-rpc and the vendor's gl-* objects are all reachable through it. "+
			"Policy scope is the string \"<object>.<method>\".",
		func(in ubusCallIn) []string { return []string{in.Object + "." + in.Method} },
		func(ctx context.Context, in ubusCallIn) (string, string, error) {
			if in.Object == "" || in.Method == "" {
				return "", "", fmt.Errorf("object and method are required")
			}
			argv := []string{"ubus", "call", in.Object, in.Method}
			if len(in.Args) > 0 {
				b, err := json.Marshal(in.Args)
				if err != nil {
					return "", "", fmt.Errorf("args not encodable: %w", err)
				}
				argv = append(argv, string(b))
			}
			out, err := run(ctx, defaultCmdTimeout, argv...)
			return out, in.Object + "." + in.Method, err
		})

	addTool(s, srv, client, "uci_apply",
		"Change router configuration safely. Stages the given UCI options, commits them, and applies "+
			"with rpcd's rollback timer armed: if uci_confirm is not called before the timeout, the router "+
			"automatically reverts everything. Use this rather than 'uci' via exec -- it is the only path "+
			"that cannot strand you with an unreachable router. "+
			"Policy scope is \"<config>.<section>.<option>\" for each change, and all must be covered.",
		func(in uciApplyIn) []string {
			var out []string
			for _, c := range in.Changes {
				out = append(out, fmt.Sprintf("%s.%s.%s", c.Config, c.Section, c.Option))
			}
			return out
		},
		func(ctx context.Context, in uciApplyIn) (string, string, error) {
			return s.uciApply(ctx, in)
		})

	addTool(s, srv, client, "uci_confirm",
		"Confirm a pending uci_apply and cancel its rollback timer. Call this only after verifying the "+
			"router is still reachable and behaving. Doing nothing is the safe default: the change reverts.",
		func(in uciConfirmIn) []string { return nil },
		func(ctx context.Context, in uciConfirmIn) (string, string, error) {
			return s.uciConfirm(ctx, in.Token)
		})

	addTool(s, srv, client, "exec",
		"Run a command on the router. argv is executed directly with no shell, so pipes, redirection and "+
			"globs do not work -- pass a single program and its arguments. Policy scope is argv[0].",
		func(in execIn) []string {
			if len(in.Argv) == 0 {
				return nil
			}
			return []string{in.Argv[0]}
		},
		func(ctx context.Context, in execIn) (string, string, error) {
			if len(in.Argv) == 0 {
				return "", "", fmt.Errorf("argv must not be empty")
			}
			out, err := run(ctx, clampSec(in.Timeout, 30, 300), in.Argv...)
			return out, strings.Join(in.Argv, " "), err
		})

	addTool(s, srv, client, "logread",
		"Read the router's system log. Separate from exec so a policy can grant log access without "+
			"granting a root shell.",
		func(in logreadIn) []string { return nil },
		func(ctx context.Context, in logreadIn) (string, string, error) {
			n := in.Lines
			if n <= 0 {
				n = 100
			}
			if n > 2000 {
				n = 2000
			}
			out, err := run(ctx, defaultCmdTimeout, "logread", "-l", fmt.Sprint(n))
			if err == nil && in.Pattern != "" {
				var keep []string
				for _, line := range strings.Split(out, "\n") {
					if strings.Contains(line, in.Pattern) {
						keep = append(keep, line)
					}
				}
				out = strings.Join(keep, "\n")
			}
			return out, fmt.Sprintf("%d lines", n), err
		})

	return srv
}

func clampSec(v, def, max int) time.Duration {
	if v <= 0 {
		v = def
	}
	if v > max {
		v = max
	}
	return time.Duration(v) * time.Second
}

// addTool registers one tool behind the shared policy+audit gate.
//
// scopeOf derives the policy scope strings from the typed input; fn does the work and
// returns (output, summary, error). Neither can bypass the gate: authorisation happens
// in this wrapper, before fn is ever called.
func addTool[In any](s *Server, srv *mcp.Server, client, name, desc string,
	scopeOf func(In) []string,
	fn func(context.Context, In) (string, string, error),
) {
	mcp.AddTool(srv, &mcp.Tool{Name: name, Description: desc},
		func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, any, error) {
			started := time.Now()
			scopes := scopeOf(in)
			ev := AuditEvent{Time: nowISO(), Client: client, Tool: name, Scope: strings.Join(scopes, " ")}
			if b, err := json.Marshal(in); err == nil {
				var m any
				if json.Unmarshal(b, &m) == nil {
					ev.Args = m
				}
			}
			finish := func(res *mcp.CallToolResult, outcome Outcome, summary, errMsg string) (*mcp.CallToolResult, any, error) {
				ev.Outcome, ev.Summary, ev.Error = outcome, summary, errMsg
				ev.Duration = time.Since(started).Milliseconds()
				s.audit.Record(ev)
				return res, nil, nil
			}

			// ubus_list is introspection only and is never gated; everything else must be
			// covered by a standing policy. Denial is the default.
			if name != "ubus_list" {
				if ok, reason := s.cfg().Authorise(client, name, scopes, time.Now()); !ok {
					return finish(errResult(reason), OutcomeDenied, "", reason)
				}
			}

			out, summary, err := fn(ctx, in)
			if err != nil {
				msg := err.Error()
				if out != "" {
					msg += "\n" + out
				}
				return finish(errResult(msg), OutcomeError, summary, err.Error())
			}
			return finish(textResult(out), OutcomeOK, summary, "")
		})
}
