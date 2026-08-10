package main

import (
	"strings"
	"testing"
	"time"
)

func TestUciArgv(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   UCIChange
		want string
	}{
		{"set an option",
			UCIChange{Config: "dhcp", Section: "pi", Option: "ip", Value: "192.168.0.141"},
			"uci set dhcp.pi.ip=192.168.0.141"},
		{"create a section",
			UCIChange{Config: "dhcp", Section: "pi", Type: "host"},
			"uci set dhcp.pi=host"},
		{"delete an option",
			UCIChange{Config: "dhcp", Section: "pi", Option: "ip", Delete: true},
			"uci delete dhcp.pi.ip"},
		{"delete a whole section",
			UCIChange{Config: "dhcp", Section: "pi", Delete: true},
			"uci delete dhcp.pi"},
		{"anonymous section syntax survives untouched",
			UCIChange{Config: "dhcp", Section: "@host[2]", Option: "mac", Value: "aa:bb"},
			"uci set dhcp.@host[2].mac=aa:bb"},
		{"empty value is a legitimate set, not a delete",
			UCIChange{Config: "network", Section: "lan", Option: "gateway", Value: ""},
			"uci set network.lan.gateway="},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := strings.Join(uciArgv(tc.in), " "); got != tc.want {
				t.Errorf("got  %q\nwant %q", got, tc.want)
			}
		})
	}
}

// The staging loop never goes through a shell, but the argv must still be exactly one
// program and its arguments -- a value containing spaces or a semicolon is one argument.
func TestUciArgvKeepsValueAsASingleArgument(t *testing.T) {
	argv := uciArgv(UCIChange{Config: "system", Section: "@system[0]",
		Option: "description", Value: "a b; rm -rf /"})
	// uci set takes one "key=value" argument, so this is 3 elements, not 4.
	if len(argv) != 3 {
		t.Fatalf("argv = %q, want 3 elements", argv)
	}
	if argv[2] != "system.@system[0].description=a b; rm -rf /" {
		t.Errorf("value was split or mangled: %q", argv[2])
	}
}

func TestUciKeyScopeGranularity(t *testing.T) {
	// Creating a section and setting an option in it are different permissions.
	create := uciKey(UCIChange{Config: "dhcp", Section: "pi", Type: "host"})
	setOpt := uciKey(UCIChange{Config: "dhcp", Section: "pi", Option: "ip"})
	if create != "dhcp.pi" {
		t.Errorf("section scope = %q, want dhcp.pi", create)
	}
	if setOpt != "dhcp.pi.ip" {
		t.Errorf("option scope = %q, want dhcp.pi.ip", setOpt)
	}
	if create == setOpt {
		t.Error("section-level and option-level changes must not share a scope string")
	}
	// Regression: an empty Option used to leave a trailing dot, which a policy glob would
	// have matched differently from either intended form.
	if strings.HasSuffix(create, ".") {
		t.Errorf("section scope has a trailing dot: %q", create)
	}
}

func TestUciScopesCoversEveryChange(t *testing.T) {
	got := uciScopes(uciApplyIn{Changes: []UCIChange{
		{Config: "dhcp", Section: "pi", Type: "host"},
		{Config: "dhcp", Section: "pi", Option: "mac", Value: "aa:bb"},
		{Config: "dhcp", Section: "pi", Option: "ip", Value: "192.168.0.141"},
	}})
	want := []string{"dhcp.pi", "dhcp.pi.mac", "dhcp.pi.ip"}
	if len(got) != len(want) {
		t.Fatalf("got %d scopes, want %d: %q", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("scope %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// A policy that grants only option-level scopes must not silently permit section creation.
func TestSectionCreationNeedsItsOwnGrant(t *testing.T) {
	c := &Config{Policies: []*Policy{{
		Client: "a", Tools: []string{"uci_apply"},
		Scopes: []string{"dhcp.pi.*"}, MaxPerMin: 60, Enabled: true,
	}}}
	scopes := uciScopes(uciApplyIn{Changes: []UCIChange{
		{Config: "dhcp", Section: "pi", Type: "host"},
	}})
	if ok, reason := c.Authorise("a", "uci_apply", scopes, time.Now()); ok {
		t.Errorf("dhcp.pi.* wrongly covered creating the section dhcp.pi (%s)", reason)
	}
}

func TestValidateChange(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      UCIChange
		wantErr string
	}{
		{"option set is fine", UCIChange{Config: "dhcp", Section: "pi", Option: "ip"}, ""},
		{"section create is fine", UCIChange{Config: "dhcp", Section: "pi", Type: "host"}, ""},
		{"section delete is fine", UCIChange{Config: "dhcp", Section: "pi", Delete: true}, ""},
		{"no config", UCIChange{Section: "pi", Option: "ip"}, "config and a section"},
		{"no section", UCIChange{Config: "dhcp", Option: "ip"}, "config and a section"},
		{"nothing to do", UCIChange{Config: "dhcp", Section: "pi"}, "needs an option"},
		{"type with option", UCIChange{Config: "dhcp", Section: "pi", Type: "host", Option: "ip"},
			"cannot be combined with option"},
		{"type with delete", UCIChange{Config: "dhcp", Section: "pi", Type: "host", Delete: true},
			"cannot be combined with delete"},
		{"config path traversal", UCIChange{Config: "../passwd", Section: "pi", Option: "ip"},
			"bad config name"},
		{"config with a dot", UCIChange{Config: "a.b", Section: "pi", Option: "ip"},
			"bad config name"},
		{"type carrying an =", UCIChange{Config: "dhcp", Section: "pi", Type: "host=x"},
			"bad section type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateChange(tc.in)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected an error containing %q, got none", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not mention %q", err, tc.wantErr)
			}
		})
	}
}

func TestUciGetScope(t *testing.T) {
	cases := []struct {
		in   uciGetIn
		want string
	}{
		{uciGetIn{Config: "dhcp"}, "dhcp"},
		{uciGetIn{Config: "dhcp", Section: "lan"}, "dhcp.lan"},
		{uciGetIn{Config: "dhcp", Section: "lan", Option: "ipaddr"}, "dhcp.lan.ipaddr"},
	}
	for _, c := range cases {
		got := uciGetScope(c.in)
		if len(got) != 1 || got[0] != c.want {
			t.Errorf("uciGetScope(%+v) = %q, want [%q]", c.in, got, c.want)
		}
	}
}

// A "<config>.*" grant covers reading any section or option, but NOT a whole-config dump,
// which addresses bare "<config>". "<config>*" (no dot) covers everything under the config.
func TestUciGetScopeCoverage(t *testing.T) {
	covered := func(glob, scope string) bool {
		_, ok := firstUncovered([]string{glob}, []string{scope})
		return ok
	}
	if !covered("dhcp.*", "dhcp.lan") || !covered("dhcp.*", "dhcp.lan.ip") {
		t.Error("dhcp.* should cover section and option reads")
	}
	if covered("dhcp.*", "dhcp") {
		t.Error("dhcp.* must NOT cover a whole-config read")
	}
	for _, s := range []string{"dhcp", "dhcp.lan", "dhcp.lan.ip"} {
		if !covered("dhcp*", s) {
			t.Errorf("dhcp* should cover %q", s)
		}
	}
}

func TestUciGetValidation(t *testing.T) {
	if _, _, err := uciGet(t.Context(), uciGetIn{}); err == nil {
		t.Error("empty config should error")
	}
	if _, _, err := uciGet(t.Context(), uciGetIn{Config: "dhcp", Option: "ip"}); err == nil {
		t.Error("option without a section should error")
	}
}
