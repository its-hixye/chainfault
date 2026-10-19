package main

import (
	"strings"
	"testing"
)

// TestVersionAliasesPrintTheSameLine pins the exact printed output of the
// version command and both of its aliases. cmd_test.go's TestVersion only
// checks that the line is contained in the output; this one checks the whole
// line, byte for byte, so the "v" prefix and the trailing newline can never
// drift.
func TestVersionAliasesPrintTheSameLine(t *testing.T) {
	const want = "chainfault v0.1.0\n"

	for _, arg := range []string{"version", "--version", "-v"} {
		t.Run(arg, func(t *testing.T) {
			code, out := runCLI(t, arg)
			if code != exitClean {
				t.Errorf("run(%q) = %d, want %d", arg, code, exitClean)
			}
			if out != want {
				t.Errorf("run(%q) printed %q, want exactly %q", arg, out, want)
			}
		})
	}
}

// TestVersionDefaultHasNoLeadingV guards the build-time override contract: the
// package variable itself never carries a "v", because the printed line adds
// one. A "v" baked into the variable would print "chainfault vv0.1.0".
func TestVersionDefaultHasNoLeadingV(t *testing.T) {
	if version != "0.1.0" {
		t.Errorf("version = %q, want %q", version, "0.1.0")
	}
	if strings.HasPrefix(version, "v") {
		t.Errorf("version = %q, want no leading \"v\": the prefix belongs to the output format", version)
	}
}

// TestVersionLineAlwaysCarriesTheVPrefix checks the format string rather than
// the current value: whatever a release build injects through
// -ldflags "-X main.version=...", the printed line starts with "chainfault v".
func TestVersionLineAlwaysCarriesTheVPrefix(t *testing.T) {
	const prefix = "chainfault v"

	code, out := runCLI(t, "version")
	if code != exitClean {
		t.Fatalf("run(\"version\") = %d, want %d", code, exitClean)
	}
	if !strings.HasPrefix(out, prefix) {
		t.Errorf("run(\"version\") printed %q, want it to start with %q", out, prefix)
	}

	// The prefix must be added by the format string, not by the value: a
	// hypothetical injected "1.2.3" has to render as "chainfault v1.2.3".
	orig := version
	t.Cleanup(func() { version = orig })

	for _, injected := range []string{"1.2.3", "9.9.9", "0.0.0-dev"} {
		version = injected
		_, got := runCLI(t, "version")
		if want := prefix + injected + "\n"; got != want {
			t.Errorf("version = %q printed %q, want %q", injected, got, want)
		}
	}
}
