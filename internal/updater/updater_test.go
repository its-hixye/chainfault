package updater

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installFakeTool writes a tiny executable shell script named tool into dir and
// returns its path. The scripts only use POSIX shell builtins (printf), so the
// tests never depend on the real Gitleaks or TruffleHog being installed.
func installFakeTool(t *testing.T, dir, tool, body string) string {
	t.Helper()
	path := filepath.Join(dir, tool)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", tool, err)
	}
	return path
}

// TestLookup is table-driven: each case installs (or omits) a fake tool on a
// PATH containing only that temp directory, then asserts the exact Status the
// doctor and scan preflight rely on.
func TestLookup(t *testing.T) {
	cases := []struct {
		name          string
		tool          string
		script        string // "" means: do not install the tool
		wantOK        bool
		wantVersion   string
		wantReasonHas string
	}{
		{
			name:        "banner with name and version prefix is trimmed",
			tool:        "gitleaks",
			script:      `printf 'gitleaks version 8.18.0\n'`,
			wantOK:      true,
			wantVersion: "8.18.0",
		},
		{
			name:        "banner with name and short v prefix is trimmed",
			tool:        "gitleaks",
			script:      `printf 'gitleaks v9.0.0\n'`,
			wantOK:      true,
			wantVersion: "9.0.0",
		},
		{
			name:        "bare version prefix is trimmed",
			tool:        "trufflehog",
			script:      `printf 'version 3.63.0\n'`,
			wantOK:      true,
			wantVersion: "3.63.0",
		},
		{
			name:        "only the first non-empty line is kept",
			tool:        "gitleaks",
			script:      `printf '\ngitleaks version 8.19.1\nbuild abc123\n'`,
			wantOK:      true,
			wantVersion: "8.19.1",
		},
		{
			name:        "banner without the tool name yields the bare version",
			tool:        "trufflehog",
			script:      `printf 'trufflehog 3.99.2\n'`,
			wantOK:      true,
			wantVersion: "3.99.2",
		},
		{
			name:        "build-process banner is installed with unknown version",
			tool:        "gitleaks",
			script:      `printf 'gitleaks version version is set by build process\n'`,
			wantOK:      true,
			wantVersion: unknownVersion,
		},
		{
			name:        "tool that prints nothing is installed with unknown version",
			tool:        "gitleaks",
			script:      `exit 0`,
			wantOK:      true,
			wantVersion: unknownVersion,
		},
		{
			name:        "tool whose --version fails is installed with unknown version",
			tool:        "trufflehog",
			script:      `exit 1`,
			wantOK:      true,
			wantVersion: unknownVersion,
		},
		{
			name:        "tool that fails --version but prints a banner keeps the version",
			tool:        "trufflehog",
			script:      `printf 'trufflehog 3.99.2\n'; exit 1`,
			wantOK:      true,
			wantVersion: "3.99.2",
		},
		{
			name:          "tool absent from PATH is reported",
			tool:          "gitleaks",
			script:        "",
			wantOK:        false,
			wantReasonHas: "PATH",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.script != "" {
				installFakeTool(t, dir, tc.tool, tc.script)
			}
			// PATH is narrowed to the temp directory so a real tool installed
			// on the machine can never satisfy (or distort) the lookup.
			t.Setenv("PATH", dir)

			st := Lookup(tc.tool)

			if st.Name != tc.tool {
				t.Errorf("Name = %q, want %q", st.Name, tc.tool)
			}
			if st.OK != tc.wantOK {
				t.Errorf("OK = %v, want %v (Reason %q)", st.OK, tc.wantOK, st.Reason)
			}
			if st.Version != tc.wantVersion {
				t.Errorf("Version = %q, want %q", st.Version, tc.wantVersion)
			}
			// doctor prints the tool name itself, so the version string must
			// never repeat it ("trufflehog trufflehog 3.99.2").
			if tc.wantOK && tc.wantVersion != unknownVersion && strings.Contains(st.Version, tc.tool) {
				t.Errorf("Version = %q repeats the tool name %q", st.Version, tc.tool)
			}
			if tc.wantOK {
				wantPath := filepath.Join(dir, tc.tool)
				if st.Path != wantPath {
					t.Errorf("Path = %q, want %q", st.Path, wantPath)
				}
			}
			if tc.wantReasonHas != "" && !strings.Contains(st.Reason, tc.wantReasonHas) {
				t.Errorf("Reason = %q, want it to contain %q", st.Reason, tc.wantReasonHas)
			}
		})
	}
}

// TestEnsure walks the four present/missing combinations and checks that the
// returned statuses stay aligned with the requested tools and that an error is
// returned whenever anything is missing.
func TestEnsure(t *testing.T) {
	tools := []string{"gitleaks", "trufflehog"}

	cases := []struct {
		name        string
		present     []string
		wantMissing []string
	}{
		{name: "both present", present: []string{"gitleaks", "trufflehog"}, wantMissing: nil},
		{name: "gitleaks missing", present: []string{"trufflehog"}, wantMissing: []string{"gitleaks"}},
		{name: "trufflehog missing", present: []string{"gitleaks"}, wantMissing: []string{"trufflehog"}},
		{name: "both missing", present: nil, wantMissing: []string{"gitleaks", "trufflehog"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, tool := range tc.present {
				installFakeTool(t, dir, tool, `printf '`+tool+` version 1.2.3\n'`)
			}
			t.Setenv("PATH", dir)

			statuses, err := Ensure(context.Background(), tools)

			if len(statuses) != len(tools) {
				t.Fatalf("len(statuses) = %d, want %d", len(statuses), len(tools))
			}
			for i, tool := range tools {
				if statuses[i].Name != tool {
					t.Errorf("statuses[%d].Name = %q, want %q", i, statuses[i].Name, tool)
				}
			}

			if len(tc.wantMissing) == 0 {
				if err != nil {
					t.Fatalf("Ensure returned error %v, want nil", err)
				}
				for _, st := range statuses {
					if !st.OK {
						t.Errorf("status %q not OK: %q", st.Name, st.Reason)
					}
				}
				return
			}

			if err == nil {
				t.Fatal("Ensure returned nil error, want missing-tool error")
			}
			for _, missing := range tc.wantMissing {
				if !strings.Contains(err.Error(), missing) {
					t.Errorf("error %q does not name missing tool %q", err.Error(), missing)
				}
			}
			for _, present := range tc.present {
				if strings.Contains(err.Error(), present+" —") {
					t.Errorf("error %q reports present tool %q as missing", err.Error(), present)
				}
			}
		})
	}
}

// TestMissingToolsErrorNamesEveryToolAndReleasesLink pins the exact error text
// the CLI prints: every missing tool with its official /releases link.
func TestMissingToolsErrorNamesEveryToolAndReleasesLink(t *testing.T) {
	err := missingToolsError([]string{"gitleaks", "trufflehog"})
	if err == nil {
		t.Fatal("want an error, got nil")
	}
	msg := err.Error()

	if !strings.HasPrefix(msg, "missing helper tool(s):") {
		t.Errorf("error %q does not start with the documented header", msg)
	}
	wantLinks := map[string]string{
		"gitleaks":   "https://github.com/gitleaks/gitleaks/releases",
		"trufflehog": "https://github.com/trufflesecurity/trufflehog/releases",
	}
	for tool, link := range wantLinks {
		if !strings.Contains(msg, tool) {
			t.Errorf("error %q does not name %q", msg, tool)
		}
		if !strings.Contains(msg, link) {
			t.Errorf("error %q does not include Releases link %q", msg, link)
		}
	}
}

// TestMissingToolsErrorWithoutKnownPage covers the fallback line used when a
// tool has no releases URL configured: it must still name the tool and tell the
// user to put it in PATH, without inventing a link.
func TestMissingToolsErrorWithoutKnownPage(t *testing.T) {
	err := missingToolsError([]string{"mysterytool"})
	msg := err.Error()

	if !strings.Contains(msg, "mysterytool") {
		t.Errorf("error %q does not name the tool", msg)
	}
	if !strings.Contains(msg, "install it and make sure it is in PATH") {
		t.Errorf("error %q lacks the no-link fallback", msg)
	}
	if strings.Contains(msg, "— install it from") {
		t.Errorf("error %q invented a Releases link for an unknown tool", msg)
	}
}

// TestExtractVersion pins the banner-parsing rule: a dotted number is the
// version, anything else means "unknown" and is left to Lookup's fallback.
func TestExtractVersion(t *testing.T) {
	cases := []struct {
		line string
		want string
	}{
		{"gitleaks version 8.26.0", "8.26.0"},
		{"trufflehog 3.99.2", "3.99.2"},
		{"gitleaks v9.0.0", "9.0.0"},
		{"version 3.63.0", "3.63.0"},
		{"secret-scanner 1.2.3-rc1", "1.2.3-rc1"},
		{"gitleaks version version is set by build process", ""},
		{"gitleaks version unknown", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := extractVersion(tc.line); got != tc.want {
			t.Errorf("extractVersion(%q) = %q, want %q", tc.line, got, tc.want)
		}
	}
}

func TestReleasesPage(t *testing.T) {
	cases := []struct {
		name string
		want string
	}{
		{"gitleaks", "https://github.com/gitleaks/gitleaks/releases"},
		{"trufflehog", "https://github.com/trufflesecurity/trufflehog/releases"},
		{"nope", ""},
		{"", ""},
	}
	for _, tc := range cases {
		if got := ReleasesPage(tc.name); got != tc.want {
			t.Errorf("ReleasesPage(%q) = %q, want %q", tc.name, got, tc.want)
		}
	}
}
