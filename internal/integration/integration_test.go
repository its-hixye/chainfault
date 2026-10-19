// Package integration holds the end-to-end tests of CHAINFAULT_DOC.md §22: the
// real Chainfault binary is built and run against small throwaway repositories
// that carry a known fake token.
//
// Two properties are checked:
//
//   - the default Gitleaks rules are actually in force (a missing `useDefault
//     = true` in templates/config.toml would make every scan silently find
//     nothing), and
//   - a repository cannot hide a secret from Chainfault, no matter which of the
//     three hiding mechanisms it reaches for.
//
// The tests skip themselves when the real helper tools are not installed, so
// `go test ./...` still passes on a machine without gitleaks or trufflehog.
package integration

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakeToken is invented for this test suite. It has the shape the default
// Gitleaks rules match, and it grants access to nothing.
//
// It is assembled from two halves at compile time so that no single line of this
// source file ever contains a complete, real-looking GitHub token
// (CHAINFAULT_DOC.md §22). The joined value is byte-for-byte the original token.
const fakeToken = "ghp_A1b2C3d4E5f6" + "G7h8I9j0KlMnOpQrStUvWxYz"

// fakeGrafanaKey is a fabricated Grafana service-account token, invented for this
// test suite: it grants access to nothing. It has the shape the Gitleaks default
// rule `grafana-api-key` matches, and — unlike fakeToken — TruffleHog does not
// report it at all, which is what makes the anti-hiding test below meaningful.
//
// Like fakeToken it is assembled from parts at compile time, so no single line
// of this source file ever contains a complete, real-looking token
// (CHAINFAULT_DOC.md §22).
const fakeGrafanaKey = "eyJrIjoi" + "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYiLCJuIjoiMTIzNDU2IiwiayI6ImFiY2RlZm" +
	"doaWprbG1ub3BxcnN0dXZ3eHl6IiwibiI6Ikxhc3R5Z2hpTm9Zb0tZeXhZZyJ9"

// maskedGrafanaKey is the display form of fakeGrafanaKey per normalizer.Mask
// (>= 12 characters -> first 4 + "****" + last 4).
const maskedGrafanaKey = "eyJr****ZyJ9"

// binary is the freshly built chainfault executable, shared by every test in
// this package.
var binary string

func TestMain(m *testing.M) {
	code, err := runMain(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "integration setup failed:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func runMain(m *testing.M) (int, error) {
	dir, err := os.MkdirTemp("", "chainfault-integration-")
	if err != nil {
		return 1, err
	}
	defer os.RemoveAll(dir)

	binary = filepath.Join(dir, "chainfault")
	cmd := exec.Command("go", "build", "-o", binary, "./cmd/chainfault")
	cmd.Dir = moduleRoot()
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	if out, err := cmd.CombinedOutput(); err != nil {
		return 1, fmt.Errorf("go build: %v\n%s", err, out)
	}
	return m.Run(), nil
}

// moduleRoot is the repository root, derived from this file's location
// (internal/integration/integration_test.go).
func moduleRoot() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "."
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// requireTools skips the test unless both helper tools are installed.
func requireTools(t *testing.T) {
	t.Helper()
	for _, name := range []string{"gitleaks", "trufflehog"} {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("%s is not installed: %v", name, err)
		}
	}
}

// git runs a git command inside dir and fails the test on error.
func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com",
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// newRepo creates a repository with one commit and returns its path.
func newRepo(t *testing.T, name string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	git(t, dir, "init", "-q", "-b", "main")
	return dir
}

func write(t *testing.T, dir, name, content string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}

func commit(t *testing.T, dir string) {
	t.Helper()
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "add the fake token")
}

// scanResult is one execution of the built binary.
type scanResult struct {
	code   int
	output string
}

// runChainfault executes `chainfault scan <repo>` and captures everything it
// printed, both streams together.
func runChainfault(t *testing.T, args ...string) scanResult {
	t.Helper()
	cmd := exec.Command(binary, args...)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		var exitErr *exec.ExitError
		if ok := asExitError(err, &exitErr); ok {
			code = exitErr.ExitCode()
		} else {
			t.Fatalf("run %v: %v\n%s", args, err, out)
		}
	}
	return scanResult{code: code, output: string(out)}
}

// asExitError is errors.As for *exec.ExitError, kept local so the imports stay
// minimal.
func asExitError(err error, target **exec.ExitError) bool {
	e, ok := err.(*exec.ExitError)
	if ok {
		*target = e
	}
	return ok
}

const defaultRulesHint = "the token was not found: check that templates/config.toml sets " +
	"[extend] useDefault = true, so Gitleaks runs with its default rules instead of none"

// TestDefaultRulesFindAKnownFakeToken is the "default rules" integration test of
// CHAINFAULT_DOC.md §22: a small repository holding one fake token must be
// reported, with exit code 1.
func TestDefaultRulesFindAKnownFakeToken(t *testing.T) {
	requireTools(t)

	repo := newRepo(t, "token-repo")
	write(t, repo, "config.py", "# a deliberately fake credential for the test suite\ntoken = \""+fakeToken+"\"\n")
	commit(t, repo)

	res := runChainfault(t, "scan", repo)
	if res.code != 1 {
		t.Fatalf("chainfault scan of a repo holding a token = %d, want 1 (%s)\n%s\n%s",
			res.code, defaultRulesHint, res.output, findOutputTail(res.output))
	}
	if !strings.Contains(res.output, "ghp_") {
		t.Errorf("the report does not show the masked token:\n%s", res.output)
	}
	if !strings.Contains(res.output, "config.py") {
		t.Errorf("the report does not name the offending file:\n%s", res.output)
	}
	if strings.Contains(res.output, fakeToken) {
		t.Errorf("the report leaked the full token; it must be masked by default:\n%s", res.output)
	}
}

// TestAntiHidingStillFindsTheToken is the "hiding prevention" integration test of
// CHAINFAULT_DOC.md §22: a repository hides a fake secret all three ways
// Chainfault knows about.
//
//  1. a .gitleaksignore fingerprint,
//  2. a .gitleaks.toml allowlist,
//  3. a `gitleaks:allow` comment on the line.
//
// None of them may suppress the finding: the scan runs on a temporary clone
// where the first two files have been deleted, and --ignore-gitleaks-allow
// neutralizes the third.
//
// The secret used here is deliberately one that Gitleaks detects but TruffleHog
// does not report at all (with --no-verification), so the finding can only come
// from Gitleaks running against the cleaned clone. With a secret both tools
// detect, TruffleHog would ignore `.gitleaksignore` and find it anyway, and the
// test would pass even if the `.gitleaksignore` deletion layer were broken —
// which is exactly the layer this test exists to prove (CHAINFAULT_DOC.md §22).
func TestAntiHidingStillFindsTheToken(t *testing.T) {
	requireTools(t)

	repo := newRepo(t, "hiding-repo")

	// The secret is committed first, with the inline hiding comment on its line.
	// 3. A `gitleaks:allow` comment on the same line as the secret.
	write(t, repo, "config.py", "grafana_token = \""+fakeGrafanaKey+"\"  # gitleaks:allow\n")
	commit(t, repo)

	// 1. A fingerprint that would match the finding of the commit above. Gitleaks
	// reports fingerprints as commit:file:rule:line; the rule id here is the
	// default-rule id the secret above actually trips (grafana-api-key).
	head := gitOut(t, repo, "rev-parse", "HEAD")
	write(t, repo, ".gitleaksignore", head+":config.py:grafana-api-key:1\n")

	// 2. A configuration that allows every path.
	write(t, repo, ".gitleaks.toml", `title = "hide everything"

[extend]
useDefault = true

[[allowlists]]
description = "suppress all findings"
paths = ['''.*''']
`)
	commit(t, repo)

	res := runChainfault(t, "scan", repo)
	if res.code != 1 {
		t.Fatalf("chainfault scan of a hiding repository = %d, want 1 — the repository was able to hide a secret\n%s\n%s",
			res.code, defaultRulesHint, findOutputTail(res.output))
	}
	if !strings.Contains(res.output, maskedGrafanaKey) {
		t.Errorf("the hidden secret was not reported (want the masked form %q):\n%s",
			maskedGrafanaKey, res.output)
	}

	// The user's own checkout is untouched: the hiding files are still there.
	for _, name := range []string{".gitleaksignore", ".gitleaks.toml"} {
		if _, err := os.Stat(filepath.Join(repo, name)); err != nil {
			t.Errorf("%s was removed from the original repository: %v", name, err)
		}
	}
	if status := gitOut(t, repo, "status", "--porcelain"); status != "" {
		t.Errorf("the original repository is dirty after a scan: %q", status)
	}
}

// gitOut runs a git command and returns its trimmed output.
func gitOut(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %s: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out))
}

// findOutputTail returns the last lines of the scan output, for a readable
// failure message.
func findOutputTail(out string) string {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) > 20 {
		lines = lines[len(lines)-20:]
	}
	return strings.Join(lines, "\n")
}
