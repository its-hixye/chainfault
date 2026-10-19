package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// fakeToken looks like a GitHub token to the default Gitleaks rules but is
// invented for this test suite: it is not a valid credential of any kind.
//
// It is assembled from two halves at compile time so that no single line of this
// source file ever contains a complete, real-looking GitHub token
// (CHAINFAULT_DOC.md §22). The joined value is byte-for-byte the original token.
const fakeToken = "ghp_A1b2C3d4E5f6" + "G7h8I9j0KlMnOpQrStUvWxYz"

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// captureOutput redirects stdout and stderr into a temporary file while fn
// runs, and returns everything written. A file rather than a pipe, so a chatty
// report can never fill a pipe buffer and deadlock the test.
func captureOutput(t *testing.T, fn func()) string {
	t.Helper()

	f, err := os.CreateTemp(t.TempDir(), "chainfault-output-")
	if err != nil {
		t.Fatalf("create temp output file: %v", err)
	}
	origOut, origErr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = f, f
	defer func() {
		os.Stdout, os.Stderr = origOut, origErr
	}()

	fn()

	f.Close()
	raw, err := os.ReadFile(f.Name())
	if err != nil {
		t.Fatalf("read captured output: %v", err)
	}
	return string(raw)
}

// runCLI calls run() with the given arguments and returns its exit code plus
// everything it printed.
func runCLI(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var code int
	out := captureOutput(t, func() { code = run(args) })
	return code, out
}

// git runs a git command inside dir.
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

// requireTools skips the test when the real helper tools are not installed.
func requireTools(t *testing.T) {
	t.Helper()
	for _, name := range requiredTools {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("%s is not installed: %v", name, err)
		}
	}
}

// secretRepo returns a git repository with one commit that holds a fake token.
func secretRepo(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "secret-repo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	git(t, dir, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "config.py"), []byte("token = \""+fakeToken+"\"\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "add token")
	return dir
}

// cleanRepo returns a git repository with one commit and no secrets.
func cleanRepo(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "clean-repo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	git(t, dir, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	git(t, dir, "add", "-A")
	git(t, dir, "commit", "-q", "-m", "init")
	return dir
}

// emptyRepo returns an initialized repository with no commits.
func emptyRepo(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "empty-repo")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	git(t, dir, "init", "-q", "-b", "main")
	return dir
}

// ---------------------------------------------------------------------------
// version / help / unknown command
// ---------------------------------------------------------------------------

func TestVersion(t *testing.T) {
	for _, arg := range []string{"version", "--version", "-v"} {
		code, out := runCLI(t, arg)
		if code != exitClean {
			t.Errorf("run(%q) = %d, want %d", arg, code, exitClean)
		}
		want := "chainfault v" + version
		if !strings.Contains(out, want) {
			t.Errorf("run(%q) printed %q, want it to contain %q", arg, out, want)
		}
	}
}

func TestHelp(t *testing.T) {
	for _, arg := range []string{"help", "--help", "-h"} {
		code, out := runCLI(t, arg)
		if code != exitClean {
			t.Errorf("run(%q) = %d, want %d", arg, code, exitClean)
		}
		if !strings.Contains(out, "chainfault scan") {
			t.Errorf("run(%q) printed %q, want the usage text", arg, out)
		}
	}
}

func TestNoArgumentsAndUnknownCommand(t *testing.T) {
	if code, _ := runCLI(t); code != exitIncomplete {
		t.Errorf("run() with no arguments = %d, want %d", code, exitIncomplete)
	}
	code, out := runCLI(t, "nonsense")
	if code != exitIncomplete {
		t.Errorf("run(\"nonsense\") = %d, want %d", code, exitIncomplete)
	}
	if !strings.Contains(out, "unknown command") {
		t.Errorf("run(\"nonsense\") printed %q, want it to name the unknown command", out)
	}
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

func TestDoctorWithBothToolsInstalled(t *testing.T) {
	requireTools(t)

	code, out := runCLI(t, "doctor")
	if code != exitClean {
		t.Errorf("doctor = %d, want %d\n%s", code, exitClean, out)
	}
	for _, name := range requiredTools {
		if !strings.Contains(out, name) {
			t.Errorf("doctor output %q is missing %s", out, name)
		}
	}
}

func TestDoctorWithOneToolMissing(t *testing.T) {
	realGitleaks, err := exec.LookPath("gitleaks")
	if err != nil {
		t.Skipf("gitleaks is not installed: %v", err)
	}
	realTruffleHog, err := exec.LookPath("trufflehog")
	if err != nil {
		t.Skipf("trufflehog is not installed: %v", err)
	}

	cases := []struct {
		name    string
		present string
		missing string
	}{
		{"gitleaks missing", realTruffleHog, "gitleaks"},
		{"trufflehog missing", realGitleaks, "trufflehog"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// A PATH holding exactly one tool: the missing one must not be
			// reachable at all, which is what doctor has to notice.
			binDir := filepath.Join(t.TempDir(), "bin")
			if err := os.MkdirAll(binDir, 0o755); err != nil {
				t.Fatalf("mkdir: %v", err)
			}
			link := filepath.Join(binDir, filepath.Base(c.present))
			if err := os.Symlink(c.present, link); err != nil {
				t.Fatalf("symlink: %v", err)
			}
			t.Setenv("PATH", binDir)

			code, out := runCLI(t, "doctor")
			if code != exitIncomplete {
				t.Errorf("doctor without %s = %d, want %d\n%s", c.missing, code, exitIncomplete, out)
			}
			if !strings.Contains(out, c.missing) {
				t.Errorf("doctor output %q does not mention %s", out, c.missing)
			}
		})
	}
}

func TestDoctorWithNoToolsAtAll(t *testing.T) {
	t.Setenv("PATH", t.TempDir())

	code, out := runCLI(t, "doctor")
	if code != exitIncomplete {
		t.Errorf("doctor without any tool = %d, want %d", code, exitIncomplete)
	}
	for _, name := range requiredTools {
		if !strings.Contains(out, name) {
			t.Errorf("doctor output %q is missing %s", out, name)
		}
	}
}

func TestDoctorRejectsExtraArguments(t *testing.T) {
	if code, _ := runCLI(t, "doctor", "extra"); code != exitIncomplete {
		t.Errorf("doctor with an extra argument = %d, want %d", code, exitIncomplete)
	}
}

// ---------------------------------------------------------------------------
// splitTarget
// ---------------------------------------------------------------------------

func TestSplitTarget(t *testing.T) {
	cases := []struct {
		name       string
		in         []string
		wantTarget string
		wantFlags  []string
	}{
		{"target first", []string{"/repo", "--html"}, "/repo", []string{"--html"}},
		{"target last", []string{"--html", "/repo"}, "/repo", []string{"--html"}},
		{"only target", []string{"/repo"}, "/repo", []string{}},
		{"space separated value", []string{"/repo", "--depth", "5"}, "/repo", []string{"--depth", "5"}},
		{"value before target", []string{"--depth", "5", "/repo"}, "/repo", []string{"--depth", "5"}},
		{"equals form", []string{"--output=r.html", "/repo"}, "/repo", []string{"--output=r.html"}},
		{"nothing", nil, "", []string{}},
		{"flag that looks like a path", []string{"--html", "/repo", "--verify"}, "/repo", []string{"--html", "--verify"}},
	}
	for _, c := range cases {
		target, flags := splitTarget(c.in)
		if target != c.wantTarget {
			t.Errorf("%s: target = %q, want %q", c.name, target, c.wantTarget)
		}
		if strings.Join(flags, " ") != strings.Join(c.wantFlags, " ") {
			t.Errorf("%s: flags = %q, want %q", c.name, flags, c.wantFlags)
		}
	}
}

// ---------------------------------------------------------------------------
// resolveOutput
// ---------------------------------------------------------------------------

func TestResolveOutput(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "report.html")

	if got, err := resolveOutput(scanFlags{}, "/repo"); err != nil || got != "" {
		t.Errorf("resolveOutput(no flags) = (%q, %v), want (\"\", nil)", got, err)
	}

	def, err := resolveOutput(scanFlags{html: true}, "/repo")
	if err != nil {
		t.Fatalf("resolveOutput(--html) = %v", err)
	}
	if !strings.HasSuffix(strings.ToLower(def), ".html") {
		t.Errorf("default output = %q, want a .html path", def)
	}

	if got, err := resolveOutput(scanFlags{html: true, output: good}, "/repo"); err != nil || got != good {
		t.Errorf("resolveOutput(valid) = (%q, %v), want (%q, nil)", got, err, good)
	}
}

func TestResolveOutputRejectsBadValues(t *testing.T) {
	dir := t.TempDir()
	cases := []struct {
		name string
		f    scanFlags
	}{
		{"output without html", scanFlags{output: filepath.Join(dir, "r.html")}},
		{"output not ending in .html", scanFlags{html: true, output: filepath.Join(dir, "r.txt")}},
		{"missing parent directory", scanFlags{html: true, output: filepath.Join(dir, "nope", "r.html")}},
	}
	for _, c := range cases {
		got, err := resolveOutput(c.f, "/repo")
		if err == nil {
			t.Errorf("%s: resolveOutput = (%q, nil), want an error", c.name, got)
		}
		if got != "" {
			t.Errorf("%s: resolveOutput returned %q alongside an error", c.name, got)
		}
	}
}

// ---------------------------------------------------------------------------
// validateTarget
// ---------------------------------------------------------------------------

func TestValidateTarget(t *testing.T) {
	root := t.TempDir()

	if err := validateTarget(cleanRepo(t)); err != nil {
		t.Errorf("validateTarget(a committed repo) = %v, want nil", err)
	}
	if err := validateTarget("https://github.com/its-hixye/chainfault"); err != nil {
		t.Errorf("validateTarget(https URL) = %v, want nil", err)
	}

	plain := filepath.Join(root, "plain")
	if err := os.MkdirAll(plain, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cases := map[string]string{
		"missing path":   filepath.Join(root, "does-not-exist"),
		"not a git repo": plain,
		"empty repo":     emptyRepo(t),
		"http URL":       "http://github.com/a/b",
		"git URL":        "git://github.com/a/b",
		"ssh URL":        "ssh://git@github.com/a/b",
		"a file":         filepath.Join(t.TempDir(), "a-file.txt"),
	}
	for name, target := range cases {
		if target == filepath.Join(t.TempDir(), "a-file.txt") {
			if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
				t.Fatalf("write: %v", err)
			}
		}
		if err := validateTarget(target); err == nil {
			t.Errorf("%s: validateTarget(%q) = nil, want an error", name, target)
		}
	}
}

// ---------------------------------------------------------------------------
// scan: exit codes (CHAINFAULT_DOC.md §16)
// ---------------------------------------------------------------------------

func TestScanExitCodeFindings(t *testing.T) {
	requireTools(t)

	repo := secretRepo(t)
	code, out := runCLI(t, "scan", repo)
	if code != exitFindings {
		t.Fatalf("scan of a repo holding a secret = %d, want %d\n%s", code, exitFindings, out)
	}
	if !strings.Contains(out, "ghp_") {
		t.Errorf("scan output does not show the masked token:\n%s", out)
	}
	// The original repository must not be modified by a scan.
	if _, err := os.Stat(filepath.Join(repo, ".git")); err != nil {
		t.Errorf("scan disturbed the original repository: %v", err)
	}
}

func TestScanExitCodeClean(t *testing.T) {
	requireTools(t)

	repo := cleanRepo(t)
	code, out := runCLI(t, "scan", repo)
	if code != exitClean {
		t.Fatalf("scan of a clean repo = %d, want %d\n%s", code, exitClean, out)
	}
}

func TestScanExitCodeIncomplete(t *testing.T) {
	requireTools(t)

	root := t.TempDir()
	plain := filepath.Join(root, "plain")
	if err := os.MkdirAll(plain, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	cases := map[string]string{
		"missing path":   filepath.Join(root, "does-not-exist"),
		"not a git repo": plain,
		"empty repo":     emptyRepo(t),
		"http URL":       "http://github.com/a/b",
	}
	for name, target := range cases {
		code, out := runCLI(t, "scan", target)
		if code != exitIncomplete {
			t.Errorf("%s: scan = %d, want %d\n%s", name, code, exitIncomplete, out)
		}
	}
}

func TestScanRejectsBadOptions(t *testing.T) {
	root := t.TempDir()
	repo := cleanRepo(t)

	cases := map[string][]string{
		"missing target":            {"scan"},
		"--output without --html":   {"scan", repo, "--output=" + filepath.Join(root, "r.html")},
		"--output not ending .html": {"scan", repo, "--html", "--output=" + filepath.Join(root, "r.txt")},
		"--output in missing dir":   {"scan", repo, "--html", "--output=" + filepath.Join(root, "nope", "r.html")},
		"--depth not a number":      {"scan", repo, "--depth", "banana"},
		"--depth zero":              {"scan", repo, "--depth", "0"},
		"--depth negative":          {"scan", repo, "--depth", "-3"},
		"unexpected extra argument": {"scan", repo, "another-target"},
		"unknown flag":              {"scan", repo, "--nope"},
	}
	for name, args := range cases {
		code, out := runCLI(t, args...)
		if code != exitIncomplete {
			t.Errorf("%s: run(%q) = %d, want %d\n%s", name, args, code, exitIncomplete, out)
		}
	}
}

func TestScanWritesHTMLReport(t *testing.T) {
	requireTools(t)

	repo := cleanRepo(t)
	out := filepath.Join(t.TempDir(), "report.html")

	code, stdout := runCLI(t, "scan", repo, "--html", "--output="+out)
	if code != exitClean {
		t.Fatalf("scan --html = %d, want %d\n%s", code, exitClean, stdout)
	}
	report, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("HTML report was not written: %v", err)
	}
	if len(report) == 0 {
		t.Error("HTML report is empty")
	}
	if !strings.Contains(stdout, out) {
		t.Errorf("scan did not report where it saved the HTML file:\n%s", stdout)
	}
}
