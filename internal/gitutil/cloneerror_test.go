package gitutil

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCloneErrorFormatsSafeMessages pins the exact wording of a failed clone.
//
// A failed clone used to print the whole git command line and the temporary
// destination path, and could echo credentials back to the terminal. These
// cases fix the replacement: one short sentence, credentials stripped, and no
// command line, destination path or stderr preamble anywhere in the result.
func TestCloneErrorFormatsSafeMessages(t *testing.T) {
	cases := []struct {
		name   string
		source string
		dst    string
		stderr string
		want   string
	}{
		{
			name:   "repository not found with credentials in the url",
			source: "https://user:secret@example.com/x",
			dst:    "/tmp/chainfault-123/repo",
			stderr: "Cloning into '/tmp/chainfault-123/repo'...\n" +
				"remote: Repository not found.\n" +
				"fatal: repository 'https://user:secret@example.com/x/' not found\n",
			want: "could not clone https://example.com/x: repository not found or not accessible",
		},
		{
			name:   "authentication failure collapses into the same message",
			source: "https://example.com/x",
			dst:    "/tmp/chainfault-123/repo",
			stderr: "fatal: Authentication failed for 'https://example.com/x/'\n",
			want:   "could not clone https://example.com/x: repository not found or not accessible",
		},
		{
			name:   "local path that does not exist is not accessible",
			source: "/home/someone/missing-repo",
			dst:    "/tmp/chainfault-123/repo",
			stderr: "fatal: repository '/home/someone/missing-repo' does not exist\n",
			want:   "could not clone /home/someone/missing-repo: repository not found or not accessible",
		},
		{
			name:   "generic fatal line is shown on its own",
			source: "https://example.com/x",
			dst:    "/tmp/chainfault-123/repo",
			stderr: "Cloning into '/tmp/chainfault-123/repo'...\n" +
				"warning: remote HEAD refers to a nonexistent ref\n" +
				"fatal: early EOF\n",
			want: "fatal: early EOF",
		},
		{
			name:   "fatal line echoing a credential url is redacted",
			source: "https://example.com/x",
			dst:    "/tmp/chainfault-123/repo",
			stderr: "fatal: unable to access 'https://user:token@example.com/x/': The requested URL returned error: 418\n",
			want:   "fatal: unable to access 'https://example.com/x/': The requested URL returned error: 418",
		},
		{
			name:   "no fatal line falls back to a generic message",
			source: "https://example.com/x",
			dst:    "/tmp/chainfault-123/repo",
			stderr: "Cloning into '/tmp/chainfault-123/repo'...\n",
			want:   "could not clone https://example.com/x: git clone failed",
		},
		{
			name:   "empty stderr falls back to a generic message",
			source: "https://example.com/x",
			dst:    "/tmp/chainfault-123/repo",
			stderr: "",
			want:   "could not clone https://example.com/x: git clone failed",
		},
		{
			name:   "fatal line mentioning the destination path hides it",
			source: "https://example.com/x",
			dst:    "/tmp/chainfault-123/repo",
			stderr: "fatal: destination path '/tmp/chainfault-123/repo' already exists and is not an empty directory.\n",
			want:   "fatal: destination path '<destination>' already exists and is not an empty directory.",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := cloneError(tc.source, tc.dst, tc.stderr)
			if err == nil {
				t.Fatal("cloneError = nil, want an error")
			}
			got := err.Error()
			if got != tc.want {
				t.Errorf("cloneError =\n  %q\nwant\n  %q", got, tc.want)
			}
			assertNoLeak(t, got, tc.source, tc.dst)
		})
	}
}

// TestCloneErrorNeverLeaksCredentials is the invariant behind the table above:
// no code path may put a user or token on screen.
func TestCloneErrorNeverLeaksCredentials(t *testing.T) {
	const (
		user  = "alice"
		token = "ghp_supersecret"
		src   = "https://" + user + ":" + token + "@example.com/x"
	)
	stders := []string{
		"fatal: repository 'https://" + user + ":" + token + "@example.com/x/' not found",
		"fatal: unable to access '" + src + "/': something broke",
		"remote: Repository not found.\nfatal: Authentication failed for '" + src + "/'\n",
		"fatal: could not read Username for 'https://example.com': terminal prompts disabled\n",
	}
	for _, stderr := range stders {
		got := cloneError(src, "/tmp/chainfault-9/repo", stderr).Error()
		if strings.Contains(got, token) || strings.Contains(got, user+"@") || strings.Contains(got, user+":") {
			t.Errorf("credentials leaked into %q", got)
		}
		if strings.Contains(got, "/tmp/chainfault-9/repo") {
			t.Errorf("temporary destination path leaked into %q", got)
		}
	}
}

// TestRedactCredentialsStripsUserinfo covers the redactor on its own, including
// the case where nothing must change.
func TestRedactCredentialsStripsUserinfo(t *testing.T) {
	cases := map[string]string{
		"https://user:token@example.com/x":      "https://example.com/x",
		"https://token@example.com/x":           "https://example.com/x",
		"https://example.com/x":                 "https://example.com/x",
		"fatal: could not read Password for a":  "fatal: could not read Password for a",
		"see https://a:b@h/x and https://c@h/y": "see https://h/x and https://h/y",
		"/home/someone/repo":                    "/home/someone/repo",
		"https://example.com/a@b/c":             "https://example.com/a@b/c",
	}
	for in, want := range cases {
		if got := redactCredentials(in); got != want {
			t.Errorf("redactCredentials(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestLastFatalLinePicksTheLastFatalOnly pins which part of git's stderr
// survives: the last `fatal:` line, trimmed, with no preamble.
func TestLastFatalLinePicksTheLastFatalOnly(t *testing.T) {
	cases := []struct {
		name   string
		stderr string
		want   string
	}{
		{"no stderr", "", ""},
		{"no fatal line", "Cloning into '/tmp/x'...\nwarning: something\n", ""},
		{"one fatal line", "Cloning into '/tmp/x'...\nfatal: early EOF\n", "fatal: early EOF"},
		{
			"last of several",
			"fatal: first\nfatal: second\nfatal: third\n",
			"fatal: third",
		},
		{"capitalized fatal", "FATAL: nope\n", "FATAL: nope"},
		{"leading space trimmed", "   fatal: padded\n", "fatal: padded"},
		{"crlf", "fatal: crlf\r\n", "fatal: crlf"},
		{"fatal must start the line", "remote: fatal: not a fatal prefix\n", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := lastFatalLine(tc.stderr); got != tc.want {
				t.Errorf("lastFatalLine(%q) = %q, want %q", tc.stderr, got, tc.want)
			}
		})
	}
}

// TestLooksNotFound covers the marker set, including the negative case that
// keeps unrelated failures on the generic path.
func TestLooksNotFound(t *testing.T) {
	positive := []string{
		"remote: Repository not found.",
		"fatal: repository 'https://example.com/x/' not found",
		"fatal: could not read from remote repository.\nremote: not found",
		"fatal: '/x' does not exist",
		"fatal: Authentication failed",
		"fatal: could not read Username for 'https://example.com'",
		"fatal: could not read Password for 'https://example.com'",
		"remote: Permission denied",
		"fatal: unable to access: Access denied",
		"error: RPC failed; HTTP 401 curl 22",
		"error: RPC failed; HTTP 403",
		"error: RPC failed; HTTP 404",
	}
	for _, stderr := range positive {
		if !looksNotFound(stderr) {
			t.Errorf("looksNotFound(%q) = false, want true", stderr)
		}
	}
	negative := []string{
		"",
		"fatal: early EOF",
		"fatal: destination path 'x' already exists and is not an empty directory.",
		"fatal: the remote end hung up unexpectedly",
	}
	for _, stderr := range negative {
		if looksNotFound(stderr) {
			t.Errorf("looksNotFound(%q) = true, want false", stderr)
		}
	}
}

// TestCloneFailureReportsNoCommandPathOrSecret drives the real Clone against a
// fake git on PATH that fails the way git fails on a bad remote, and asserts
// the end-to-end contract: no command line, no temporary destination path, no
// credential. No network and no real remote is involved.
func TestCloneFailureReportsNoCommandPathOrSecret(t *testing.T) {
	const (
		user  = "alice"
		token = "ghp_supersecret"
		src   = "https://" + user + ":" + token + "@example.com/x"
	)

	dir := t.TempDir()
	fakeDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(fakeDir, 0o755); err != nil {
		t.Fatalf("create fake bin dir: %v", err)
	}
	// The fake git mimics git's own preamble (which names the destination) and
	// echoes the source URL, then exits 1.
	script := "#!/bin/sh\n" +
		"for arg in \"$@\"; do\n" +
		"\tdst=\"$arg\"\n" +
		"done\n" +
		"printf 'Cloning into %s...\\n' \"'$dst'\" >&2\n" +
		"printf \"fatal: unable to access '%s/': The requested URL returned error: 403\\n\" '" + src + "' >&2\n" +
		"exit 1\n"
	if err := os.WriteFile(filepath.Join(fakeDir, "git"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake git: %v", err)
	}
	t.Setenv("PATH", fakeDir)

	dst := filepath.Join(dir, "clone", "repo")
	err := Clone(context.Background(), src, dst)
	if err == nil {
		t.Fatal("Clone against a failing git = nil, want an error")
	}
	got := err.Error()
	t.Logf("clone error: %s", got)

	// "HTTP 403" (with the space git prints) is not in the marker set, so this
	// takes the fatal-line path and proves the fatal line alone is surfaced.
	const want = "fatal: unable to access 'https://example.com/x/': The requested URL returned error: 403"
	if got != want {
		t.Errorf("Clone error =\n  %q\nwant\n  %q", got, want)
	}
	assertNoLeak(t, got, src, dst)
	if strings.Contains(got, "core.hooksPath") || strings.Contains(got, "--no-recurse-submodules") {
		t.Errorf("git command line leaked into %q", got)
	}
}

// TestCloneNotFoundRemoteReportsGenericMessage drives Clone against a fake git
// whose stderr carries the not-found marker, the most common real failure.
func TestCloneNotFoundRemoteReportsGenericMessage(t *testing.T) {
	dir := t.TempDir()
	fakeDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(fakeDir, 0o755); err != nil {
		t.Fatalf("create fake bin dir: %v", err)
	}
	script := "#!/bin/sh\n" +
		"printf 'Cloning into ...\\n' >&2\n" +
		"printf 'remote: Repository not found.\\n' >&2\n" +
		"printf 'fatal: repository not found\\n' >&2\n" +
		"exit 128\n"
	if err := os.WriteFile(filepath.Join(fakeDir, "git"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake git: %v", err)
	}
	t.Setenv("PATH", fakeDir)

	src := "https://example.com/owner/repo.git"
	dst := filepath.Join(dir, "clone", "repo")
	err := Clone(context.Background(), src, dst)
	if err == nil {
		t.Fatal("Clone against a failing git = nil, want an error")
	}
	want := "could not clone " + src + ": repository not found or not accessible"
	if got := err.Error(); got != want {
		t.Errorf("Clone error =\n  %q\nwant\n  %q", got, want)
	}
}

// assertNoLeak fails the test if msg contains the source URL's credentials or
// the temporary destination path.
func assertNoLeak(t *testing.T, msg, source, dst string) {
	t.Helper()
	if i := strings.Index(source, "@"); i > 0 && strings.Contains(source, "://") {
		userinfo := source[strings.Index(source, "://")+3 : i]
		if userinfo != "" && strings.Contains(msg, userinfo) {
			t.Errorf("credential userinfo %q leaked into %q", userinfo, msg)
		}
	}
	if dst != "" && strings.Contains(msg, dst) {
		t.Errorf("temporary destination path %q leaked into %q", dst, msg)
	}
}
