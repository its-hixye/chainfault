package scanner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// installEdgeTool writes a small executable shell script named name into dir.
// The scripts use only the POSIX shell builtin printf, so the tests never need
// the real helper tools. It is deliberately separate from scanner_test.go's
// helpers so the two files stay independent.
func installEdgeTool(t *testing.T, dir, name, script string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
	return path
}

// TestWriteSecretFileUsesOwnerOnlyPermissions pins §19: config.toml holds
// secrets-adjacent material and must be readable by the owner only.
func TestWriteSecretFileUsesOwnerOnlyPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	content := []byte("[rules]\nsecret = \"value\"\n")

	got, err := writeSecretFile(path, content)
	if err != nil {
		t.Fatalf("writeSecretFile: %v", err)
	}
	if got != path {
		t.Errorf("returned path = %q, want %q", got, path)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("file mode = %04o, want 0600", perm)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if string(data) != string(content) {
		t.Errorf("content = %q, want %q", data, content)
	}
}

// TestWriteSecretFileReportsWriteFailure covers the error branch: a missing
// parent directory means the file cannot be created.
func TestWriteSecretFileReportsWriteFailure(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "does-not-exist", "config.toml")

	got, err := writeSecretFile(bad, []byte("x"))
	if err == nil {
		t.Fatal("want an error for an unwritable path, got nil")
	}
	if got != "" {
		t.Errorf("returned path = %q, want empty on failure", got)
	}
}

// TestExecToolKeepsStreamsApart proves execTool distinguishes stdout from
// stderr and surfaces a clean exit as code 0 with no error.
func TestExecToolKeepsStreamsApart(t *testing.T) {
	dir := t.TempDir()
	installEdgeTool(t, dir, "edge-ok", `printf 'out-line\n'
printf 'err-line\n' >&2
exit 0`)
	t.Setenv("PATH", dir)

	code, stdout, stderr, err := execTool(context.Background(), "edge-ok", nil)

	if err != nil {
		t.Fatalf("execTool: %v", err)
	}
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if stdout != "out-line\n" {
		t.Errorf("stdout = %q, want %q", stdout, "out-line\n")
	}
	if stderr != "err-line\n" {
		t.Errorf("stderr = %q, want %q", stderr, "err-line\n")
	}
}

// TestExecToolReturnsExitCodeNotError confirms a non-zero exit is reported as a
// code (not as a run error), which is how Run decides to build a toolReason.
func TestExecToolReturnsExitCodeNotError(t *testing.T) {
	dir := t.TempDir()
	installEdgeTool(t, dir, "edge-fail", `printf 'boom\n'
printf 'oops\n' >&2
exit 7`)
	t.Setenv("PATH", dir)

	code, stdout, stderr, err := execTool(context.Background(), "edge-fail", nil)

	if err != nil {
		t.Fatalf("execTool returned error for an exit-code failure: %v", err)
	}
	if code != 7 {
		t.Errorf("code = %d, want 7", code)
	}
	if stdout != "boom\n" {
		t.Errorf("stdout = %q, want %q", stdout, "boom\n")
	}
	if stderr != "oops\n" {
		t.Errorf("stderr = %q, want %q", stderr, "oops\n")
	}
}

// TestExecToolMissingCommandIsAStartError covers the "could not start" branch:
// when the binary cannot be found the error is NOT an *exec.ExitError, so
// execTool returns code -1 and the underlying ErrNotFound.
func TestExecToolMissingCommandIsAStartError(t *testing.T) {
	// PATH is narrowed to an empty directory so the name cannot resolve.
	t.Setenv("PATH", t.TempDir())

	code, stdout, stderr, err := execTool(context.Background(), "chainfault-no-such-tool-xyz", nil)

	if err == nil {
		t.Fatal("want a start error for a missing command, got nil")
	}
	if code != -1 {
		t.Errorf("code = %d, want -1", code)
	}
	if !errors.Is(err, exec.ErrNotFound) {
		t.Errorf("error = %v, want it to wrap exec.ErrNotFound", err)
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		t.Errorf("error = %v, want a start error, not an *exec.ExitError", err)
	}
	if stdout != "" || stderr != "" {
		t.Errorf("stdout = %q, stderr = %q, want both empty", stdout, stderr)
	}
}

// TestToolReason is table-driven over the exact reason strings Run emits for a
// failed tool: terse when silent, trimmed otherwise, and tail-only when noisy.
func TestToolReason(t *testing.T) {
	tail400 := strings.Repeat("B", 400)
	exact400 := strings.Repeat("x", 400)

	cases := []struct {
		name   string
		code   int
		output string
		want   string
	}{
		{
			name:   "empty output is terse",
			code:   7,
			output: "",
			want:   "exited with status 7",
		},
		{
			name:   "whitespace-only output is terse",
			code:   7,
			output: "  \n\t ",
			want:   "exited with status 7",
		},
		{
			name:   "short output is trimmed and appended",
			code:   3,
			output: "  spaced out  ",
			want:   "exited with status 3: spaced out",
		},
		{
			name:   "exactly 400 characters is not truncated",
			code:   1,
			output: exact400,
			want:   "exited with status 1: " + exact400,
		},
		{
			name:   "long output keeps only the last 400 characters",
			code:   2,
			output: strings.Repeat("A", 50) + tail400,
			want:   "exited with status 2: ..." + tail400,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := toolReason(tc.code, tc.output); got != tc.want {
				t.Errorf("toolReason(%d, %d-char output) = %q, want %q", tc.code, len(tc.output), got, tc.want)
			}
		})
	}
}
