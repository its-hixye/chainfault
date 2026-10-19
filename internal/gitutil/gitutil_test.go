package gitutil

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// git runs a git command inside dir and fails the test on error.
func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	// A scanned repository's own config must never influence our fixtures.
	cmd.Env = append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_AUTHOR_NAME=Test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test", "GIT_COMMITTER_EMAIL=test@example.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s (in %s): %v\n%s", strings.Join(args, " "), dir, err, out)
	}
	return strings.TrimSpace(string(out))
}

// newRepo creates an empty git repository (no commits) under root.
func newRepo(t *testing.T, root, name string) string {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
	git(t, dir, "init", "-q", "-b", "main")
	return dir
}

// commit writes content to name in repo and commits it, returning the commit hash.
func commit(t *testing.T, repo, name, content, msg string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	git(t, repo, "add", "-A")
	git(t, repo, "commit", "-q", "-m", msg)
	return git(t, repo, "rev-parse", "HEAD")
}

// repoWithCommits returns a repository holding n commits touching file.txt.
func repoWithCommits(t *testing.T, n int) string {
	t.Helper()
	repo := newRepo(t, t.TempDir(), "repo")
	for i := 1; i <= n; i++ {
		commit(t, repo, "file.txt", "line "+strings.Repeat("x", i)+"\n", "commit "+string(rune('0'+i)))
	}
	return repo
}

// ---------------------------------------------------------------------------
// IsURL / IsHttpsURL
// ---------------------------------------------------------------------------

func TestIsURL(t *testing.T) {
	cases := map[string]bool{
		"https://github.com/a/b.git": true,
		"http://github.com/a/b.git":  true,
		"git://github.com/a/b.git":   true,
		"ssh://git@github.com/a/b":   true,
		"file:///tmp/repo":           true,
		"/tmp/repo":                  false,
		"repo":                       false,
		"":                           false,
	}
	for target, want := range cases {
		if got := IsURL(target); got != want {
			t.Errorf("IsURL(%q) = %v, want %v", target, got, want)
		}
	}
}

func TestIsHttpsURL(t *testing.T) {
	// Only https:// is accepted (CHAINFAULT_DOC.md §19); every other scheme
	// is rejected.
	accepted := []string{"https://github.com/a/b.git", "HTTPS://github.com/a/b"}
	for _, target := range accepted {
		if !IsHttpsURL(target) {
			t.Errorf("IsHttpsURL(%q) = false, want true", target)
		}
	}
	rejected := []string{
		"http://github.com/a/b.git",
		"git://github.com/a/b.git",
		"ssh://git@github.com/a/b",
		"file:///tmp/repo",
		"ftp://x",
		"not a url",
		"/tmp/repo",
		"",
	}
	for _, target := range rejected {
		if IsHttpsURL(target) {
			t.Errorf("IsHttpsURL(%q) = true, want false", target)
		}
	}
}

// ---------------------------------------------------------------------------
// Clone
// ---------------------------------------------------------------------------

func TestCloneLocalRepoLeavesOriginalUntouched(t *testing.T) {
	root := t.TempDir()
	src := newRepo(t, root, "src")
	commit(t, src, "marker.txt", "do-not-touch\n", "add marker")

	dst := filepath.Join(root, "dst")
	if err := Clone(context.Background(), src, dst); err != nil {
		t.Fatalf("Clone: %v", err)
	}

	// The clone is a real git working tree.
	if _, err := os.Stat(filepath.Join(dst, ".git")); err != nil {
		t.Errorf("clone has no .git: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dst, "marker.txt"))
	if err != nil {
		t.Fatalf("marker missing from clone: %v", err)
	}
	if string(got) != "do-not-touch\n" {
		t.Errorf("clone marker = %q, want %q", got, "do-not-touch\n")
	}

	// The original is byte-for-byte unchanged.
	orig, err := os.ReadFile(filepath.Join(src, "marker.txt"))
	if err != nil || string(orig) != "do-not-touch\n" {
		t.Errorf("original marker = %q (%v), want unchanged", orig, err)
	}
	if n := git(t, src, "status", "--porcelain"); n != "" {
		t.Errorf("original repo is dirty after Clone: %q", n)
	}
}

func TestCloneRejectsNonHTTPSURLs(t *testing.T) {
	// Anything containing "://" is treated as a URL and must be https://.
	// The check happens before any git process runs, so these never touch the
	// network.
	for _, target := range []string{
		"http://github.com/a/b.git",
		"git://github.com/a/b.git",
		"ssh://git@github.com/a/b",
		"file:///tmp/repo",
		"ftp://x",
		"not a url",
	} {
		dst := filepath.Join(t.TempDir(), "dst")
		err := Clone(context.Background(), target, dst)
		if target == "not a url" {
			// Not a URL: it is resolved as a local path and fails because
			// nothing exists there.
			if err == nil {
				t.Errorf("Clone(%q) = nil, want an error", target)
			}
			continue
		}
		if err == nil {
			t.Errorf("Clone(%q) = nil, want an error", target)
			continue
		}
		if _, statErr := os.Stat(dst); statErr == nil {
			t.Errorf("Clone(%q) created %s despite failing", target, dst)
		}
	}

	// The accepted scheme is https:// — asserting the gate itself, since a real
	// https clone would need the network.
	if !IsHttpsURL("https://github.com/a/b.git") {
		t.Error("https:// must be the accepted clone scheme")
	}
}

func TestCloneRejectsMissingAndNonDirectorySources(t *testing.T) {
	root := t.TempDir()

	missing := filepath.Join(root, "nope")
	if err := Clone(context.Background(), missing, filepath.Join(root, "dst1")); err == nil {
		t.Error("Clone of a missing path = nil, want an error")
	}

	file := filepath.Join(root, "a-file")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := Clone(context.Background(), file, filepath.Join(root, "dst2")); err == nil {
		t.Error("Clone of a file = nil, want an error")
	}
}

// ---------------------------------------------------------------------------
// StripHidingFiles
// ---------------------------------------------------------------------------

func TestStripHidingFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{".gitleaks.toml", ".gitleaksignore", "keep.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	if err := StripHidingFiles(dir); err != nil {
		t.Fatalf("StripHidingFiles: %v", err)
	}
	for _, name := range []string{".gitleaks.toml", ".gitleaksignore"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Errorf("%s still exists after StripHidingFiles", name)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "keep.txt")); err != nil {
		t.Errorf("StripHidingFiles deleted an unrelated file: %v", err)
	}
}

func TestStripHidingFilesIsANoOpWhenAbsent(t *testing.T) {
	dir := t.TempDir()
	if err := StripHidingFiles(dir); err != nil {
		t.Errorf("StripHidingFiles on a clean dir = %v, want nil", err)
	}
	// A second call is still a no-op.
	if err := StripHidingFiles(dir); err != nil {
		t.Errorf("second StripHidingFiles = %v, want nil", err)
	}
}

// ---------------------------------------------------------------------------
// IsRepo / HasCommits / CommitCount
// ---------------------------------------------------------------------------

func TestIsRepo(t *testing.T) {
	root := t.TempDir()

	repo := newRepo(t, root, "repo")
	if !IsRepo(repo) {
		t.Error("IsRepo on a git dir = false, want true")
	}

	plain := filepath.Join(root, "plain")
	if err := os.MkdirAll(plain, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if IsRepo(plain) {
		t.Error("IsRepo on a non-git dir = true, want false")
	}

	if IsRepo("") {
		t.Error("IsRepo(\"\") = true, want false")
	}
}

func TestHasCommits(t *testing.T) {
	root := t.TempDir()

	withCommits := repoWithCommits(t, 1)
	if !HasCommits(withCommits) {
		t.Error("HasCommits on a repo with one commit = false, want true")
	}

	empty := newRepo(t, root, "empty")
	if HasCommits(empty) {
		t.Error("HasCommits on a freshly initialized repo = true, want false")
	}

	plain := filepath.Join(root, "plain")
	os.MkdirAll(plain, 0o755)
	if HasCommits(plain) {
		t.Error("HasCommits on a non-git dir = true, want false")
	}
}

func TestCommitCount(t *testing.T) {
	repo := repoWithCommits(t, 3)
	n, err := CommitCount(context.Background(), repo)
	if err != nil {
		t.Fatalf("CommitCount: %v", err)
	}
	if n != 3 {
		t.Errorf("CommitCount = %d, want 3", n)
	}
}

func TestCommitCountFailsOutsideARepository(t *testing.T) {
	plain := filepath.Join(t.TempDir(), "plain")
	if err := os.MkdirAll(plain, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := CommitCount(context.Background(), plain); err == nil {
		t.Error("CommitCount outside a repository = nil error, want an error")
	}
	if _, err := CommitCount(context.Background(), filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Error("CommitCount in a missing dir = nil error, want an error")
	}
}

// ---------------------------------------------------------------------------
// ShowLines
// ---------------------------------------------------------------------------

func TestShowLinesReadsHistoryNotTheWorkingTree(t *testing.T) {
	repo := newRepo(t, t.TempDir(), "repo")
	first := commit(t, repo, "app.txt", "v1\nline two\n", "first")
	commit(t, repo, "app.txt", "v2\nline two\n", "second")

	// The working tree is v2 ...
	head, err := os.ReadFile(filepath.Join(repo, "app.txt"))
	if err != nil {
		t.Fatalf("read working tree: %v", err)
	}
	if string(head) != "v2\nline two\n" {
		t.Fatalf("working tree = %q, want v2", head)
	}

	// ... but ShowLines at the first commit must return v1 (CHAINFAULT_DOC.md §15).
	lines, err := ShowLines(context.Background(), repo, first, "app.txt")
	if err != nil {
		t.Fatalf("ShowLines: %v", err)
	}
	if len(lines) != 2 || lines[0] != "v1" || lines[1] != "line two" {
		t.Errorf("ShowLines at first commit = %q, want [v1 line two]", lines)
	}
	for _, l := range lines {
		if strings.Contains(l, "v2") {
			t.Errorf("ShowLines returned working-tree content: %q", lines)
		}
	}
}

func TestShowLinesRequiresCommitAndPath(t *testing.T) {
	repo := repoWithCommits(t, 1)
	hash := git(t, repo, "rev-parse", "HEAD")

	if _, err := ShowLines(context.Background(), repo, "", "file.txt"); err == nil {
		t.Error("ShowLines with an empty commit = nil error, want an error")
	}
	if _, err := ShowLines(context.Background(), repo, hash, ""); err == nil {
		t.Error("ShowLines with an empty path = nil error, want an error")
	}
	if _, err := ShowLines(context.Background(), repo, hash, "not-there.txt"); err == nil {
		t.Error("ShowLines with a missing file = nil error, want an error")
	}
}

// ---------------------------------------------------------------------------
// SplitLines
// ---------------------------------------------------------------------------

func TestSplitLines(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"one line without newline", "a", []string{"a"}},
		{"one line with newline", "a\n", []string{"a"}},
		{"two lines", "a\nb\n", []string{"a", "b"}},
		{"no trailing newline", "a\nb", []string{"a", "b"}},
		{"blank line in the middle", "a\n\nb\n", []string{"a", "", "b"}},
		{"crlf", "a\r\nb\r\n", []string{"a", "b"}},
	}
	for _, c := range cases {
		got := SplitLines(c.in)
		if len(got) != len(c.want) {
			t.Errorf("%s: SplitLines(%q) = %q, want %q", c.name, c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: SplitLines(%q) = %q, want %q", c.name, c.in, got, c.want)
				break
			}
		}
	}
}

func TestSplitLinesDoesNotInventATrailingEmptyLine(t *testing.T) {
	lines := SplitLines("alpha\nbeta\n")
	if n := len(lines); n != 2 {
		t.Fatalf("len(SplitLines) = %d (%q), want 2", n, lines)
	}
	if lines[len(lines)-1] == "" {
		t.Error("SplitLines kept a trailing empty line for content ending in a newline")
	}
}

// ---------------------------------------------------------------------------
// HeadInfo
// ---------------------------------------------------------------------------

func TestHeadInfo(t *testing.T) {
	repo := newRepo(t, t.TempDir(), "repo")
	hash := commit(t, repo, "file.txt", "hello\n", "first")

	gotHash, gotBranch, err := HeadInfo(context.Background(), repo)
	if err != nil {
		t.Fatalf("HeadInfo: %v", err)
	}
	if gotHash != hash[:7] && gotHash != hash {
		t.Errorf("HeadInfo hash = %q, want the short hash %q", gotHash, hash[:7])
	}
	if len(gotHash) != 7 {
		t.Errorf("HeadInfo hash = %q, want 7 characters", gotHash)
	}
	if gotBranch != "main" {
		t.Errorf("HeadInfo branch = %q, want %q", gotBranch, "main")
	}
}

func TestHeadInfoFailsOutsideARepository(t *testing.T) {
	plain := filepath.Join(t.TempDir(), "plain")
	if err := os.MkdirAll(plain, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, _, err := HeadInfo(context.Background(), plain); err == nil {
		t.Error("HeadInfo outside a repository = nil error, want an error")
	}
}
