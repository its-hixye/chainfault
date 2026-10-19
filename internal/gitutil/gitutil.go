// Package gitutil wraps the git operations Chainfault needs: cloning into a
// temporary directory, counting commits, and reading a file's contents at a
// given commit (CHAINFAULT_DOC.md §6, §21).
package gitutil

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// repoTimeout bounds every git invocation so a hung git cannot hang a scan.
const repoTimeout = 2 * time.Minute

// hidingFiles are the files a scanned repository could use to hide its own
// secrets from Gitleaks. They are deleted from the temporary clone before any
// scanner runs, because `.gitleaksignore` cannot be disabled by any flag
// (CHAINFAULT_DOC.md §6, §19).
var hidingFiles = []string{".gitleaks.toml", ".gitleaksignore"}

// cmdError is a failed git invocation. It carries the raw stderr separately
// from the human-facing message so Clone can classify the failure (and redact
// credentials) before anything is shown to the user.
type cmdError struct {
	args   []string
	stderr string
	err    error
}

func (e *cmdError) Error() string {
	msg := strings.TrimSpace(e.stderr)
	if msg == "" {
		msg = e.err.Error()
	}
	return fmt.Sprintf("git %s: %s", strings.Join(e.args, " "), msg)
}

func (e *cmdError) Unwrap() error { return e.err }

// run executes a git command and returns its stdout. On failure it returns a
// *cmdError holding the raw stderr.
func run(ctx context.Context, dir string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, repoTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	// Never let a scanned repository's git config leak into our own run.
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=true")

	var out, errOut strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	if err := cmd.Run(); err != nil {
		return out.String(), &cmdError{args: args, stderr: errOut.String(), err: err}
	}
	return out.String(), nil
}

// IsURL reports whether target is a remote URL rather than a local path.
func IsURL(target string) bool {
	return strings.Contains(target, "://")
}

// IsHttpsURL reports whether target is an https:// URL. Chainfault accepts
// https:// clone URLs only (CHAINFAULT_DOC.md §19).
func IsHttpsURL(target string) bool {
	return strings.HasPrefix(strings.ToLower(target), "https://")
}

// IsRepo reports whether dir is the root of a git working tree.
func IsRepo(dir string) bool {
	if dir == "" {
		return false
	}
	if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
		return true
	}
	out, err := run(context.Background(), dir, "rev-parse", "--is-inside-work-tree")
	return err == nil && strings.TrimSpace(out) == "true"
}

// HasCommits reports whether HEAD resolves to at least one commit.
func HasCommits(dir string) bool {
	out, err := run(context.Background(), dir, "rev-list", "--count", "HEAD")
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(strings.TrimSpace(out))
	return err == nil && n > 0
}

// userinfoInURL matches the `user:token@` part of any URL-shaped token so it
// can be stripped before an error is shown. Credentials in a clone URL must
// never reach the terminal or a log file.
var userinfoInURL = regexp.MustCompile(`(?i)([a-z][a-z0-9+.\-]*://)[^/\s@]*@`)

// redactCredentials removes any `user:token@` userinfo from URLs appearing in
// text, so `https://user:token@example.com/x` becomes `https://example.com/x`.
// Text without URLs is returned unchanged.
func redactCredentials(text string) string {
	return userinfoInURL.ReplaceAllString(text, "$1")
}

// notFoundMarkers are the case-insensitive stderr markers that mean the
// repository is missing, private, or otherwise not reachable. They all collapse
// into one message, because "not found" and "wrong credentials" are
// indistinguishable from the client side and must not be told apart to an
// attacker probing which repositories exist.
var notFoundMarkers = []string{
	"repository not found",
	"not found",
	"does not exist",
	"authentication failed",
	"could not read username",
	"could not read password",
	"permission denied",
	"access denied",
	"http 401",
	"http 403",
	"http 404",
}

// looksNotFound reports whether stderr carries a not-found or auth marker.
func looksNotFound(stderr string) bool {
	lower := strings.ToLower(stderr)
	for _, marker := range notFoundMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// lastFatalLine returns the last line of git's stderr that begins with
// "fatal:", trimmed, or "" when there is none. Everything before it
// ("Cloning into ...", progress chatter, advice text) is noise that leaks the
// temporary destination path and must not be shown.
func lastFatalLine(stderr string) string {
	lines := strings.Split(strings.ReplaceAll(stderr, "\r\n", "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		line := strings.TrimSpace(lines[i])
		if strings.HasPrefix(strings.ToLower(line), "fatal:") {
			return line
		}
	}
	return ""
}

// cloneError turns a failed clone into a short, safe message. It is pure, so
// it can be table-tested without running git.
//
// The result never contains the git command line, the temporary destination
// path (dst), or git's stderr preamble, and it never contains credentials that
// were embedded in source or echoed by git.
func cloneError(source, dst, stderr string) error {
	safe := redactCredentials(source)
	if looksNotFound(stderr) {
		return fmt.Errorf("could not clone %s: repository not found or not accessible", safe)
	}
	fatal := redactCredentials(lastFatalLine(stderr))
	// git sometimes repeats the destination path in its fatal line; the temp
	// clone directory is an implementation detail and must not be printed.
	if fatal != "" && dst != "" {
		fatal = strings.ReplaceAll(fatal, dst, "<destination>")
	}
	if fatal != "" {
		// "Show only git's last fatal line" is deliberate: the URL is already in
		// most fatal lines, and repeating it adds noise without adding a cause.
		return errors.New(fatal)
	}
	return fmt.Errorf("could not clone %s: git clone failed", safe)
}

// Clone copies a repository into dst. source may be an https:// URL or a local
// path; either way the original is never touched.
//
// Cloning is how the "never scan in place" rule of CHAINFAULT_DOC.md §6 is
// enforced. Hooks are disabled and submodules are not fetched so a hostile
// repository cannot execute code or pull in more repositories.
//
// A failed clone reports a short, credential-free message; see cloneError.
func Clone(ctx context.Context, source, dst string) error {
	if IsURL(source) {
		if !IsHttpsURL(source) {
			return fmt.Errorf("only https:// clone URLs are accepted, got %q", redactCredentials(source))
		}
	} else {
		abs, err := filepath.Abs(source)
		if err != nil {
			return fmt.Errorf("resolve %q: %w", source, err)
		}
		info, err := os.Stat(abs)
		if err != nil {
			return fmt.Errorf("cannot read %q: %w", source, err)
		}
		if !info.IsDir() {
			return fmt.Errorf("%q is not a directory", source)
		}
		source = abs
	}

	args := []string{"-c", "core.hooksPath=/dev/null", "clone", "--quiet", "--no-recurse-submodules"}
	args = append(args, source, dst)
	if _, err := run(ctx, "", args...); err != nil {
		var ce *cmdError
		if errors.As(err, &ce) {
			return cloneError(source, dst, ce.stderr)
		}
		return fmt.Errorf("could not clone %s: %w", redactCredentials(source), err)
	}
	return nil
}

// StripHidingFiles deletes the files a repository could use to suppress its own
// findings. It is a no-op when they are absent.
func StripHidingFiles(dir string) error {
	var firstErr error
	for _, name := range hidingFiles {
		p := filepath.Join(dir, name)
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = fmt.Errorf("remove %s: %w", p, err)
		}
	}
	return firstErr
}

// CommitCount returns the number of commits reachable from HEAD, i.e. how many
// commits the scan covered.
func CommitCount(ctx context.Context, dir string) (int, error) {
	out, err := run(ctx, dir, "rev-list", "--count", "HEAD")
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		return 0, fmt.Errorf("unexpected rev-list output %q", strings.TrimSpace(out))
	}
	return n, nil
}

// ShowLines returns the contents of path as it existed at commit, split into
// lines. Code context is always read from history, never from the current
// working tree (CHAINFAULT_DOC.md §15) — this applies to HEAD findings too.
func ShowLines(ctx context.Context, dir, commit, filePath string) ([]string, error) {
	if commit == "" || filePath == "" {
		return nil, errors.New("commit and path are required")
	}
	out, err := run(ctx, dir, "show", commit+":"+filePath)
	if err != nil {
		return nil, err
	}
	return SplitLines(out), nil
}

// SplitLines splits file content into lines without inventing a trailing empty
// line for content that ends in a newline.
func SplitLines(content string) []string {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	if content == "" {
		return nil
	}
	lines := strings.Split(content, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines
}

// HeadInfo returns the short HEAD hash and the current branch name.
func HeadInfo(ctx context.Context, dir string) (hash, branch string, err error) {
	out, err := run(ctx, dir, "rev-parse", "--short", "HEAD")
	if err != nil {
		return "", "", err
	}
	hash = strings.TrimSpace(out)

	out, err = run(ctx, dir, "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		// A detached HEAD is fine; fall back to an empty branch name.
		return hash, "", nil
	}
	if b := strings.TrimSpace(out); b != "HEAD" {
		branch = b
	}
	return hash, branch, nil
}
