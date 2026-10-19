// Package scanner runs Gitleaks and TruffleHog over a repository and converts
// their raw output into internal findings (CHAINFAULT_DOC.md §13, §16).
package scanner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/its-hixye/chainfault/internal/normalizer"
)

// Options configures one scan.
type Options struct {
	// RepoPath is the temporary clone to scan — never the user's own checkout.
	RepoPath string
	// Depth is "" or "full" for the whole history, otherwise a commit count.
	Depth string
	// Verify drops TruffleHog's --no-verification so it contacts the real
	// service. It is the only step of Chainfault that talks to the network
	// with a discovered secret, so it is opt-in.
	Verify bool
	// GitleaksConfig is the contents of the config.toml passed with -c.
	GitleaksConfig []byte
}

// Result is the outcome of one tool.
type Result struct {
	Name     string
	OK       bool
	Reason   string
	Findings []normalizer.Finding
	Duration time.Duration
}

// Status reports a tool's progress so the CLI can draw the live wait screen of
// CHAINFAULT_DOC.md §14. It is called at most twice per tool.
type Status struct {
	Name     string
	Finished bool
	OK       bool
	Duration time.Duration
}

// runTimeout bounds a single tool invocation.
const runTimeout = 60 * time.Minute

// Run executes both tools concurrently and waits for both.
//
// The two tools always run in parallel, never one after the other. One tool
// failing never stops the other; the failure is reported and the caller turns
// it into the "Scan incomplete" state and exit code 2 (CHAINFAULT_DOC.md §16).
func Run(ctx context.Context, opts Options, onStatus func(Status)) []Result {
	// A private work directory holds the Gitleaks config and the raw report.
	work, err := os.MkdirTemp("", "chainfault-work-")
	if err != nil {
		return []Result{
			{Name: normalizer.ToolGitleaks, Reason: fmt.Sprintf("cannot create temp dir: %v", err)},
			{Name: normalizer.ToolTruffleHog, Reason: fmt.Sprintf("cannot create temp dir: %v", err)},
		}
	}
	defer os.RemoveAll(work)

	configPath, err := writeSecretFile(filepath.Join(work, "config.toml"), opts.GitleaksConfig)
	if err != nil {
		reason := fmt.Sprintf("cannot write gitleaks config: %v", err)
		return []Result{
			{Name: normalizer.ToolGitleaks, Reason: reason},
			{Name: normalizer.ToolTruffleHog, Reason: reason},
		}
	}

	var wg sync.WaitGroup
	results := make([]Result, 2)
	wg.Add(2)
	go func() { defer wg.Done(); results[0] = runGitleaks(ctx, opts, work, configPath, onStatus) }()
	go func() { defer wg.Done(); results[1] = runTruffleHog(ctx, opts, onStatus) }()
	wg.Wait()

	return results
}

// runGitleaks runs Gitleaks over the repository history.
//
// The flags are fixed and every one of them is load-bearing (CHAINFAULT_DOC.md
// §13, §19, §21):
//
//	--exit-code 0           Gitleaks returns 1 when it *finds* something; without
//	                        this a successful scan would be read as a failure.
//	-c <config>             uses Chainfault's config so the repository's own
//	                        .gitleaks.toml cannot change the rules.
//	-i <empty dir>          points the ignore path at an empty directory.
//	--ignore-gitleaks-allow neutralizes a `gitleaks:allow` comment on a line.
//	                        Neither -c nor -i can neutralize the repository's
//	                        .gitleaksignore — that is why the scan runs on a
//	                        clone the file has been deleted from.
//	--no-redact (absent)    we mask secrets ourselves and show the head and
//	                        tail of each one; --redact would replace it all.
func runGitleaks(ctx context.Context, opts Options, work, configPath string, onStatus func(Status)) Result {
	res := Result{Name: normalizer.ToolGitleaks}
	start := time.Now()

	ignoreDir := filepath.Join(work, "empty-ignore")
	if err := os.MkdirAll(ignoreDir, 0o700); err != nil {
		res.Reason = fmt.Sprintf("cannot create ignore dir: %v", err)
		return res
	}
	reportPath := filepath.Join(work, "gitleaks-report.json")

	args := []string{
		"git", opts.RepoPath,
		"-f", "json",
		"-r", reportPath,
		"--exit-code", "0",
		"--no-banner",
		"-c", configPath,
		"-i", ignoreDir,
		"--ignore-gitleaks-allow",
	}
	if n, ok := depthToCount(opts.Depth); ok {
		// Gitleaks has no direct depth flag; it is expressed through git log.
		args = append(args, "--log-opts=-n "+strconv.Itoa(n))
	}

	code, stdout, stderr, runErr := execTool(ctx, "gitleaks", args)
	res.Duration = time.Since(start)
	if runErr != nil {
		res.Reason = fmt.Sprintf("could not run gitleaks: %v", runErr)
		report(onStatus, res)
		return res
	}
	if code != 0 {
		res.Reason = toolReason(code, strings.TrimSpace(stdout+"\n"+stderr))
		report(onStatus, res)
		return res
	}

	// The raw report holds full secrets: it is read once and deleted at once.
	raw, err := os.ReadFile(reportPath)
	os.Remove(reportPath)
	if err != nil {
		res.Reason = fmt.Sprintf("could not read gitleaks report: %v", err)
		report(onStatus, res)
		return res
	}

	findings, err := normalizer.ParseGitleaksJSON(raw)
	if err != nil {
		res.Reason = err.Error()
		report(onStatus, res)
		return res
	}
	res.Findings = findings
	res.OK = true
	report(onStatus, res)
	return res
}

// runTruffleHog runs TruffleHog over the repository history.
//
//	--no-verification          the scan itself must work without network access;
//	                           --verify drops this flag on purpose.
//	--no-update                mandatory: TruffleHog's self-updater otherwise
//	                           pulls a release before scanning, which breaks the
//	                           7-day policy of §8 and can exit 1 without ever
//	                           scanning.
//	--fail-on-scan-errors      TruffleHog returns 0 even when it hits an error,
//	                           so this is what makes a real failure visible.
//	--fail                     deliberately NOT passed: it turns findings into
//	                           exit 183 and would be indistinguishable from a
//	                           crash.
//	file://<absolute path>     TruffleHog rejects a bare local path
//	                           ("unsupported Git URI").
func runTruffleHog(ctx context.Context, opts Options, onStatus func(Status)) Result {
	res := Result{Name: normalizer.ToolTruffleHog}
	start := time.Now()

	abs, err := filepath.Abs(opts.RepoPath)
	if err != nil {
		res.Reason = fmt.Sprintf("cannot resolve repository path: %v", err)
		report(onStatus, res)
		return res
	}

	args := []string{
		"git", "file://" + abs,
		"--json",
		"--no-update",
		"--fail-on-scan-errors",
	}
	if !opts.Verify {
		args = append(args, "--no-verification")
	}
	if n, ok := depthToCount(opts.Depth); ok {
		args = append(args, "--max-depth", strconv.Itoa(n))
	}

	code, stdout, stderr, runErr := execTool(ctx, "trufflehog", args)
	res.Duration = time.Since(start)
	if runErr != nil {
		res.Reason = fmt.Sprintf("could not run trufflehog: %v", runErr)
		report(onStatus, res)
		return res
	}
	if code != 0 {
		res.Reason = toolReason(code, strings.TrimSpace(stderr))
		report(onStatus, res)
		return res
	}

	// TruffleHog's JSONL findings arrive on stdout; its info logs on stderr.
	findings, err := normalizer.ParseTruffleHogJSONL([]byte(stdout))
	if err != nil {
		res.Reason = err.Error()
		report(onStatus, res)
		return res
	}
	res.Findings = findings
	res.OK = true
	report(onStatus, res)
	return res
}

// execTool runs a helper tool and returns its exit code with both output
// streams kept apart.
//
// Keeping them apart matters: TruffleHog writes its JSONL findings to stdout
// while it logs to stderr, and merging the two streams risks splicing a JSON
// record in half. Callers that only want a diagnostic message join them.
func execTool(ctx context.Context, name string, args []string) (code int, stdout, stderr string, err error) {
	ctx, cancel := context.WithTimeout(ctx, runTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err = cmd.Run()
	stdout, stderr = outBuf.String(), errBuf.String()
	if err == nil {
		return 0, stdout, stderr, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode(), stdout, stderr, nil
	}
	return -1, stdout, stderr, err
}

// toolReason builds the one-line reason shown by the Failed Scanner Tools
// block. When the tool said nothing useful, the reason stays terse.
func toolReason(code int, output string) string {
	msg := strings.TrimSpace(output)
	if msg == "" {
		return fmt.Sprintf("exited with status %d", code)
	}
	// Only the tail matters; a failing scan can be noisy.
	if len(msg) > 400 {
		msg = "..." + msg[len(msg)-400:]
	}
	return fmt.Sprintf("exited with status %d: %s", code, msg)
}

// depthToCount turns the --depth option into a commit count. `full` (and the
// empty default) means no limit, in which case no depth flag is passed at all.
func depthToCount(depth string) (int, bool) {
	depth = strings.TrimSpace(strings.ToLower(depth))
	if depth == "" || depth == "full" {
		return 0, false
	}
	n, err := strconv.Atoi(depth)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// ValidDepth reports whether a --depth value is acceptable.
func ValidDepth(depth string) bool {
	if strings.EqualFold(strings.TrimSpace(depth), "full") {
		return true
	}
	_, ok := depthToCount(depth)
	return ok
}

func report(onStatus func(Status), res Result) {
	if onStatus != nil {
		onStatus(Status{Name: res.Name, Finished: true, OK: res.OK, Duration: res.Duration})
	}
}

// writeSecretFile writes content to path with 0600 permissions — owner only —
// and returns the path. Used for the Gitleaks config and any other artifact
// that must never be world-readable.
func writeSecretFile(path string, content []byte) (string, error) {
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return "", err
	}
	return path, nil
}
