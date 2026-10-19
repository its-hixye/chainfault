// Command chainfault scans a git repository for leaked secrets by running
// Gitleaks and TruffleHog, merging their findings into one de-duplicated list,
// scoring each secret from 1 to 10 and reporting the results to the terminal
// and optionally to a self-contained HTML file.
//
// See CHAINFAULT_DOC.md for the full specification.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/its-hixye/chainfault/internal/gitutil"
	"github.com/its-hixye/chainfault/internal/merger"
	"github.com/its-hixye/chainfault/internal/normalizer"
	"github.com/its-hixye/chainfault/internal/reporter"
	"github.com/its-hixye/chainfault/internal/scanner"
	"github.com/its-hixye/chainfault/internal/updater"
	"github.com/its-hixye/chainfault/templates"
)

// version is the Chainfault release without its leading "v" (CHAINFAULT_DOC.md
// §26). It is a variable rather than a constant so a release build can stamp
// its own number in:
//
//	go build -ldflags "-X main.version=1.2.3" ./cmd/chainfault
//
// The "v" is added when printing, so an injected value can never lose it.
var version = "0.1.0"

// requiredTools are the helper tools `scan` drives.
var requiredTools = []string{normalizer.ToolGitleaks, normalizer.ToolTruffleHog}

// Exit codes (CHAINFAULT_DOC.md §16). Failure always wins over findings.
const (
	exitClean      = 0 // both tools ran to completion, no secrets found
	exitFindings   = 1 // both tools ran to completion, secrets found
	exitIncomplete = 2 // a tool failed, or the input was invalid
)

// errInterrupted marks a scan the user stopped with Ctrl+C.
var errInterrupted = errors.New("interrupted")

// interruptedMessage reports the cleanup that happened after Ctrl+C. Only URL
// inputs trigger the clone-specific sentence; a local path gets the minimal
// message. Both are printed to stderr by cmdScan.
func interruptedMessage(target string) string {
	if gitutil.IsURL(target) {
		return "\nInterrupted — the temporary clone was deleted."
	}
	return "\nInterrupted"
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return exitIncomplete
	}
	switch args[0] {
	case "scan":
		return cmdScan(args[1:])
	case "doctor":
		return cmdDoctor(args[1:])
	case "version", "--version", "-v":
		fmt.Printf("chainfault v%s\n", version)
		return exitClean
	case "help", "--help", "-h":
		usage(os.Stdout)
		return exitClean
	default:
		fmt.Fprintf(os.Stderr, "chainfault: unknown command %q\n\n", args[0])
		usage(os.Stderr)
		return exitIncomplete
	}
}

// ---------------------------------------------------------------------------
// doctor
// ---------------------------------------------------------------------------

// cmdDoctor prints the path and version of both helper tools. It installs
// nothing; when a tool is missing it also prints where to get it
// (CHAINFAULT_DOC.md §12).
func cmdDoctor(args []string) int {
	if len(args) > 0 {
		fmt.Fprintf(os.Stderr, "chainfault doctor: unexpected argument %q\n", args[0])
		return exitIncomplete
	}
	allOK := true
	for _, name := range requiredTools {
		st := updater.Lookup(name)
		if st.OK {
			fmt.Printf("✔ %-12s %s (%s)\n", st.Name, st.Version, st.Path)
			continue
		}
		allOK = false
		fmt.Printf("✖ %-12s %s\n", st.Name, st.Reason)
		if page := updater.ReleasesPage(name); page != "" {
			fmt.Printf("  %-12s install it from %s\n", "", page)
		}
	}
	if !allOK {
		fmt.Fprintln(os.Stderr, "\nBoth gitleaks and trufflehog must be installed and on PATH for a scan to run.")
		return exitIncomplete
	}
	return exitClean
}

// ---------------------------------------------------------------------------
// scan
// ---------------------------------------------------------------------------

// scanFlags holds the parsed options of the scan command (CHAINFAULT_DOC.md §13).
type scanFlags struct {
	depth  string
	html   bool
	output string
	verify bool
	reveal bool
}

// scanFlagSet builds the flag set from the same option definitions that render
// the help, so descriptions and names cannot drift apart.
func scanFlagSet(f *scanFlags) *flag.FlagSet {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	for _, opt := range scanOptions {
		switch opt.Flag {
		case "depth":
			fs.StringVar(&f.depth, opt.Flag, "full", opt.Description)
		case "html":
			fs.BoolVar(&f.html, opt.Flag, false, opt.Description)
		case "output":
			fs.StringVar(&f.output, opt.Flag, "", opt.Description)
		case "verify":
			fs.BoolVar(&f.verify, opt.Flag, false, opt.Description)
		case "reveal":
			fs.BoolVar(&f.reveal, opt.Flag, false, opt.Description)
		}
	}
	return fs
}

func cmdScan(args []string) int {
	// `scan --help` is a successful request for help, not a scan with a
	// misspelled target. -h stays an alias for the same thing.
	if hasHelpFlag(args) {
		scanUsage(os.Stdout)
		return exitClean
	}
	// Go's flag package accepts -depth as well as --depth. The CLI documents
	// only the double-dash form, so reject the single-dash long flags with a
	// precise correction instead of silently accepting them.
	if err := rejectSingleDashLongFlags(args); err != nil {
		fmt.Fprintf(os.Stderr, "chainfault scan: %v\n", err)
		return exitIncomplete
	}

	var f scanFlags
	fs := scanFlagSet(&f)
	fs.SetOutput(os.Stderr)

	// The target may be written before or after the options, because that is
	// how people naturally type `chainfault scan <path> --html`; Go's flag
	// package alone would stop at the first positional argument.
	target, extra := splitTarget(args)
	if err := fs.Parse(extra); err != nil {
		return exitIncomplete
	}
	rest := fs.Args()
	if target == "" {
		fmt.Fprintln(os.Stderr, "chainfault scan: missing <path-or-url>")
		return exitIncomplete
	}
	if len(rest) > 0 {
		fmt.Fprintf(os.Stderr, "chainfault scan: unexpected argument %q\n", rest[0])
		return exitIncomplete
	}

	if !scanner.ValidDepth(f.depth) {
		fmt.Fprintf(os.Stderr, "chainfault scan: --depth must be a positive number or \"full\", got %q\n", f.depth)
		return exitIncomplete
	}

	outputPath, err := resolveOutput(f, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "chainfault scan: %v\n", err)
		return exitIncomplete
	}

	// Ctrl+C must stop the scan and still delete the temporary clone, so the
	// whole run sits under a cancellable context (CHAINFAULT_DOC.md §16).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	code, err := runScan(ctx, target, f, outputPath, reporter.Style{Color: colorEnabled(os.Stdout)})
	if err != nil {
		// A cancelled context means Ctrl+C, whichever step happened to be
		// running: report the interruption, not a git or tool error.
		if errors.Is(err, errInterrupted) || ctx.Err() != nil {
			fmt.Fprintln(os.Stderr, interruptedMessage(target))
			return exitIncomplete
		}
		fmt.Fprintf(os.Stderr, "chainfault scan: %v\n", err)
		return exitIncomplete
	}
	return code
}

// hasHelpFlag reports whether the user explicitly asked for scan help. It is
// checked before parsing so `chainfault scan --help` always exits successfully,
// even when the rest of the argument list is incomplete.
func hasHelpFlag(args []string) bool {
	for _, a := range args {
		if a == "-h" || a == "--help" {
			return true
		}
	}
	return false
}

// rejectSingleDashLongFlags rejects -depth, -html, -output, -reveal and -verify.
// The flag package would accept them, but the documented spelling uses two
// dashes; a one-dash long option is almost always a typo, so say so explicitly.
func rejectSingleDashLongFlags(args []string) error {
	for _, a := range args {
		if !strings.HasPrefix(a, "-") || strings.HasPrefix(a, "--") {
			continue
		}
		name := strings.TrimPrefix(a, "-")
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		for _, opt := range scanOptions {
			if name == opt.Flag {
				return fmt.Errorf("use --%s instead of -%s", name, name)
			}
		}
	}
	return nil
}

// valueFlags are the scan options that take a separate value argument.
var valueFlags = map[string]bool{"--depth": true, "--output": true}

// splitTarget pulls the single positional argument out of the argument list so
// the options may appear on either side of it. The value of a space-separated
// flag is never mistaken for the target.
func splitTarget(args []string) (target string, flags []string) {
	flags = make([]string, 0, len(args))
	expectValue := false
	for _, a := range args {
		switch {
		case expectValue:
			expectValue = false
		case valueFlags[a]:
			expectValue = true
		case target == "" && !strings.HasPrefix(a, "-"):
			target = a
			continue
		}
		flags = append(flags, a)
	}
	return target, flags
}

// runScan performs the ten steps of CHAINFAULT_DOC.md §10 and returns the
// process exit code. Cleanup is registered with defer so it runs on every
// return path, including a Ctrl+C cancellation.
func runScan(ctx context.Context, target string, f scanFlags, outputPath string, style reporter.Style) (int, error) {
	start := time.Now()

	// 1. Check the helper tools. This happens before any work so a missing tool
	//    fails fast.
	// missingToolsError already names every missing tool and its Releases page;
	// printing a second status row here would duplicate that information.
	if _, err := updater.Ensure(ctx, requiredTools); err != nil {
		return exitIncomplete, err
	}

	// 2. Validate the target: not a git repository, or an empty one, is a hard
	//    error before any clone or scan happens (CHAINFAULT_DOC.md §16).
	if err := validateTarget(target); err != nil {
		return exitIncomplete, err
	}

	projectName := projectNameFor(target)
	fmt.Printf("Chainfault scanning %s\n", projectName)

	// 3. Scan a temporary clone, never the user's checkout (CHAINFAULT_DOC.md §6).
	cloneDir, err := os.MkdirTemp("", "chainfault-scan-")
	if err != nil {
		return exitIncomplete, fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(cloneDir)

	repoDir := filepath.Join(cloneDir, "repo")
	prog := newProgress(style.Color)
	// The animation goroutine is stopped on every return path, so a failed or
	// interrupted scan can never leave it running.
	defer prog.stopAnimation()
	prog.cloneStep(target)
	// Both scanners are registered up front so the wait screen shows them in
	// their "waiting" state until each one actually starts.
	prog.add(normalizer.ToolGitleaks)
	prog.add(normalizer.ToolTruffleHog)
	if err := gitutil.Clone(ctx, target, repoDir); err != nil {
		prog.clear()
		return exitIncomplete, err
	}
	prog.cloneDone()
	if !gitutil.HasCommits(repoDir) {
		prog.clear()
		return exitIncomplete, fmt.Errorf("%s has no commits — nothing to scan", target)
	}

	// 4. Delete the two files a repository could use to hide its own secrets.
	//    No flag can neutralize .gitleaksignore, so the clone is the only
	//    place this can be enforced (CHAINFAULT_DOC.md §6, §19).
	if err := gitutil.StripHidingFiles(repoDir); err != nil {
		prog.clear()
		return exitIncomplete, err
	}

	commitCount, err := gitutil.CommitCount(ctx, repoDir)
	if err != nil {
		commitCount = 0
	}
	headHash, branch, err := gitutil.HeadInfo(ctx, repoDir)
	if err != nil {
		headHash, branch = "", ""
	}

	// 5. Run both scanners in parallel and wait for both.
	prog.startScanner(normalizer.ToolGitleaks)
	prog.startScanner(normalizer.ToolTruffleHog)
	results := scanner.Run(ctx, scanner.Options{
		RepoPath:       repoDir,
		Depth:          f.depth,
		Verify:         f.verify,
		GitleaksConfig: []byte(templates.GitleaksConfig),
	}, prog.scannerStatus)
	// A cancelled scan must not leave the rows looking like ordinary failures:
	// label them interrupted before painting the final frame.
	if ctx.Err() != nil {
		prog.interrupt()
	}
	prog.done()
	fmt.Println()

	if ctx.Err() != nil {
		return exitIncomplete, errInterrupted
	}

	// 6. Merge the duplicates, then score, classify and enrich.
	var all []normalizer.Finding
	toolStatus := make([]reporter.ToolStatus, 0, len(results))
	var failed []reporter.ToolStatus
	for _, r := range results {
		toolStatus = append(toolStatus, reporter.ToolStatus{Name: r.Name, OK: r.OK, Reason: r.Reason})
		if !r.OK {
			failed = append(failed, reporter.ToolStatus{Name: r.Name, Reason: r.Reason})
			continue
		}
		all = append(all, r.Findings...)
	}
	findings := reporter.Enrich(ctx, reporter.Options{RepoDir: repoDir, Reveal: f.reveal}, merger.Merge(all))

	duration := time.Since(start)
	meta := reporter.Meta{
		ProjectName:    projectName,
		ProjectPath:    target,
		ScanDate:       time.Now().UTC().Format("Jan 2, 2006 · 15:04 MST"),
		ScanDuration:   formatDuration(duration),
		ScanCommand:    "chainfault scan " + target,
		CommitsScanned: commitCount,
		CommitHash:     headHash,
		Branch:         branch,
		Reveal:         f.reveal,
	}

	// 7. The terminal report is always printed.
	reporter.Terminal(os.Stdout, findings, toolStatus, f.reveal, style)

	// 8. The HTML report only when asked for.
	if outputPath != "" {
		report := reporter.BuildReport(meta, toolStatus, findings, f.reveal)
		if err := reporter.WriteHTML(outputPath, report); err != nil {
			return exitIncomplete, err
		}
		fmt.Printf("\nHTML report saved to: %s\n", outputPath)
		if f.reveal {
			fmt.Println("This report contains full secrets. Delete it after use.")
		}
	}

	// 9. The temporary clone is removed by the deferred cleanup above.
	// 10. Exit code: failure wins over findings (CHAINFAULT_DOC.md §16).
	if len(failed) > 0 {
		return exitIncomplete, nil
	}
	if len(findings) > 0 {
		return exitFindings, nil
	}
	return exitClean, nil
}

// scpStylePattern matches the git shorthand user@host:path, which is an SSH
// remote even though it has no URL scheme.
var scpStylePattern = regexp.MustCompile(`^[^/@\s]+@[^/:\s]+:.+`)

// isSSHInput reports whether target is an SSH remote in either URL or scp-style
// form. Both would otherwise fall through to the local-path checks and produce
// the misleading "<path> does not exist" error.
func isSSHInput(target string) bool {
	return strings.HasPrefix(strings.ToLower(target), "ssh://") || scpStylePattern.MatchString(target)
}

// validateTarget rejects anything that is not a scannable git repository.
func validateTarget(target string) error {
	if isSSHInput(target) {
		return fmt.Errorf("only https:// repository URLs and local paths are supported, got %q", target)
	}
	if gitutil.IsURL(target) {
		if !gitutil.IsHttpsURL(target) {
			return fmt.Errorf("only https:// repository URLs are supported, got %q", target)
		}
		return nil
	}
	abs, err := filepath.Abs(target)
	if err != nil {
		return fmt.Errorf("resolve %q: %w", target, err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("%q does not exist", target)
		}
		return fmt.Errorf("cannot read %q: %w", target, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%q is not a directory", target)
	}
	if !gitutil.IsRepo(abs) {
		return fmt.Errorf("%q is not a git repository", target)
	}
	if !gitutil.HasCommits(abs) {
		return fmt.Errorf("%s is a git repository with no commits — nothing to scan", target)
	}
	return nil
}

// resolveOutput validates --output and returns where the HTML report goes, or
// "" when none was requested (CHAINFAULT_DOC.md §13).
func resolveOutput(f scanFlags, target string) (string, error) {
	if f.output == "" {
		if !f.html {
			return "", nil
		}
		// Default: the current directory, never inside the scanned repository,
		// with a timestamp so an old report is never overwritten.
		wd, err := os.Getwd()
		if err != nil {
			return "", fmt.Errorf("determine current directory: %w", err)
		}
		return reporter.DefaultOutputPath(wd, projectNameFor(target), time.Now().Format("2006-01-02-1504")), nil
	}
	// --output without --html would be silently ignored, so it is an error
	// rather than a convenience (CHAINFAULT_DOC.md §13).
	if !f.html {
		return "", errors.New("--output requires --html")
	}
	if !strings.HasSuffix(strings.ToLower(f.output), ".html") {
		return "", fmt.Errorf("--output must end in .html, got %q", f.output)
	}
	abs, err := filepath.Abs(f.output)
	if err != nil {
		return "", fmt.Errorf("resolve %q: %w", f.output, err)
	}
	// A missing parent directory is an error; directories are never created
	// implicitly, so a typo cannot silently scatter reports.
	parent := filepath.Dir(abs)
	info, err := os.Stat(parent)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("output directory %q does not exist", parent)
	}
	return abs, nil
}

// projectNameFor derives a readable project name from a path or a URL.
func projectNameFor(target string) string {
	name := strings.TrimRight(target, "/")
	if gitutil.IsURL(name) {
		if i := strings.LastIndex(name, "/"); i >= 0 {
			name = name[i+1:]
		}
	} else {
		name = filepath.Base(name)
	}
	return strings.TrimSuffix(name, ".git")
}

// formatDuration renders a scan duration the way the reports show it.
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	return fmt.Sprintf("%.1fs", d.Seconds())
}

// isTerminal reports whether f is an interactive terminal, so escape sequences
// are only written when a human will actually see them.
func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
