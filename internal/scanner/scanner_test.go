package scanner

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeTool installs a shell script named tool in a fresh directory, puts that
// directory at the front of PATH for the duration of the test, and returns the
// file the script appends its arguments to.
//
// Real Gitleaks and TruffleHog are never required: these tests assert on the
// exact command line Chainfault builds, which is what the flags in
// CHAINFAULT_DOC.md §13, §19 and §21 are about. It returns the directory the
// fake tool was installed in.
func fakeTool(t *testing.T, name, script, argsFileEnv string) string {
	t.Helper()

	binDir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", binDir, err)
	}
	path := filepath.Join(binDir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
	t.Setenv(argsFileEnv, filepath.Join(t.TempDir(), "args.txt"))
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return binDir
}

// writeArgs is prepended to every fake tool: it records argv, one line per
// argument, so a test can assert on the exact flags. argsEnv names the
// environment variable holding the file to write to.
func writeArgs(argsEnv string) string {
	return "\nprintf '%s\\n' \"$@\" >> \"$" + argsEnv + "\"\n"
}

// fakeGitleaks installs a gitleaks that records its arguments, writes an empty
// (but valid) JSON report to the path given after -r, and exits with exitCode.
func fakeGitleaks(t *testing.T, exitCode int, report string) string {
	t.Helper()
	const env = "CHAINFAKE_GITLEAKS_ARGS_FILE"
	return fakeTool(t, "gitleaks", writeArgs(env)+`
report=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-r" ]; then report="$a"; fi
  prev="$a"
done
if [ -n "$report" ]; then printf '%s' '`+report+`' > "$report"; fi
exit `+itoa(exitCode)+`
`, env)
}

// fakeTruffleHog installs a trufflehog that records its arguments, prints
// stdout on standard output and exits with exitCode.
func fakeTruffleHog(t *testing.T, exitCode int, stdout string) string {
	t.Helper()
	const env = "CHAINFAKE_TRUFFLEHOG_ARGS_FILE"
	return fakeTool(t, "trufflehog", writeArgs(env)+`
cat <<'CHAINFAULT_FAKE_STDOUT'
`+stdout+`
CHAINFAULT_FAKE_STDOUT
exit `+itoa(exitCode)+`
`, env)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}

// recordedArgs reads back the arguments a fake tool was invoked with.
func recordedArgs(t *testing.T, env string) []string {
	t.Helper()
	raw, err := os.ReadFile(os.Getenv(env))
	if err != nil {
		t.Fatalf("read recorded args (%s): %v", env, err)
	}
	var args []string
	for _, l := range strings.Split(string(raw), "\n") {
		if l == "" {
			continue
		}
		args = append(args, l)
	}
	return args
}

// tempRepo creates a git repository with one commit so the scanner has
// something real to point at.
func tempRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cfg.py"), []byte("value = 1\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	gitInit(t, dir)
	return dir
}

// gitInit creates a git repository with a single commit inside dir.
func gitInit(t *testing.T, dir string) {
	t.Helper()
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"config", "user.email", "test@example.com"},
		{"config", "user.name", "Test"},
		{"add", "-A"},
		{"commit", "-q", "-m", "fixture"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

// findResult returns the result of the named tool.
func findResult(results []Result, name string) (Result, bool) {
	for _, r := range results {
		if r.Name == name {
			return r, true
		}
	}
	return Result{}, false
}

// containsArgPair reports whether args holds want immediately followed by value.
func containsArgPair(args []string, want, value string) bool {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == want && args[i+1] == value {
			return true
		}
	}
	return false
}

func hasArg(args []string, want string) bool {
	for _, a := range args {
		if a == want {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Argument construction
// ---------------------------------------------------------------------------

func TestRunBuildsTheDocumentedGitleaksArguments(t *testing.T) {
	fakeGitleaks(t, 0, "[]")
	fakeTruffleHog(t, 0, "")
	repo := tempRepo(t)

	res := Run(context.Background(), Options{
		RepoPath:       repo,
		GitleaksConfig: []byte("[extend]\nuseDefault = true\n"),
	}, nil)

	if len(res) != 2 {
		t.Fatalf("Run returned %d results, want 2", len(res))
	}

	args := recordedArgs(t, "CHAINFAKE_GITLEAKS_ARGS_FILE")
	if len(args) == 0 {
		t.Fatal("the fake gitleaks recorded no arguments")
	}
	if args[0] != "git" {
		t.Errorf("gitleaks subcommand = %q, want %q", args[0], "git")
	}
	if args[1] != repo {
		t.Errorf("gitleaks repo = %q, want %q", args[1], repo)
	}

	// Every flag of CHAINFAULT_DOC.md §13, with its exact value.
	wantPairs := [][2]string{
		{"-f", "json"},
		{"--exit-code", "0"},
		{"--no-banner", ""},
	}
	for _, p := range wantPairs {
		if p[1] == "" {
			if !hasArg(args, p[0]) {
				t.Errorf("gitleaks args %q missing %q", args, p[0])
			}
			continue
		}
		if !containsArgPair(args, p[0], p[1]) {
			t.Errorf("gitleaks args %q missing %q %q", args, p[0], p[1])
		}
	}
	if !hasArg(args, "--ignore-gitleaks-allow") {
		t.Errorf("gitleaks args %q missing --ignore-gitleaks-allow", args)
	}

	// -r must point at a report path inside a temp dir, and the config must be
	// written with the content the caller supplied.
	reportIdx := indexOf(args, "-r")
	if reportIdx < 0 || reportIdx+1 >= len(args) {
		t.Fatalf("gitleaks args %q have no -r <path>", args)
	}
	reportPath := args[reportIdx+1]
	if !strings.HasSuffix(reportPath, ".json") {
		t.Errorf("report path = %q, want a .json path", reportPath)
	}
	configIdx := indexOf(args, "-c")
	if configIdx < 0 || configIdx+1 >= len(args) {
		t.Fatalf("gitleaks args %q have no -c <path>", args)
	}
	ignoreIdx := indexOf(args, "-i")
	if ignoreIdx < 0 || ignoreIdx+1 >= len(args) {
		t.Fatalf("gitleaks args %q have no -i <path>", args)
	}
	if args[configIdx+1] == args[ignoreIdx+1] {
		t.Error("-c and -i must not point at the same path")
	}

	// TruffleHog gets an absolute file:// URL, never a bare path.
	thArgs := recordedArgs(t, "CHAINFAKE_TRUFFLEHOG_ARGS_FILE")
	if len(thArgs) < 2 || thArgs[0] != "git" {
		t.Fatalf("trufflehog args = %q, want it to start with git", thArgs)
	}
	abs, err := filepath.Abs(repo)
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	if thArgs[1] != "file://"+abs {
		t.Errorf("trufflehog target = %q, want %q", thArgs[1], "file://"+abs)
	}
	for _, want := range []string{"--json", "--no-update", "--fail-on-scan-errors"} {
		if !hasArg(thArgs, want) {
			t.Errorf("trufflehog args %q missing %q", thArgs, want)
		}
	}
	if hasArg(thArgs, "--fail") {
		t.Errorf("trufflehog args %q must not pass --fail", thArgs)
	}
}

func TestVerifyOnlyDropsNoVerification(t *testing.T) {
	fakeGitleaks(t, 0, "[]")
	fakeTruffleHog(t, 0, "")
	repo := tempRepo(t)

	Run(context.Background(), Options{RepoPath: repo, Verify: true}, nil)

	args := recordedArgs(t, "CHAINFAKE_TRUFFLEHOG_ARGS_FILE")
	if hasArg(args, "--no-verification") {
		t.Errorf("trufflehog args %q must not contain --no-verification with Verify set", args)
	}
	for _, want := range []string{"--json", "--no-update", "--fail-on-scan-errors"} {
		if !hasArg(args, want) {
			t.Errorf("trufflehog args %q lost %q with Verify set", args, want)
		}
	}
}

func TestDepthMapsToBothTools(t *testing.T) {
	fakeGitleaks(t, 0, "[]")
	fakeTruffleHog(t, 0, "")
	repo := tempRepo(t)

	cases := []struct {
		depth      string
		wantGLLog  string
		wantTHArgs [2]string
	}{
		{depth: "5", wantGLLog: "--log-opts=-n 5", wantTHArgs: [2]string{"--max-depth", "5"}},
		{depth: "full"},
		{depth: ""},
	}

	for _, c := range cases {
		os.Remove(os.Getenv("CHAINFAKE_GITLEAKS_ARGS_FILE"))
		os.Remove(os.Getenv("CHAINFAKE_TRUFFLEHOG_ARGS_FILE"))

		Run(context.Background(), Options{RepoPath: repo, Depth: c.depth}, nil)

		glArgs := recordedArgs(t, "CHAINFAKE_GITLEAKS_ARGS_FILE")
		thArgs := recordedArgs(t, "CHAINFAKE_TRUFFLEHOG_ARGS_FILE")

		if c.wantGLLog == "" {
			for _, a := range glArgs {
				if strings.HasPrefix(a, "--log-opts") {
					t.Errorf("depth %q: gitleaks must get no --log-opts, got %q", c.depth, a)
				}
			}
			if hasArg(thArgs, "--max-depth") {
				t.Errorf("depth %q: trufflehog must get no --max-depth, got %q", c.depth, thArgs)
			}
			continue
		}
		if !hasArg(glArgs, c.wantGLLog) {
			t.Errorf("depth %q: gitleaks args %q missing %q", c.depth, glArgs, c.wantGLLog)
		}
		if !containsArgPair(thArgs, c.wantTHArgs[0], c.wantTHArgs[1]) {
			t.Errorf("depth %q: trufflehog args %q missing %q %q", c.depth, thArgs, c.wantTHArgs[0], c.wantTHArgs[1])
		}
	}
}

func TestValidDepth(t *testing.T) {
	valid := []string{"full", "FULL", "  full  ", "1", "5", "250"}
	for _, d := range valid {
		if !ValidDepth(d) {
			t.Errorf("ValidDepth(%q) = false, want true", d)
		}
	}
	invalid := []string{"", "0", "-3", "abc", "3.5", "1e3"}
	for _, d := range invalid {
		if ValidDepth(d) {
			t.Errorf("ValidDepth(%q) = true, want false", d)
		}
	}
}

func TestDepthToCount(t *testing.T) {
	cases := []struct {
		in   string
		want int
		ok   bool
	}{
		{"5", 5, true},
		{"42", 42, true},
		{" 7 ", 7, true},
		{"", 0, false},
		{"full", 0, false},
		{"FULL", 0, false},
		{"0", 0, false},
		{"-1", 0, false},
		{"abc", 0, false},
	}
	for _, c := range cases {
		got, ok := depthToCount(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("depthToCount(%q) = (%d, %v), want (%d, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

// ---------------------------------------------------------------------------
// Failure handling
// ---------------------------------------------------------------------------

func TestOneFailingToolDoesNotStopTheOther(t *testing.T) {
	fakeGitleaks(t, 1, "")
	fakeTruffleHog(t, 0, "")
	repo := tempRepo(t)

	res := Run(context.Background(), Options{RepoPath: repo}, nil)

	gl, ok := findResult(res, "gitleaks")
	if !ok {
		t.Fatal("no gitleaks result")
	}
	if gl.OK {
		t.Error("gitleaks result OK = true although the tool exited 1")
	}
	if strings.TrimSpace(gl.Reason) == "" {
		t.Error("a failed gitleaks result must carry a reason")
	}

	th, ok := findResult(res, "trufflehog")
	if !ok {
		t.Fatal("no trufflehog result")
	}
	if !th.OK {
		t.Errorf("trufflehog result OK = false: %q", th.Reason)
	}
}

func TestMissingToolIsReportedNotPanicked(t *testing.T) {
	// Only trufflehog is faked, and PATH holds nothing else, so gitleaks
	// cannot be found.
	binDir := fakeTruffleHog(t, 0, "")
	repo := tempRepo(t)
	t.Setenv("PATH", binDir)

	res := Run(context.Background(), Options{RepoPath: repo}, nil)

	gl, ok := findResult(res, "gitleaks")
	if !ok {
		t.Fatal("no gitleaks result")
	}
	if gl.OK {
		t.Error("gitleaks result OK = true although the tool is missing")
	}
	if !strings.Contains(gl.Reason, "gitleaks") {
		t.Errorf("reason = %q, want it to name gitleaks", gl.Reason)
	}
}

// ---------------------------------------------------------------------------
// TruffleHog output handling
// ---------------------------------------------------------------------------

func TestTruffleHogLogLinesWithoutDetectorNameAreDropped(t *testing.T) {
	const finding = `{"DetectorName":"AWS","DecoderName":"PLAIN","Verified":false,"Raw":"AKIAIOSFODNN7EXAMPLE","SourceMetadata":{"Data":{"Git":{"commit":"abc123","file":"src/cfg.py","email":"A <a@b.c>","timestamp":"2026-01-01T00:00:00Z","line":3}}}}`

	fakeGitleaks(t, 0, "[]")
	// TruffleHog mixes its info logs into the same stream as its findings.
	fakeTruffleHog(t, 0, `{"level":"info","ts":1,"msg":"scanning"}`+"\n"+`{"info-0":1}`+"\n"+finding+"\n")
	repo := tempRepo(t)

	res := Run(context.Background(), Options{RepoPath: repo}, nil)

	th, ok := findResult(res, "trufflehog")
	if !ok {
		t.Fatal("no trufflehog result")
	}
	if !th.OK {
		t.Fatalf("trufflehog failed: %q", th.Reason)
	}
	if len(th.Findings) != 1 {
		t.Fatalf("got %d findings, want exactly 1: %+v", len(th.Findings), th.Findings)
	}
	f := th.Findings[0]
	if f.SecretValue != "AKIAIOSFODNN7EXAMPLE" {
		t.Errorf("SecretValue = %q, want the raw record value", f.SecretValue)
	}
	if f.FilePath != "src/cfg.py" {
		t.Errorf("FilePath = %q, want %q", f.FilePath, "src/cfg.py")
	}
	if f.Line != 3 {
		t.Errorf("Line = %d, want 3", f.Line)
	}
	if f.SecretType != "AWS key" {
		t.Errorf("SecretType = %q, want %q", f.SecretType, "AWS key")
	}
	if len(f.FoundBy) != 1 || f.FoundBy[0] != "trufflehog" {
		t.Errorf("FoundBy = %q, want [trufflehog]", f.FoundBy)
	}
}

func TestStatusCallbackIsCalledForBothTools(t *testing.T) {
	fakeGitleaks(t, 0, "[]")
	fakeTruffleHog(t, 0, "")
	repo := tempRepo(t)

	var mu sync.Mutex
	var names []string
	Run(context.Background(), Options{RepoPath: repo}, func(s Status) {
		mu.Lock()
		defer mu.Unlock()
		names = append(names, s.Name)
	})

	if len(names) != 2 {
		t.Fatalf("status callback fired %d times (%q), want 2", len(names), names)
	}
	seen := map[string]bool{}
	for _, n := range names {
		seen[n] = true
	}
	if !seen["gitleaks"] || !seen["trufflehog"] {
		t.Errorf("status names = %q, want one entry per tool", names)
	}
}

func indexOf(args []string, want string) int {
	for i, a := range args {
		if a == want {
			return i
		}
	}
	return -1
}
