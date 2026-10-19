package main

// Tests for the exit-code rule "a failed scanner beats findings" (Task 3,
// CHAINFAULT_DOC.md §16): exit code 2 must win over exit code 1 even when the
// other scanner really did find a secret. cmd_test.go already covers the clean
// (TestScanExitCodeClean), findings-only (TestScanExitCodeFindings) and
// invalid-input (TestScanExitCodeIncomplete) cases; these two cover the one
// that is still missing, in both directions, with no real helper tools.
//
// The fakes mirror internal/scanner/scanner_test.go: a `#!/bin/sh` script named
// exactly `gitleaks` / `trufflehog`, written with mode 0o755 into a temp dir
// that is prepended to PATH. PATH is extended, never replaced, because
// Chainfault shells out to the real `git` for clone and `git show`.

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Failure markers printed by the fake tools so a test can prove the Failed
// Scanner Tools block carried the failed tool's reason.
const (
	fakeGitleaksFailure   = "FAKE_GITLEAKS_FAILURE"
	fakeTruffleHogFailure = "FAKE_TRUFFLEHOG_FAILURE"
)

// installFakeTool writes an executable `#!/bin/sh` script named name into a
// fresh bin directory and prepends that directory to PATH.
func installFakeTool(t *testing.T, name, script string) {
	t.Helper()

	binDir := filepath.Join(t.TempDir(), "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", binDir, err)
	}
	if err := os.WriteFile(filepath.Join(binDir, name), []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// versionBanner makes the fake answer the `--version` probe updater.Ensure runs
// before a scan. Without it the tool would look broken for the wrong reason and
// the scan would exit 2 before either scanner ran.
func versionBanner(name, version string) string {
	return `if [ "$1" = "--version" ]; then
echo "` + name + ` version ` + version + `"
exit 0
fi
`
}

// fakeGitleaksFinding installs a gitleaks that writes a valid JSON report
// naming fakeToken in config.py at the given commit, then exits 0.
func fakeGitleaksFinding(t *testing.T, commit string) {
	t.Helper()

	report := `[{"RuleID":"github-pat","Description":"GitHub Personal Access Token",` +
		`"File":"config.py","StartLine":1,"Secret":"` + fakeToken + `",` +
		`"Commit":"` + commit + `","Author":"Test <test@example.com>",` +
		`"Date":"2026-01-01T00:00:00Z","Entropy":3.5}]`

	installFakeTool(t, "gitleaks", versionBanner("gitleaks", "8.18.0")+`
report=""
prev=""
for a in "$@"; do
  if [ "$prev" = "-r" ]; then report="$a"; fi
  prev="$a"
done
if [ -n "$report" ]; then printf '%s' '`+report+`' > "$report"; fi
exit 0
`)
}

// fakeGitleaksFailing installs a gitleaks that fails for real on every scan
// invocation (a non-zero exit, deliberately not a "cannot start"), while still
// answering the version probe.
func fakeGitleaksFailing(t *testing.T) {
	t.Helper()
	installFakeTool(t, "gitleaks", versionBanner("gitleaks", "8.18.0")+`
echo "`+fakeGitleaksFailure+`"
echo "`+fakeGitleaksFailure+`" >&2
exit 7
`)
}

// fakeTruffleHogFinding installs a trufflehog that prints a JSONL finding for
// fakeToken in config.py at the given commit on stdout, then exits 0.
func fakeTruffleHogFinding(t *testing.T, commit string) {
	t.Helper()

	jsonl := `{"DetectorName":"GitHub","DecoderName":"PLAIN","Verified":false,` +
		`"Raw":"` + fakeToken + `","SourceMetadata":{"Data":{"Git":{"commit":"` +
		commit + `","file":"config.py","email":"Test <test@example.com>",` +
		`"timestamp":"2026-01-01T00:00:00Z","line":1}}}}`

	installFakeTool(t, "trufflehog", versionBanner("trufflehog", "3.88.0")+`
cat <<'CHAINFAULT_FAKE_JSONL'
`+jsonl+`
CHAINFAULT_FAKE_JSONL
exit 0
`)
}

// fakeTruffleHogFailing installs a trufflehog that fails for real on every scan
// invocation while still answering the version probe.
func fakeTruffleHogFailing(t *testing.T) {
	t.Helper()
	installFakeTool(t, "trufflehog", versionBanner("trufflehog", "3.88.0")+`
echo "`+fakeTruffleHogFailure+`" >&2
echo "`+fakeTruffleHogFailure+`"
exit 9
`)
}

// headCommit returns the commit a repository's HEAD points at, so the faked
// report can name a commit and a file that really exist in the scanned clone.
func headCommit(t *testing.T, repo string) string {
	t.Helper()
	out, err := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatalf("git rev-parse HEAD in %s: %v", repo, err)
	}
	return strings.TrimSpace(string(out))
}

// assertFailureReported checks the red Failed Scanner Tools block names the
// failed tool and carries its reason, and that the scan says it is incomplete.
func assertFailureReported(t *testing.T, out, tool, marker string) {
	t.Helper()
	if !strings.Contains(out, "Failed Scanner Tools") {
		t.Errorf("the Failed Scanner Tools block is missing:\n%s", out)
	}
	if !strings.Contains(out, tool) {
		t.Errorf("the failed tool %q is not named in the report:\n%s", tool, out)
	}
	if !strings.Contains(out, marker) {
		t.Errorf("the failed tool's reason is missing from the report:\n%s", out)
	}
	if !strings.Contains(out, "Scan incomplete") {
		t.Errorf("the report does not say the scan is incomplete:\n%s", out)
	}
}

// assertFindingReported checks the working scanner's finding survived: the
// masked token is shown and exactly one finding is counted.
func assertFindingReported(t *testing.T, out string) {
	t.Helper()
	if !strings.Contains(out, "ghp_") {
		t.Errorf("the finding from the working scanner is missing (no masked token):\n%s", out)
	}
	if !strings.Contains(out, "Total: 1 finding across 1 file") {
		t.Errorf("the report does not count exactly one finding:\n%s", out)
	}
}

// TestScanExitCode2WhenGitleaksFailsButTruffleHogFinds: Gitleaks fails for
// real while TruffleHog reports a secret. The failure must win, so the exit
// code is 2 — not 1, even though a secret was found.
func TestScanExitCode2WhenGitleaksFailsButTruffleHogFinds(t *testing.T) {
	fakeGitleaksFailing(t)
	repo := secretRepo(t)
	fakeTruffleHogFinding(t, headCommit(t, repo))

	code, out := runCLI(t, "scan", repo)

	if code == exitFindings {
		t.Fatalf("scan = %d (findings): a failed scanner must outrank a finding\n%s", code, out)
	}
	if code != exitIncomplete {
		t.Fatalf("scan = %d, want %d\n%s", code, exitIncomplete, out)
	}
	assertFailureReported(t, out, "gitleaks", fakeGitleaksFailure)
	assertFindingReported(t, out)
}

// TestScanExitCode2WhenTruffleHogFailsButGitleaksFinds is the mirror image:
// TruffleHog fails for real while Gitleaks reports a secret. Same rule, same
// exit code, so neither tool's failure path is left untested.
func TestScanExitCode2WhenTruffleHogFailsButGitleaksFinds(t *testing.T) {
	repo := secretRepo(t)
	fakeGitleaksFinding(t, headCommit(t, repo))
	fakeTruffleHogFailing(t)

	code, out := runCLI(t, "scan", repo)

	if code == exitFindings {
		t.Fatalf("scan = %d (findings): a failed scanner must outrank a finding\n%s", code, out)
	}
	if code != exitIncomplete {
		t.Fatalf("scan = %d, want %d\n%s", code, exitIncomplete, out)
	}
	assertFailureReported(t, out, "trufflehog", fakeTruffleHogFailure)
	assertFindingReported(t, out)
}
