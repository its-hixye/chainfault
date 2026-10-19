package reporter

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/its-hixye/chainfault/internal/normalizer"
	"github.com/its-hixye/chainfault/internal/risk"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// repTestRaw is a fabricated credential (not a real one). It is long enough to
// exercise the ">= 12 characters" masking rule.
const repTestRaw = "AKIAIOSFODNN7EXAMPLE"

// repTestFinding builds a normalizer.Finding with realistic defaults so each
// test only has to state the field(s) it cares about.
func repTestFinding(mutators ...func(*normalizer.Finding)) normalizer.Finding {
	f := normalizer.Finding{
		FilePath:      "config.py",
		Line:          5,
		SecretType:    "AWS key",
		Category:      normalizer.CategoryCloudKeys,
		SecretValue:   repTestRaw,
		MaskedSecret:  normalizer.Mask(repTestRaw),
		SecretKeyName: "ENV_KEY",
		CommitHash:    "deadbeefcafe1234",
		CommitDate:    "Oct 18, 2026",
		CommitAuthor:  "dev",
	}
	for _, m := range mutators {
		m(&f)
	}
	return f
}

// repTestGit runs a git command inside dir with a fully isolated environment
// (no user/system config, no signing) so the test repo is deterministic.
func repTestGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	base := []string{
		"-c", "user.name=Chainfault Test",
		"-c", "user.email=test@example.com",
		"-c", "commit.gpgsign=false",
		"-c", "init.defaultBranch=main",
	}
	cmd := exec.Command("git", append(base, args...)...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// app.py with the secret on line 5; two commits differ only on that line so the
// v1 secret is only in history.
const (
	repTestAppV1 = `# app config
import os

region = "us-east-1"
db_password = "historysecretvalue123"
debug = False

timeout = 30

# end
`

	repTestAppV2 = `# app config
import os

region = "us-east-1"
db_password = "rotatedvalue999xxx"
debug = False

timeout = 30

# end
`
)

// repTestRepo creates a real git repository in t.TempDir() and commits app.py
// twice, returning the directory and both commit hashes (v1 then v2).
func repTestRepo(t *testing.T) (dir, c1, c2 string) {
	t.Helper()
	dir = t.TempDir()
	repTestGit(t, dir, "init")
	write := func(content string) {
		if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(content), 0o600); err != nil {
			t.Fatalf("write app.py: %v", err)
		}
	}
	write(repTestAppV1)
	repTestGit(t, dir, "add", "app.py")
	repTestGit(t, dir, "commit", "-m", "add app")
	c1 = repTestGit(t, dir, "rev-parse", "HEAD")

	write(repTestAppV2)
	repTestGit(t, dir, "add", "app.py")
	repTestGit(t, dir, "commit", "-m", "rotate db password")
	c2 = repTestGit(t, dir, "rev-parse", "HEAD")
	return dir, c1, c2
}

func repTestRunTerminal(t *testing.T, findings []normalizer.Finding, tools []ToolStatus, reveal bool, st Style) string {
	t.Helper()
	var buf bytes.Buffer
	Terminal(&buf, findings, tools, reveal, st)
	return buf.String()
}

// ---------------------------------------------------------------------------
// Terminal
// ---------------------------------------------------------------------------

// TestTerminalSeverityBandsCapitalized checks the exact header text of the four
// score bands: the stored lowercase severity is shown with a capital first
// letter (§14).
func TestTerminalSeverityBandsCapitalized(t *testing.T) {
	cases := []struct {
		severity string
		score    int
		want     string
	}{
		{risk.Critical, 9, "[Critical 9/10] AWS key"},
		{risk.High, 8, "[High 8/10] AWS key"},
		{risk.Medium, 5, "[Medium 5/10] AWS key"},
		{risk.Low, 2, "[Low 2/10] AWS key"},
	}
	for _, tc := range cases {
		f := repTestFinding(func(f *normalizer.Finding) {
			f.Severity = tc.severity
			f.Score = tc.score
		})
		out := repTestRunTerminal(t, []normalizer.Finding{f}, []ToolStatus{{Name: "gitleaks", OK: true}}, false, Style{})
		if !strings.Contains(out, tc.want) {
			t.Errorf("severity %q score %d: output does not contain %q\n%s", tc.severity, tc.score, tc.want, out)
		}
	}
}

// TestTerminalRendersFindingFields checks every line of one finding's block:
// path, masked secret, verified flag and commit count.
func TestTerminalRendersFindingFields(t *testing.T) {
	f := repTestFinding(func(f *normalizer.Finding) {
		f.Severity = risk.Critical
		f.Score = 9
		f.DecodedFrom = "BASE64"
		f.Verified = true
		f.SeenInCommits = 3
	})
	out := repTestRunTerminal(t, []normalizer.Finding{f},
		[]ToolStatus{{Name: "gitleaks", OK: true}, {Name: "trufflehog", OK: true}}, false, Style{})

	for _, want := range []string{
		"[Critical 9/10] AWS key",
		"Path:     config.py:5",
		`Secret:   ENV_KEY = "AKIA****MPLE"`,
		"Verified live",
		"Seen in:  3 commits",
		"Total: 1 finding across 1 file",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("terminal output missing %q\n%s", want, out)
		}
	}
	// A finding still in the file must not show a Commit line.
	if strings.Contains(out, "Commit:") {
		t.Errorf("non-history-only finding must not show a Commit line\n%s", out)
	}
	// No failed tool: no incomplete state.
	if strings.Contains(out, "Scan incomplete") || strings.Contains(out, "Failed Scanner Tools") {
		t.Errorf("clean scan must not advertise a failure\n%s", out)
	}
}

// TestTerminalMarkersAndCommitLine checks the "(test file)" and "(history
// only)" suffixes and the history-only Commit line.
func TestTerminalMarkersAndCommitLine(t *testing.T) {
	f := repTestFinding(func(f *normalizer.Finding) {
		f.Severity = risk.Low
		f.Score = 2
		f.IsTestFile = true
		f.HistoryOnly = true
		f.CommitHash = "deadbeefcafe1234"
		f.CommitDate = "Oct 18, 2026"
		f.CommitAuthor = "dev"
	})
	out := repTestRunTerminal(t, []normalizer.Finding{f}, []ToolStatus{{Name: "gitleaks", OK: true}}, false, Style{})

	if !strings.Contains(out, "[Low 2/10] AWS key (test file) (history only)") {
		t.Errorf("markers missing or out of order\n%s", out)
	}
	if !strings.Contains(out, "Commit:   deadbee — Oct 18, 2026 — dev") {
		t.Errorf("history-only Commit line missing\n%s", out)
	}
}

// TestTerminalSecretRevealTogglesRawValue checks the secret line: masked by
// default, raw value with reveal.
func TestTerminalSecretRevealTogglesRawValue(t *testing.T) {
	f := repTestFinding(func(f *normalizer.Finding) {
		f.Severity = risk.Critical
		f.Score = 9
		f.HistoryOnly = true // suppress noise; not relevant here
	})

	masked := repTestRunTerminal(t, []normalizer.Finding{f}, nil, false, Style{})
	if !strings.Contains(masked, `Secret:   ENV_KEY = "AKIA****MPLE"`) {
		t.Errorf("masked secret line missing\n%s", masked)
	}
	if strings.Contains(masked, repTestRaw) {
		t.Errorf("raw secret leaked without reveal\n%s", masked)
	}

	revealed := repTestRunTerminal(t, []normalizer.Finding{f}, nil, true, Style{})
	if !strings.Contains(revealed, `Secret:   ENV_KEY = "`+repTestRaw+`"`) {
		t.Errorf("raw secret line missing with reveal\n%s", revealed)
	}
}

// TestTerminalSecretLineWithoutKeyName covers the branch where no variable name
// could be extracted: the report shows just the quoted value.
func TestTerminalSecretLineWithoutKeyName(t *testing.T) {
	f := repTestFinding(func(f *normalizer.Finding) {
		f.Severity = risk.High
		f.Score = 8
		f.SecretKeyName = ""
	})
	out := repTestRunTerminal(t, []normalizer.Finding{f}, nil, false, Style{})
	if !strings.Contains(out, `Secret:   "AKIA****MPLE"`) {
		t.Errorf("secret line without key name missing\n%s", out)
	}
}

// TestTerminalNeverShowsDecoderLabel locks in the removal of the decoder line:
// whatever encoder the decoding scanner unwrapped the secret from, the terminal
// report must not mention it — for a real decoder, for the PLAIN marker and for
// the empty default alike. It is scanner detail, not part of the finding.
func TestTerminalNeverShowsDecoderLabel(t *testing.T) {
	for _, decoded := range []string{"", "PLAIN", "BASE64", "UTF16"} {
		f := repTestFinding(func(f *normalizer.Finding) {
			f.Severity = risk.Medium
			f.Score = 5
			f.HistoryOnly = true
			f.DecodedFrom = decoded
		})
		out := repTestRunTerminal(t, []normalizer.Finding{f}, nil, false, Style{})
		for _, banned := range []string{"Decoded:", "Decoded ", "BASE64", "UTF16", "PLAIN"} {
			if strings.Contains(out, banned) {
				t.Errorf("decodedFrom=%q: terminal output must not show the decoder (%q)\n%s", decoded, banned, out)
			}
		}
	}
}

// TestTerminalVerifiedLiveTag checks the verified marker reads as a "Verified
// live" tag (--verify only) and is absent for an unverified finding.
func TestTerminalVerifiedLiveTag(t *testing.T) {
	verified := repTestFinding(func(f *normalizer.Finding) {
		f.Severity = risk.Critical
		f.Score = 9
		f.Verified = true
	})
	out := repTestRunTerminal(t, []normalizer.Finding{verified}, nil, false, Style{})
	if !strings.Contains(out, "Verified live") {
		t.Errorf("verified finding must carry the %q tag\n%s", "Verified live", out)
	}
	// The old wording must be gone.
	if strings.Contains(out, "Verified: yes") {
		t.Errorf("verified finding must not print the old %q line\n%s", "Verified: yes", out)
	}

	unverified := repTestFinding(func(f *normalizer.Finding) {
		f.Severity = risk.Critical
		f.Score = 9
		f.Verified = false
	})
	out = repTestRunTerminal(t, []normalizer.Finding{unverified}, nil, false, Style{})
	if strings.Contains(out, "Verified") {
		t.Errorf("unverified finding must not show a Verified tag\n%s", out)
	}
}

// TestTerminalTotalLineGrammar checks the closing count line reads correctly for
// 0, 1 and several findings/files: only an exact count of one is singular.
func TestTerminalTotalLineGrammar(t *testing.T) {
	t.Run("zero", func(t *testing.T) {
		out := repTestRunTerminal(t, nil, []ToolStatus{{Name: "gitleaks", OK: true}}, false, Style{})
		if !strings.Contains(out, "Total: 0 findings across 0 files") {
			t.Errorf("zero total line wrong\n%s", out)
		}
	})

	t.Run("one finding in one file", func(t *testing.T) {
		f := repTestFinding(func(f *normalizer.Finding) { f.Severity = risk.High; f.Score = 8 })
		out := repTestRunTerminal(t, []normalizer.Finding{f}, nil, false, Style{})
		if !strings.Contains(out, "Total: 1 finding across 1 file") {
			t.Errorf("singular total line wrong\n%s", out)
		}
		for _, banned := range []string{"Total: 1 findings", "Total: 1 finding across 1 files"} {
			if strings.Contains(out, banned) {
				t.Errorf("total line must not read %q\n%s", banned, out)
			}
		}
	})

	t.Run("many findings in one file", func(t *testing.T) {
		var fs []normalizer.Finding
		for i := 0; i < 3; i++ {
			fs = append(fs, repTestFinding(func(f *normalizer.Finding) {
				f.Severity = risk.High
				f.Score = 8
				f.Line = i + 1
			}))
		}
		out := repTestRunTerminal(t, fs, nil, false, Style{})
		if !strings.Contains(out, "Total: 3 findings across 1 file") {
			t.Errorf("mixed total line wrong\n%s", out)
		}
	})

	t.Run("many findings in many files", func(t *testing.T) {
		var fs []normalizer.Finding
		for i, path := range []string{"a.py", "b.py", "c.py"} {
			fs = append(fs, repTestFinding(func(f *normalizer.Finding) {
				f.Severity = risk.High
				f.Score = 8
				f.FilePath = path
				f.Line = i + 1
			}))
		}
		out := repTestRunTerminal(t, fs, nil, false, Style{})
		if !strings.Contains(out, "Total: 3 findings across 3 files") {
			t.Errorf("plural total line wrong\n%s", out)
		}
	})
}

// TestTerminalCleanRepositoryMessage checks the clean message appears only when
// every scanner ran OK.
func TestTerminalCleanRepositoryMessage(t *testing.T) {
	tools := []ToolStatus{{Name: "gitleaks", OK: true}, {Name: "trufflehog", OK: true}}
	out := repTestRunTerminal(t, nil, tools, false, Style{})

	if !strings.Contains(out, "Repository is clean, no issues found") {
		t.Errorf("clean message missing\n%s", out)
	}
	if !strings.Contains(out, "Total: 0 findings across 0 files") {
		t.Errorf("zero total line missing\n%s", out)
	}
	if strings.Contains(out, "Scan incomplete") || strings.Contains(out, "Failed Scanner Tools") {
		t.Errorf("clean report must not contain failure text\n%s", out)
	}
}

// TestTerminalIncompleteScanMessages checks the failure path: a failed scanner
// turns the clean message into an "incomplete" warning and prints the red
// Failed Scanner Tools block.
func TestTerminalIncompleteScanMessages(t *testing.T) {
	tools := []ToolStatus{
		{Name: "gitleaks", OK: true},
		{Name: "trufflehog", OK: false, Reason: "boom"},
	}
	out := repTestRunTerminal(t, nil, tools, false, Style{})

	if strings.Contains(out, "Repository is clean") {
		t.Errorf("failed scanner must not certify the repo clean\n%s", out)
	}
	if !strings.Contains(out, "Scan incomplete") {
		t.Errorf("incomplete message missing\n%s", out)
	}
	if !strings.Contains(out, "Failed Scanner Tools") {
		t.Errorf("Failed Scanner Tools block missing\n%s", out)
	}
	if !strings.Contains(out, "trufflehog") || !strings.Contains(out, "boom") {
		t.Errorf("failed tool name/reason missing\n%s", out)
	}
}

// TestTerminalIncompleteWithFindings checks the second incomplete line printed
// when a scan produced findings but a scanner still failed, and the default
// reason used when a failed tool reports no reason.
func TestTerminalIncompleteWithFindings(t *testing.T) {
	f := repTestFinding(func(f *normalizer.Finding) {
		f.Severity = risk.Critical
		f.Score = 9
	})
	tools := []ToolStatus{
		{Name: "gitleaks", OK: true},
		{Name: "trufflehog", OK: false},
	}
	out := repTestRunTerminal(t, []normalizer.Finding{f}, tools, false, Style{})

	if !strings.Contains(out, "Scan incomplete: 1 of 2 scanners failed") {
		t.Errorf("scanner-count incomplete line missing\n%s", out)
	}
	if strings.Contains(out, "gitleaks") {
		// gitleaks ran OK, so it must NOT appear in the failed-tools block.
		t.Errorf("healthy scanner must not be listed as failed\n%s", out)
	}
	if !strings.Contains(out, "process exited with an error") {
		t.Errorf("default failure reason missing\n%s", out)
	}
}

// TestTerminalColorEmitsEscapes covers the colour branch: severity headers and
// the failed tools block carry ANSI escapes when Style.Color is set.
func TestTerminalColorEmitsEscapes(t *testing.T) {
	f := repTestFinding(func(f *normalizer.Finding) {
		f.Severity = risk.Critical
		f.Score = 9
	})
	out := repTestRunTerminal(t, []normalizer.Finding{f},
		[]ToolStatus{{Name: "gitleaks", OK: false, Reason: "boom"}}, false, Style{Color: true})

	if !strings.Contains(out, ansiRed+"[Critical 9/10]") {
		t.Errorf("severity header not coloured red: %q", out)
	}
	if !strings.Contains(out, ansiReset) {
		t.Errorf("colour escape is not reset: %q", out)
	}
	if !strings.Contains(out, ansiRed+"Failed Scanner Tools") {
		t.Errorf("failed tools header not coloured red: %q", out)
	}
}

// ---------------------------------------------------------------------------
// SortFindings
// ---------------------------------------------------------------------------

// TestSortFindingsFixedOrder locks the tie-break order of §15: score
// descending, then file path, then line, then secret type, then commit hash.
func TestSortFindingsFixedOrder(t *testing.T) {
	// All minority fields equal except one, to isolate each tie-break.
	findings := []normalizer.Finding{
		// F: lowest score, must come last.
		{SecretKeyName: "F", Score: 5, FilePath: "a.py", Line: 1, SecretType: "AWS key", CommitHash: "aaa"},
		// E: 9 but file b.py, after all a.py.
		{SecretKeyName: "E", Score: 9, FilePath: "b.py", Line: 1, SecretType: "AWS key", CommitHash: "aaa"},
		// A: 9, a.py, line 10, AWS key, commit bbb (after B).
		{SecretKeyName: "A", Score: 9, FilePath: "a.py", Line: 10, SecretType: "AWS key", CommitHash: "bbb"},
		// B: 9, a.py, line 10, AWS key, commit aaa (before A).
		{SecretKeyName: "B", Score: 9, FilePath: "a.py", Line: 10, SecretType: "AWS key", CommitHash: "aaa"},
		// C: 9, a.py, line 10, GitHub token (after AWS key).
		{SecretKeyName: "C", Score: 9, FilePath: "a.py", Line: 10, SecretType: "GitHub token", CommitHash: "aaa"},
		// D: 9, a.py, line 2 (before line 10).
		{SecretKeyName: "D", Score: 9, FilePath: "a.py", Line: 2, SecretType: "AWS key", CommitHash: "aaa"},
	}

	SortFindings(findings)

	got := make([]string, len(findings))
	for i, f := range findings {
		got[i] = f.SecretKeyName
	}
	want := []string{"D", "B", "A", "C", "E", "F"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("sort order = %v, want %v", got, want)
	}
}

// TestSortFindingsStableOnFullTie checks SortFindings does not reorder two
// findings that are equal on every key (stable sort).
func TestSortFindingsStableOnFullTie(t *testing.T) {
	// Same key fields, distinguishable by the audit-only Entropy field.
	findings := []normalizer.Finding{
		{SecretKeyName: "first", Score: 9, FilePath: "a.py", Line: 1, SecretType: "AWS key", CommitHash: "aaa", Entropy: 1},
		{SecretKeyName: "second", Score: 9, FilePath: "a.py", Line: 1, SecretType: "AWS key", CommitHash: "aaa", Entropy: 2},
	}
	SortFindings(findings)
	if findings[0].SecretKeyName != "first" || findings[1].SecretKeyName != "second" {
		t.Errorf("equal findings were reordered: %s, %s", findings[0].SecretKeyName, findings[1].SecretKeyName)
	}
}

// ---------------------------------------------------------------------------
// Enrich
// ---------------------------------------------------------------------------

// TestEnrichHistoryOnlyAndCodeContext builds a real git repo so `git show
// <commit>:<path>` works, and verifies history-only detection, scoring,
// severity, key-name extraction and the exact 3-before/3-after code window.
func TestEnrichHistoryOnlyAndCodeContext(t *testing.T) {
	dir, c1, _ := repTestRepo(t)
	ctx := context.Background()

	findings := []normalizer.Finding{repTestFinding(func(f *normalizer.Finding) {
		f.FilePath = "app.py"
		f.Line = 5
		f.CommitHash = c1 // v1 still had the secret; HEAD (v2) does not
		f.SecretValue = "historysecretvalue123"
		f.MaskedSecret = normalizer.Mask("historysecretvalue123")
		f.Category = normalizer.CategoryDBPasswords // base 8
	})}

	out := Enrich(ctx, Options{RepoDir: dir}, findings)
	if len(out) != 1 {
		t.Fatalf("Enrich returned %d findings, want 1", len(out))
	}
	f := out[0]

	if !f.HistoryOnly {
		t.Errorf("secret absent from HEAD must be flagged history-only")
	}
	if f.Score != 8 || f.Severity != risk.High {
		t.Errorf("score/severity = %d/%s, want 8/high", f.Score, f.Severity)
	}
	if f.Language != "python" {
		t.Errorf("language = %q, want python", f.Language)
	}
	if f.SecretKeyName != "db_password" {
		t.Errorf("secretKeyName = %q, want db_password", f.SecretKeyName)
	}

	// 3 lines before (2,3,4) + target (5) + 3 after (6,7,8).
	if len(f.CodeLines) != 7 {
		t.Fatalf("code context has %d lines, want 7\n%+v", len(f.CodeLines), f.CodeLines)
	}
	wantNumbers := []int{2, 3, 4, 5, 6, 7, 8}
	highlighted := 0
	for i, l := range f.CodeLines {
		if l.Number != wantNumbers[i] {
			t.Errorf("line %d number = %d, want %d", i, l.Number, wantNumbers[i])
		}
		if l.IsHighlighted {
			highlighted++
			if l.Number != 5 {
				t.Errorf("highlighted line = %d, want 5", l.Number)
			}
		}
	}
	if highlighted != 1 {
		t.Errorf("highlighted lines = %d, want exactly 1", highlighted)
	}
	// The code context is read from v1 and masked: the raw secret is gone.
	if got, want := f.CodeLines[3].Code, `db_password = "hist****e123"`; got != want {
		t.Errorf("highlighted code = %q, want %q", got, want)
	}
	for _, l := range f.CodeLines {
		if strings.Contains(l.Code, "historysecretvalue123") {
			t.Errorf("code context leaks the raw secret: %q", l.Code)
		}
	}
}

// TestEnrichSecretStillPresentIsNotHistoryOnly checks the negative branch: a
// secret that survives at HEAD is not history-only.
func TestEnrichSecretStillPresentIsNotHistoryOnly(t *testing.T) {
	dir, _, c2 := repTestRepo(t)

	findings := []normalizer.Finding{repTestFinding(func(f *normalizer.Finding) {
		f.FilePath = "app.py"
		f.Line = 5
		f.CommitHash = c2
		f.SecretValue = "rotatedvalue999xxx"
		f.MaskedSecret = normalizer.Mask("rotatedvalue999xxx")
		f.Category = normalizer.CategoryDBPasswords
	})}

	f := Enrich(context.Background(), Options{RepoDir: dir}, findings)[0]
	if f.HistoryOnly {
		t.Errorf("secret present at HEAD must not be history-only")
	}
	if len(f.CodeLines) != 7 {
		t.Errorf("code context has %d lines, want 7", len(f.CodeLines))
	}
}

// TestEnrichTestFilePenaltyAndMissingContext checks the test-file flag drops
// the score by two, and that a finding whose file is not in the commit gets no
// code context.
func TestEnrichTestFilePenaltyAndMissingContext(t *testing.T) {
	dir, c1, _ := repTestRepo(t)

	findings := []normalizer.Finding{
		repTestFinding(func(f *normalizer.Finding) {
			f.FilePath = "tests/config_test.py" // test path, file not in the repo
			f.Line = 1
			f.CommitHash = c1
			f.SecretValue = "some-unique-test-value"
			f.Category = normalizer.CategoryCloudKeys // base 9
		}),
	}

	f := Enrich(context.Background(), Options{RepoDir: dir}, findings)[0]
	if !f.IsTestFile {
		t.Errorf("tests/config_test.py must be flagged a test file")
	}
	if f.Score != 7 || f.Severity != risk.High {
		t.Errorf("test-file score/severity = %d/%s, want 7/high (9-2)", f.Score, f.Severity)
	}
	if len(f.CodeLines) != 0 {
		t.Errorf("missing file must yield no code context, got %d lines", len(f.CodeLines))
	}
}

// TestEnrichWithoutCommitHash covers the early-return branch: no commit means
// history-only with no code context.
func TestEnrichWithoutCommitHash(t *testing.T) {
	findings := []normalizer.Finding{repTestFinding(func(f *normalizer.Finding) {
		f.CommitHash = ""
		f.FilePath = "config.py"
		f.SecretValue = "no-commit-value-xx"
	})}

	f := Enrich(context.Background(), Options{RepoDir: t.TempDir()}, findings)[0]
	if !f.HistoryOnly {
		t.Errorf("a finding without a commit must be history-only")
	}
	if len(f.CodeLines) != 0 {
		t.Errorf("a finding without a commit must have no code context, got %d", len(f.CodeLines))
	}
}

// TestEnrichClampsContextAtFileStart checks the 3-before window is clamped at
// the first line instead of going negative.
func TestEnrichClampsContextAtFileStart(t *testing.T) {
	dir, c1, _ := repTestRepo(t)
	findings := []normalizer.Finding{repTestFinding(func(f *normalizer.Finding) {
		f.FilePath = "app.py"
		f.Line = 1
		f.CommitHash = c1
		f.SecretValue = "# app config"
		f.Category = normalizer.CategoryRandomText
	})}

	f := Enrich(context.Background(), Options{RepoDir: dir}, findings)[0]
	if len(f.CodeLines) != 4 { // lines 1..4
		t.Fatalf("code context = %d lines, want 4\n%+v", len(f.CodeLines), f.CodeLines)
	}
	if f.CodeLines[0].Number != 1 || !f.CodeLines[0].IsHighlighted {
		t.Errorf("first line must be 1 and highlighted: %+v", f.CodeLines[0])
	}
}

// TestEnrichRevealKeepsRawCodeContext checks that Enrich, with reveal on, keeps
// the original line in CodeRaw while Code stays masked.
func TestEnrichRevealKeepsRawCodeContext(t *testing.T) {
	dir, c1, _ := repTestRepo(t)
	findings := []normalizer.Finding{repTestFinding(func(f *normalizer.Finding) {
		f.FilePath = "app.py"
		f.Line = 5
		f.CommitHash = c1
		f.SecretValue = "historysecretvalue123"
		f.MaskedSecret = normalizer.Mask("historysecretvalue123")
		f.Category = normalizer.CategoryDBPasswords
	})}

	f := Enrich(context.Background(), Options{RepoDir: dir, Reveal: true}, findings)[0]
	target := f.CodeLines[3]
	if target.CodeRaw != `db_password = "historysecretvalue123"` {
		t.Errorf("codeRaw = %q, want the original line", target.CodeRaw)
	}
	if target.Code != `db_password = "hist****e123"` {
		t.Errorf("code = %q, want the masked line even with reveal", target.Code)
	}
}

// ---------------------------------------------------------------------------
// maskContextLines
// ---------------------------------------------------------------------------

// TestMaskContextLinesMasksLongestFirst checks that a secret containing another
// secret is masked whole: the shorter needle must not shred the longer mask.
func TestMaskContextLinesMasksLongestFirst(t *testing.T) {
	findings := []normalizer.Finding{
		{SecretValue: "abcdefghijkl", CodeLines: []normalizer.CodeLine{
			{Number: 1, Code: `v = "abcdefghijkl" and "abcdef"`},
		}},
		{SecretValue: "abcdef"},
	}
	maskContextLines(findings, false)

	line := findings[0].CodeLines[0].Code
	if strings.Contains(line, "abcdefghijkl") || strings.Contains(line, "abcdef") {
		t.Errorf("line still leaks a raw secret: %q", line)
	}
	if line != `v = "abcd****ijkl" and "ab****"` {
		t.Errorf("masked line = %q, want %q", line, `v = "abcd****ijkl" and "ab****"`)
	}
}

// TestMaskContextLinesHonoursReveal checks the reveal snapshot: with reveal the
// raw line is preserved in CodeRaw, without it CodeRaw is empty and never holds
// the masked line.
func TestMaskContextLinesHonoursReveal(t *testing.T) {
	build := func() []normalizer.Finding {
		return []normalizer.Finding{{
			SecretValue: "short",
			CodeLines: []normalizer.CodeLine{
				{Number: 1, Code: `k = "short"`, IsHighlighted: true},
				{Number: 2, Code: "other = 1"},
			},
		}}
	}

	revealed := build()
	maskContextLines(revealed, true)
	if got := revealed[0].CodeLines[0].CodeRaw; got != `k = "short"` {
		t.Errorf("reveal=true: codeRaw = %q, want original line", got)
	}
	if got := revealed[0].CodeLines[0].Code; got != `k = "sh****"` {
		t.Errorf("reveal=true: code = %q, want masked line", got)
	}

	hidden := build()
	maskContextLines(hidden, false)
	for _, l := range hidden[0].CodeLines {
		if l.CodeRaw != "" {
			t.Errorf("reveal=false: line %d codeRaw = %q, want empty", l.Number, l.CodeRaw)
		}
	}
}

// TestMaskContextLinesEmptySecretIgnored checks an empty secret never becomes a
// needle (which would replace the empty string everywhere).
func TestMaskContextLinesEmptySecretIgnored(t *testing.T) {
	findings := []normalizer.Finding{{
		SecretValue: "",
		CodeLines:   []normalizer.CodeLine{{Number: 1, Code: "unchanged = 1"}},
	}}
	maskContextLines(findings, false)
	if got := findings[0].CodeLines[0].Code; got != "unchanged = 1" {
		t.Errorf("empty secret altered the line: %q", got)
	}
}

// ---------------------------------------------------------------------------
// BuildReport / FileCount / Language
// ---------------------------------------------------------------------------

// TestBuildReportDisplayShape checks the display contract: IDs, sanitized
// location, short hash, inline code lines and a non-nil FoundBy.
func TestBuildReportDisplayShape(t *testing.T) {
	f := repTestFinding(func(f *normalizer.Finding) {
		f.Severity = risk.High
		f.Score = 8
		f.FoundBy = nil
		f.Language = "python"
		f.CodeLines = []normalizer.CodeLine{
			{Number: 4, Code: "region = 1"},
			{Number: 5, Code: `key = "AKIA****MPLE"`, IsHighlighted: true},
		}
	})

	rep := BuildReport(Meta{}, []ToolStatus{{Name: "gitleaks", OK: true}}, []normalizer.Finding{f, f}, false)
	if len(rep.Findings) != 2 {
		t.Fatalf("got %d findings, want 2", len(rep.Findings))
	}

	first := rep.Findings[0]
	if first.ID != "sec-1" {
		t.Errorf("ID = %q, want sec-1", first.ID)
	}
	if rep.Findings[1].ID != "sec-2" {
		t.Errorf("second ID = %q, want sec-2", rep.Findings[1].ID)
	}
	if first.Location != "config.py:5" {
		t.Errorf("location = %q, want config.py:5", first.Location)
	}
	if first.Commit.Hash != "deadbee" {
		t.Errorf("commit hash = %q, want the 7-char short hash", first.Commit.Hash)
	}
	if first.FoundBy == nil || len(first.FoundBy) != 0 {
		t.Errorf("FoundBy = %#v, want a non-nil empty slice", first.FoundBy)
	}
	if first.CodeSnippet.Language != "python" {
		t.Errorf("language = %q, want python", first.CodeSnippet.Language)
	}
	if len(first.CodeSnippet.Lines) != 2 {
		t.Fatalf("code lines = %d, want 2", len(first.CodeSnippet.Lines))
	}
	if first.CodeSnippet.Lines[1].Number != 5 || !first.CodeSnippet.Lines[1].IsHighlighted {
		t.Errorf("highlighted code line lost: %+v", first.CodeSnippet.Lines[1])
	}
}

// TestBuildReportRawSecretOnlyOnReveal checks the whole build pipeline:
// rawSecret is set by BuildReport only when reveal is true, and the raw code
// line survives into the report only with reveal (Enrich's maskContextLines
// empties codeRaw without reveal; BuildReport copies whatever it is given).
func TestBuildReportRawSecretOnlyOnReveal(t *testing.T) {
	dir, c1, _ := repTestRepo(t)
	build := func() []normalizer.Finding {
		return []normalizer.Finding{repTestFinding(func(f *normalizer.Finding) {
			f.FilePath = "app.py"
			f.Line = 5
			f.CommitHash = c1
			f.SecretValue = "historysecretvalue123"
			f.MaskedSecret = normalizer.Mask("historysecretvalue123")
			f.Category = normalizer.CategoryDBPasswords
		})}
	}

	hidden := BuildReport(Meta{}, nil,
		Enrich(context.Background(), Options{RepoDir: dir}, build()), false)
	if hidden.Findings[0].RawSecret != "" {
		t.Errorf("rawSecret = %q, want empty without reveal", hidden.Findings[0].RawSecret)
	}
	for _, l := range hidden.Findings[0].CodeSnippet.Lines {
		if l.CodeRaw != "" {
			t.Errorf("line %d: codeRaw = %q, want empty without reveal", l.Number, l.CodeRaw)
		}
	}

	revealed := BuildReport(Meta{}, nil,
		Enrich(context.Background(), Options{RepoDir: dir, Reveal: true}, build()), true)
	if revealed.Findings[0].RawSecret != "historysecretvalue123" {
		t.Errorf("rawSecret = %q, want the full secret with reveal", revealed.Findings[0].RawSecret)
	}
	var sawRaw bool
	for _, l := range revealed.Findings[0].CodeSnippet.Lines {
		if l.CodeRaw == `db_password = "historysecretvalue123"` {
			sawRaw = true
		}
	}
	if !sawRaw {
		t.Errorf("no codeRaw line carries the raw secret with reveal: %+v", revealed.Findings[0].CodeSnippet.Lines)
	}
}

// TestFileCountDistinctPaths checks the count uses distinct file paths.
func TestFileCountDistinctPaths(t *testing.T) {
	if got := FileCount(nil); got != 0 {
		t.Errorf("FileCount(nil) = %d, want 0", got)
	}
	findings := []normalizer.Finding{
		{FilePath: "a.py"},
		{FilePath: "b.py"},
		{FilePath: "a.py"},
		{FilePath: "dir/c.py"},
	}
	if got := FileCount(findings); got != 3 {
		t.Errorf("FileCount = %d, want 3 distinct paths", got)
	}
}

// TestLanguageMapsExtensions checks the extension -> language mapping and its
// plain-text fallback.
func TestLanguageMapsExtensions(t *testing.T) {
	cases := map[string]string{
		"a.py": "python", "a.js": "javascript", "a.mjs": "javascript", "a.cjs": "javascript",
		"a.jsx": "javascript", "a.ts": "typescript", "a.tsx": "typescript", "a.mts": "typescript",
		"a.go": "go", "a.rb": "ruby", "a.java": "java", "a.kt": "java", "a.kts": "java",
		"a.php": "php", "a.rs": "rust", "a.sh": "shell", "a.bash": "shell", "a.zsh": "shell",
		"a.env": "shell", "a.json": "json", "a.yml": "yaml", "a.yaml": "yaml",
		"a.toml": "toml", "a.ini": "toml", "a.cfg": "toml", "a.conf": "toml", "a.properties": "toml",
		"a.sql": "sql", "a.html": "html", "a.htm": "html", "a.css": "css", "a.scss": "css",
		"a.md": "markdown", "A.PY": "python", "noextension": "text", "": "text",
	}
	for path, want := range cases {
		if got := Language(path); got != want {
			t.Errorf("Language(%q) = %q, want %q", path, got, want)
		}
	}
}

// TestDefaultOutputPath checks the report filename shape.
func TestDefaultOutputPath(t *testing.T) {
	got := DefaultOutputPath("/tmp/out", "demo", "2026-10-18-1200")
	want := filepath.Join("/tmp/out", "chainfault-report-demo-2026-10-18-1200.html")
	if got != want {
		t.Errorf("DefaultOutputPath = %q, want %q", got, want)
	}
}

// TestSecretLineFormsCoverBothPEMRepresentations checks the two forms of a PEM
// that can occur inside a single source line: the real-newline value reported by
// TruffleHog and the literal `\n` escaped value reported by Gitleaks. Both must
// be recognized so history detection and context masking work for either.
func TestSecretLineFormsCoverBothPEMRepresentations(t *testing.T) {
	pem := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
	escaped := strings.ReplaceAll(pem, "\n", `\n`)
	forms := secretLineForms(pem)
	for _, want := range []string{pem, escaped} {
		found := false
		for _, got := range forms {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("secretLineForms is missing %q; got %q", want, forms)
		}
	}
}

// TestMaskContextLinesMasksEscapedPEM checks that the escaped representation in
// a source line is fully masked even when the finding's reported value uses
// real newlines. Without both forms the key body would leak in code context.
func TestMaskContextLinesMasksEscapedPEM(t *testing.T) {
	pem := "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END PRIVATE KEY-----"
	escaped := strings.ReplaceAll(pem, "\n", `\n`)
	code := `const key = "` + escaped + `";`
	findings := []normalizer.Finding{{
		SecretValue: pem,
		CodeLines:   []normalizer.CodeLine{{Code: code, IsHighlighted: true}},
	}}
	maskContextLines(findings, false)
	got := findings[0].CodeLines[0].Code
	if strings.Contains(got, "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC") {
		t.Errorf("escaped PEM body leaked through code context: %q", got)
	}
	if !strings.Contains(got, "****") {
		t.Errorf("code context was not masked: %q", got)
	}
}
