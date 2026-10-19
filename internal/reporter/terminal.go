package reporter

import (
	"fmt"
	"io"
	"unicode"

	"github.com/its-hixye/chainfault/internal/normalizer"
	"github.com/its-hixye/chainfault/internal/risk"
)

// ANSI colours. They are only emitted when the output is a terminal; the CLI
// decides that and passes a plain io.Writer otherwise.
const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiDim    = "\x1b[2m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiOrange = "\x1b[38;5;208m"
)

// Style controls whether the terminal report emits colour escapes.
type Style struct{ Color bool }

// Terminal writes the terminal report (CHAINFAULT_DOC.md §14).
//
// tools is the status of every scanner that ran, not only the failed ones: a
// failed scanner changes the report's overall state, so the counts must be
// honest. The set of lines mirrors the HTML card exactly — severity and score,
// the type, the test-file and history-only markers, the path, the commit
// (history only), the secret, the verified flag and the commit count.
// `Entropy:` and `Found by:` are deliberately absent: they are data, not report
// content, and so is the decoder: which encoder a secret came from is an
// implementation detail of the decoding scanner, not a finding about the leak.
func Terminal(w io.Writer, findings []normalizer.Finding, tools []ToolStatus, reveal bool, st Style) {
	failed := failedTools(tools)

	if len(findings) == 0 {
		if len(failed) == 0 {
			fmt.Fprintln(w, st.color(ansiGreen, "✔ Repository is clean, no issues found"))
		} else {
			fmt.Fprintln(w, st.color(ansiOrange, "! Scan incomplete — the repository cannot be certified clean"))
		}
		writeFailedTools(w, failed, st)
		fmt.Fprintln(w, "\n"+totalLine(0, 0))
		return
	}

	for _, f := range findings {
		writeFinding(w, f, reveal, st)
		fmt.Fprintln(w)
	}

	writeFailedTools(w, failed, st)
	if len(failed) > 0 {
		fmt.Fprintf(w, "Scan incomplete: %d of %d scanners failed — results may be missing.\n\n",
			len(failed), len(tools))
	}
	fmt.Fprintln(w, totalLine(len(findings), FileCount(findings)))
}

// totalLine renders the closing count line with correct grammar for every
// count: "Total: 1 finding across 1 file", "Total: 0 findings across 0 files",
// "Total: 7 findings across 3 files".
func totalLine(findings, files int) string {
	return fmt.Sprintf("Total: %s across %s",
		countWithNoun(findings, "finding", "findings"),
		countWithNoun(files, "file", "files"))
}

// countWithNoun renders "1 finding" but "2 findings" (and "0 findings"): only
// exactly one takes the singular noun.
func countWithNoun(n int, singular, plural string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, singular)
	}
	return fmt.Sprintf("%d %s", n, plural)
}

// failedTools returns only the scanners that did not run to completion.
func failedTools(tools []ToolStatus) []ToolStatus {
	var failed []ToolStatus
	for _, t := range tools {
		if !t.OK {
			failed = append(failed, t)
		}
	}
	return failed
}

// writeFinding renders one secret's block.
func writeFinding(w io.Writer, f normalizer.Finding, reveal bool, st Style) {
	head := fmt.Sprintf("[%s %d/10] %s",
		capitalizeSeverity(f.Severity), f.Score, normalizer.Sanitize(f.SecretType))
	if f.IsTestFile {
		head += " (test file)"
	}
	if f.HistoryOnly {
		head += " (history only)"
	}
	fmt.Fprintf(w, "%s\n", st.color(severityColor(f.Severity), head))

	location := fmt.Sprintf("%s:%d", normalizer.Sanitize(f.FilePath), f.Line)
	fmt.Fprintf(w, "Path:     %s\n", location)

	// The commit line is shown only for a history-only finding; for anything
	// still in the file it would just be the current commit.
	if f.HistoryOnly {
		fmt.Fprintf(w, "Commit:   %s — %s — %s\n",
			normalizer.ShortHash(f.CommitHash),
			normalizer.Sanitize(f.CommitDate),
			normalizer.Sanitize(f.CommitAuthor))
	}

	fmt.Fprintf(w, "Secret:   %s\n", secretLine(f, reveal))

	// No decoder line: the encoder a secret was found in is scanner detail, not
	// something the reader can act on.
	if f.Verified {
		fmt.Fprintln(w, "Verified live: yes")
	}
	if f.SeenInCommits > 1 {
		fmt.Fprintf(w, "Seen in:  %d commits\n", f.SeenInCommits)
	}
}

// secretLine formats `NAME = "value"`, or just `"value"` when no unambiguous
// variable name could be extracted from the code line.
func secretLine(f normalizer.Finding, reveal bool) string {
	value := f.MaskedSecret
	if reveal {
		value = normalizer.Sanitize(f.SecretValue)
	}
	quoted := `"` + value + `"`
	if f.SecretKeyName == "" {
		return quoted
	}
	return normalizer.Sanitize(f.SecretKeyName) + " = " + quoted
}

// writeFailedTools prints the Failed Scanner Tools block in red (terminal
// counterpart of the HTML block). This is the only place a tool name appears.
func writeFailedTools(w io.Writer, failed []ToolStatus, st Style) {
	if len(failed) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s\n", st.color(ansiRed, "Failed Scanner Tools"))
	for _, t := range failed {
		reason := normalizer.Sanitize(t.Reason)
		if reason == "" {
			reason = "process exited with an error"
		}
		fmt.Fprintf(w, "  %-12s %s\n", normalizer.Sanitize(t.Name), st.color(ansiRed, reason))
	}
}

// capitalizeSeverity renders the stored lowercase severity (critical, high,
// medium, low) with a capital first letter — Critical, High, Medium, Low — as
// CHAINFAULT_DOC.md §14 requires. The stored value and the sort order are not
// touched.
func capitalizeSeverity(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

func severityColor(severity string) string {
	switch severity {
	case risk.Critical:
		return ansiRed
	case risk.High:
		return ansiOrange
	case risk.Medium:
		return ansiYellow
	default:
		return ansiGreen
	}
}

// color wraps s in an escape sequence when colour is enabled.
func (s Style) color(code, text string) string {
	if !s.Color || code == "" {
		return text
	}
	return code + text + ansiReset
}
