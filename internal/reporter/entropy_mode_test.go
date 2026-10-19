package reporter

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/its-hixye/chainfault/internal/normalizer"
	"github.com/its-hixye/chainfault/internal/risk"
	"github.com/its-hixye/chainfault/templates"
)

// entropyProbe is a deliberately distinctive entropy value. It is used as the
// Finding.Entropy of every fixture below so that a substring match inside a
// rendered report is proof of a leak and can never be a coincidence.
const entropyProbe = "7.3141"

// entropyProbeValue is entropyProbe as the float64 the findings actually carry.
const entropyProbeValue = 7.3141

// entropyFinding builds a normalizer.Finding whose Entropy is the probe value.
// repTestFinding comes from reporter_test.go (same package).
func entropyFinding() normalizer.Finding {
	return repTestFinding(func(f *normalizer.Finding) {
		f.Severity = risk.Critical
		f.Score = 9
		f.HistoryOnly = true // keeps the block stable; irrelevant to entropy
		f.Entropy = entropyProbeValue
	})
}

// jsonIslandTag is the exact opening tag of the one place where the reporter
// injects the marshaled report. CHAINFAULT_DOC.md §15 puts the findings there,
// and §10/§20 say the entropy field is KEPT in that JSON: carrying it inside the
// injected data is the documented contract, not a display leak.
const jsonIslandTag = `<script type="application/json" id="injected-report-data">`

// jsonIsland returns the injected data island of a rendered report, tags
// included, and fails the test when it is missing.
func jsonIsland(t *testing.T, html string) string {
	t.Helper()

	start := strings.Index(html, jsonIslandTag)
	if start < 0 {
		t.Fatalf("the injected data island %q is missing from the rendered report", jsonIslandTag)
	}
	rest := html[start:]
	end := strings.Index(rest, "</script>")
	if end < 0 {
		t.Fatalf("the injected data island is not closed with </script>")
	}
	return rest[:end+len("</script>")]
}

// withoutJSONIsland returns the report with its injected data island removed,
// i.e. everything a browser actually displays.
func withoutJSONIsland(t *testing.T, html string) string {
	t.Helper()
	return strings.Replace(html, jsonIsland(t, html), "", 1)
}

var (
	htmlCommentRE  = regexp.MustCompile(`(?s)<!--.*?-->`)
	blockCommentRE = regexp.MustCompile(`(?s)/\*.*?\*/`)
)

// stripComments removes HTML comments and JavaScript /* ... */ block comments.
// It is deliberately literal — it never removes executable markup or script, so
// the stripper itself can never hide a reference. Line comments are handled per
// occurrence by lineCommented.
func stripComments(src string) string {
	return blockCommentRE.ReplaceAllString(htmlCommentRE.ReplaceAllString(src, ""), "")
}

// lineCommented reports whether the byte at pos sits inside a // line comment,
// i.e. whether a "//" appears earlier on the same line.
func lineCommented(src string, pos int) bool {
	lineStart := strings.LastIndexByte(src[:pos], '\n') + 1
	return strings.Contains(src[lineStart:pos], "//")
}

// entropyReferences returns every occurrence of needle (lower case) in src that
// is NOT inside a // line comment, each described with its byte offset, 1-based
// line number and a short escaped window, so a failure is exact and copy-pastable.
// Pass src through stripComments first.
func entropyReferences(src, needle string) []string {
	var out []string
	lower := strings.ToLower(src)
	for from := 0; ; {
		i := strings.Index(lower[from:], needle)
		if i < 0 {
			break
		}
		pos := from + i
		if !lineCommented(src, pos) {
			start := pos - 30
			if start < 0 {
				start = 0
			}
			end := pos + len(needle) + 30
			if end > len(src) {
				end = len(src)
			}
			window := strings.NewReplacer("\n", `\n`, "\r", `\r`, "\t", `\t`).Replace(src[start:end])
			line := 1 + strings.Count(src[:pos], "\n")
			out = append(out, fmt.Sprintf("byte offset %d (line %d): ...%s...", pos, line, window))
		}
		from = pos + len(needle)
	}
	return out
}

// writeHTMLWithEntropy runs the real write path (reporter.WriteHTML) with a
// finding whose Entropy is the probe value and returns the bytes it wrote.
func writeHTMLWithEntropy(t *testing.T, reveal bool) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.html")
	rep := BuildReport(Meta{Reveal: reveal},
		[]ToolStatus{{Name: "gitleaks", OK: true}},
		[]normalizer.Finding{entropyFinding()}, reveal)
	if err := WriteHTML(path, rep); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read written report %s: %v", path, err)
	}
	return string(raw)
}

// ---------------------------------------------------------------------------
// TASK 1 — the written HTML report is always 0600
// ---------------------------------------------------------------------------

// TestWriteHTMLFileModeIsAlways0600 runs the real write path and checks the
// on-disk permission bits, with and without reveal, plus the tighten-on-
// overwrite case. os.Stat's Mode() is masked to the low 9 bits so only the
// permission bits are compared.
func TestWriteHTMLFileModeIsAlways0600(t *testing.T) {
	cases := []struct {
		name   string
		reveal bool
	}{
		{name: "without reveal", reveal: false},
		{name: "with reveal", reveal: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "report.html")
			rep := BuildReport(Meta{Reveal: tc.reveal},
				[]ToolStatus{{Name: "gitleaks", OK: true}},
				[]normalizer.Finding{entropyFinding()}, tc.reveal)

			if err := WriteHTML(path, rep); err != nil {
				t.Fatalf("WriteHTML: %v", err)
			}

			info, err := os.Stat(path)
			if err != nil {
				t.Fatalf("stat %s: %v", path, err)
			}
			if info.Size() == 0 {
				t.Errorf("report file %s is empty", path)
			}
			if got := info.Mode() & 0o777; got != 0o600 {
				t.Errorf("report file mode = %#o, want 0600", got)
			}
		})
	}

	// Overwriting a pre-existing, world-readable report must tighten it too:
	// os.WriteFile only applies the mode on create.
	t.Run("overwrite tightens a 0644 file", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "report.html")
		if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
			t.Fatalf("seed world-readable file: %v", err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatalf("chmod seed file: %v", err)
		}

		rep := BuildReport(Meta{}, nil, []normalizer.Finding{entropyFinding()}, false)
		if err := WriteHTML(path, rep); err != nil {
			t.Fatalf("WriteHTML: %v", err)
		}

		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", path, err)
		}
		if got := info.Mode() & 0o777; got != 0o600 {
			t.Errorf("overwritten report mode = %#o, want 0600", got)
		}
	})
}

// ---------------------------------------------------------------------------
// TASK 2(a) — the TERMINAL report never displays entropy
// ---------------------------------------------------------------------------

// TestTerminalNeverDisplaysEntropy renders the terminal report with a finding
// whose Entropy is the probe value and checks the rendered text carries neither
// the value nor the word "entropy", with and without reveal.
func TestTerminalNeverDisplaysEntropy(t *testing.T) {
	for _, reveal := range []bool{false, true} {
		t.Run(fmt.Sprintf("reveal=%v", reveal), func(t *testing.T) {
			var buf bytes.Buffer
			Terminal(&buf, []normalizer.Finding{entropyFinding()},
				[]ToolStatus{{Name: "gitleaks", OK: true}}, reveal, Style{})
			out := buf.String()

			if strings.Contains(out, entropyProbe) {
				t.Errorf("terminal output contains the entropy value %q\n%s", entropyProbe, out)
			}
			if strings.Contains(strings.ToLower(out), "entropy") {
				t.Errorf("terminal output contains the word \"entropy\"\n%s", out)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TASK 2(b) — the HTML report never DISPLAYS entropy
// ---------------------------------------------------------------------------
//
// Entropy legitimately travels inside the injected JSON island: CHAINFAULT_DOC.md
// §10 and §20 keep the field in the stored data and only forbid showing it. So
// the check is not "the file must not contain the string" — it is "nothing the
// browser displays may contain it": the rendered document with the data island
// removed must be clean, and the production template source must not read or
// print the field anywhere outside its comments.

// TestHTMLReportNeverDisplaysEntropy renders the report through the real write
// path, removes the injected data island, and asserts the rest of the document
// carries neither the entropy value nor the word "entropy", with and without
// reveal. It also asserts the island DID carry the field, so the test cannot
// pass by accident on a report that lost its data.
func TestHTMLReportNeverDisplaysEntropy(t *testing.T) {
	for _, reveal := range []bool{false, true} {
		t.Run(fmt.Sprintf("reveal=%v", reveal), func(t *testing.T) {
			full := writeHTMLWithEntropy(t, reveal)

			// Positive control: the data island must really carry the field.
			island := jsonIsland(t, full)
			if !strings.Contains(island, `"entropy":`+entropyProbe) {
				t.Errorf("the injected data island does not carry the entropy field %q; the data contract or the fixture changed:\n%s",
					entropyProbe, island)
			}

			body := withoutJSONIsland(t, full)
			if strings.Contains(body, jsonIslandTag) {
				t.Fatalf("the injected data island is still present after removal")
			}
			// Anti-vacuity guard: the remainder must still be the real document, so
			// this test cannot pass by accidentally looking at nothing.
			if len(body) < len(full)/2 || !strings.Contains(body, "</html>") {
				t.Fatalf("removing the data island left %d of %d bytes; the check would be vacuous", len(body), len(full))
			}
			for _, needle := range []string{entropyProbe, "entropy"} {
				for _, hit := range entropyReferences(body, strings.ToLower(needle)) {
					t.Errorf("the rendered report displays %q outside the injected data island: %s", needle, hit)
				}
			}
		})
	}
}

// TestTemplateSourceNeverReadsOrPrintsEntropy checks the production template
// itself: after HTML and /* */ comments are stripped (and per-occurrence //
// comments ignored), no ".entropy", ["entropy"], ['entropy'] or bare "entropy"
// reference may remain in executable markup or script. templates.ReportHTML is
// the embedded copy of templates/report.html — the exact bytes that get served.
func TestTemplateSourceNeverReadsOrPrintsEntropy(t *testing.T) {
	src := stripComments(templates.ReportHTML)

	for _, needle := range []string{".entropy", `["entropy"]`, "['entropy']", "entropy"} {
		for _, hit := range entropyReferences(src, needle) {
			t.Errorf("the production template reads or prints %q outside a comment: %s", needle, hit)
		}
	}
}
