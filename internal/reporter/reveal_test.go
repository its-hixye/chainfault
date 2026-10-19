package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/its-hixye/chainfault/internal/normalizer"
	"github.com/its-hixye/chainfault/templates"
)

// fakeToken is a fabricated credential used only by these tests. It matches
// the GitHub PAT shape so the scanners' normalization path is realistic, but it
// is not a real credential.
//
// It is assembled from two halves at compile time so that no single line of this
// source file ever contains a complete, real-looking GitHub token (CHAINFAULT_DOC.md
// §22). The joined value is byte-for-byte the original token.
const fakeToken = "ghp_A1b2C3d4E5f6" + "G7h8I9j0KlMnOpQrStUvWxYz"

const injectionTag = `<script type="application/json" id="injected-report-data">`

// maskedToken is the display form of fakeToken per normalizer.Mask (>= 12
// characters -> first4 + "****" + last4).
var maskedToken = "ghp_****WxYz"

// revealTestReport builds a one-finding report the way BuildReport does for a
// single leaked GitHub token with its code context.
func revealTestReport(reveal bool) Report {
	finding := Finding{
		ID:            "sec-1",
		TypeLabel:     "GitHub token",
		Location:      "config.py:2",
		Severity:      "critical",
		Score:         9,
		SecretKeyName: "token",
		MaskedSecret:  maskedToken,
		Commit:        Commit{Hash: "abc1234", Date: "Oct 18, 2026", Author: "dev"},
		CodeSnippet: CodeSnippet{
			Language: "python",
			Lines: []CodeLine{
				{Number: 1, Code: "# settings"},
				{
					Number:        2,
					Code:          `token = "` + maskedToken + `"`,
					IsHighlighted: true,
				},
				{Number: 3, Code: "debug = False"},
			},
		},
	}
	if reveal {
		finding.RawSecret = fakeToken
		for i := range finding.CodeSnippet.Lines {
			// maskContextLines keeps the original line for the reveal toggle.
			finding.CodeSnippet.Lines[i].CodeRaw = originalLine(finding.CodeSnippet.Lines[i].Number)
		}
	}

	return Report{
		Meta:       Meta{ProjectName: "demo", ProjectPath: "/tmp/demo", CommitsScanned: 1, Reveal: reveal},
		ToolStatus: []ToolStatus{{Name: "gitleaks", OK: true}},
		Findings:   []Finding{finding},
	}
}

func originalLine(number int) string {
	if number == 2 {
		return `token = "` + fakeToken + `"`
	}
	if number == 1 {
		return "# settings"
	}
	return "debug = False"
}

// writeAndReadReport renders the report with the production WriteHTML and
// returns the written file contents.
func writeAndReadReport(t *testing.T, rep Report) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")
	if err := WriteHTML(path, rep); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	return string(data)
}

// injectedData extracts and unmarshals the JSON the template injects.
func injectedData(t *testing.T, out string) Report {
	t.Helper()
	idx := strings.Index(out, injectionTag)
	if idx < 0 {
		t.Fatalf("report is missing the injection tag %s", injectionTag)
	}
	raw := out[idx+len(injectionTag):]
	if end := strings.Index(raw, "</script>"); end >= 0 {
		raw = raw[:end]
	}
	var rep Report
	if err := json.Unmarshal([]byte(raw), &rep); err != nil {
		t.Fatalf("unmarshal injected report data: %v", err)
	}
	return rep
}

// TestWriteHTMLWithoutRevealLeaksNothing locks in the no-reveal contract: the
// raw secret must not exist anywhere in the written file, rawSecret is empty,
// and no code line carries a raw value.
func TestWriteHTMLWithoutRevealLeaksNothing(t *testing.T) {
	out := writeAndReadReport(t, revealTestReport(false))

	if strings.Contains(out, fakeToken) {
		t.Errorf("report written without --reveal contains the full secret")
	}

	rep := injectedData(t, out)
	if len(rep.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(rep.Findings))
	}
	f := rep.Findings[0]
	if f.RawSecret != "" {
		t.Errorf("rawSecret = %q, want empty without --reveal", f.RawSecret)
	}
	if f.MaskedSecret != maskedToken {
		t.Errorf("maskedSecret = %q, want %q", f.MaskedSecret, maskedToken)
	}
	for _, l := range f.CodeSnippet.Lines {
		if l.CodeRaw != "" {
			t.Errorf("line %d: codeRaw = %q, want empty without --reveal", l.Number, l.CodeRaw)
		}
		if strings.Contains(l.Code, fakeToken) {
			t.Errorf("line %d: code leaks the raw secret", l.Number)
		}
	}
	if strings.Contains(out, `"codeRaw"`) {
		t.Error("written report must not contain a codeRaw field without --reveal")
	}
}

// TestWriteHTMLWithRevealExposesRawCodeOnly checks that --reveal is an explicit
// opt-in: the full secret and the original code line are present, while `code`
// stays masked so hiding restores the masked line.
func TestWriteHTMLWithRevealExposesRawCodeOnly(t *testing.T) {
	out := writeAndReadReport(t, revealTestReport(true))

	if !strings.Contains(out, fakeToken) {
		t.Errorf("report written with --reveal does not contain the full secret")
	}

	rep := injectedData(t, out)
	if !rep.Meta.Reveal {
		t.Error("meta.reveal must be true")
	}
	f := rep.Findings[0]
	if f.RawSecret != fakeToken {
		t.Errorf("rawSecret = %q, want the full secret with --reveal", f.RawSecret)
	}
	if f.MaskedSecret != maskedToken {
		t.Errorf("maskedSecret = %q, want %q", f.MaskedSecret, maskedToken)
	}

	var sawRaw bool
	for _, l := range f.CodeSnippet.Lines {
		if l.CodeRaw != "" {
			sawRaw = true
		}
		if strings.Contains(l.Code, fakeToken) {
			t.Errorf("line %d: masked `code` must stay masked even with --reveal", l.Number)
		}
	}
	if !sawRaw {
		t.Fatal("no codeRaw lines with --reveal")
	}
	for _, l := range f.CodeSnippet.Lines {
		if l.Number == 2 {
			if l.CodeRaw != originalLine(2) {
				t.Errorf("highlighted codeRaw = %q, want the ORIGINAL unmasked line", l.CodeRaw)
			}
			if l.Code != `token = "`+maskedToken+`"` {
				t.Errorf("highlighted code = %q, want the masked line", l.Code)
			}
		}
	}
}

// TestMaskContextLinesShortSecretMasksContext covers the short-secret gap: a
// value shorter than four characters used to skip masking and leak verbatim
// through the code context. Every line must come out masked in both reveal
// modes, and CodeRaw holds the original line only with reveal.
func TestMaskContextLinesShortSecretMasksContext(t *testing.T) {
	for _, reveal := range []bool{false, true} {
		findings := []normalizer.Finding{{
			SecretValue: "abc",
			CodeLines: []normalizer.CodeLine{
				{Number: 1, Code: `short = "abc"`, IsHighlighted: true},
				{Number: 2, Code: "unrelated = 1"},
			},
		}}

		maskContextLines(findings, reveal)

		lines := findings[0].CodeLines
		if strings.Contains(lines[0].Code, `"abc"`) {
			t.Errorf("reveal=%v: code context still exposes the raw short secret: %q", reveal, lines[0].Code)
		}
		if lines[0].Code != `short = "ab****"` {
			t.Errorf("reveal=%v: masked line = %q, want %q", reveal, lines[0].Code, `short = "ab****"`)
		}
		if lines[1].Code != "unrelated = 1" {
			t.Errorf("reveal=%v: unrelated line was modified: %q", reveal, lines[1].Code)
		}
		if reveal {
			if lines[0].CodeRaw != `short = "abc"` {
				t.Errorf("reveal=true: codeRaw = %q, want the original line", lines[0].CodeRaw)
			}
			if lines[1].CodeRaw != "unrelated = 1" {
				t.Errorf("reveal=true: codeRaw = %q, want the original line", lines[1].CodeRaw)
			}
		}
		if !reveal {
			for _, l := range lines {
				if l.CodeRaw != "" {
					t.Errorf("reveal=false: line %d codeRaw = %q, want empty", l.Number, l.CodeRaw)
				}
				if l.CodeRaw == l.Code && strings.Contains(l.Code, "abc") {
					t.Errorf("reveal=false: line %d CodeRaw must never hold the masked line", l.Number)
				}
			}
		}
	}
}

// TestMaskContextLinesEmptySecretIsIgnored guards the empty-value case: an empty
// needle must never be replaced, which would shred every code line.
func TestMaskContextLinesEmptySecretIsIgnored(t *testing.T) {
	findings := []normalizer.Finding{{
		SecretValue: "",
		CodeLines:   []normalizer.CodeLine{{Number: 1, Code: "code = 1"}},
	}}
	maskContextLines(findings, false)
	if got := findings[0].CodeLines[0].Code; got != "code = 1" {
		t.Errorf("empty secret changed the code line: %q", got)
	}
}

// TestTemplateGuardsRevealAndCopy is a code-level check of the template's
// contract (not a DOM check): the eye button is behind the canReveal guard, the
// copy button is always rendered, and both the card and the copy handler pick
// the secret from the currently displayed state.
func TestTemplateGuardsRevealAndCopy(t *testing.T) {
	tmpl := templates.ReportHTML

	const (
		guard     = "${canReveal ? `"
		eye       = `data-action="toggle-card-secret"`
		copy      = `data-action="copy-secret"`
		selection = "isRevealed ? (finding.rawSecret || finding.maskedSecret) : finding.maskedSecret"
	)

	guardIdx := strings.Index(tmpl, guard)
	if guardIdx < 0 {
		t.Fatal("eye button is not guarded by the canReveal conditional")
	}
	eyeIdx := strings.Index(tmpl[guardIdx:], eye)
	if eyeIdx < 0 {
		t.Error("no toggle-card-secret button rendered behind the canReveal guard")
	}
	if strings.Count(tmpl, eye) != 1 {
		t.Errorf("expected exactly one toggle-card-secret button, got %d", strings.Count(tmpl, eye))
	}
	if strings.Contains(tmpl[guardIdx:], copy) && strings.Index(tmpl[guardIdx:], copy) < eyeIdx {
		t.Error("the copy button must not live inside the canReveal-only block")
	}
	if !strings.Contains(tmpl, copy) {
		t.Error("the copy button must always be rendered")
	}

	// Card display and the copy handler both select on the revealed state, so a
	// second click (re-mask) falls back to maskedSecret.
	if n := strings.Count(tmpl, selection); n < 2 {
		t.Errorf("expected the displayed-state selection in both the card and the copy handler, found %d occurrences", n)
	}
	if !strings.Contains(tmpl, `const canReveal = REPORT_DATA.meta.reveal;`) {
		t.Error("canReveal is not derived from meta.reveal")
	}
	// Raw code context is gated on reveal as well.
	if !strings.Contains(tmpl, "(REPORT_DATA.meta.reveal && isRevealed && finding.rawSecret && line.codeRaw) ? line.codeRaw : line.code") {
		t.Error("the code line must fall back to line.code unless reveal is on")
	}
}
