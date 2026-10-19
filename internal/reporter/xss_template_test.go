package reporter

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// xssPayload is repository-controlled text that tries to break out of the
// <script type="application/json"> injection point and inject markup. It also
// carries an ampersand and a double quote so the HTML-entity escaping of `<`,
// `>` and `&` is exercised too.
const xssPayload = `</script><img src=x onerror=alert(1)>&".py`

// xssReport builds a one-finding report whose repository-controlled strings
// (path/location and variable name) carry the payload. Everything else mirrors
// what BuildReport produces for a single leaked credential.
func xssReport() Report {
	return Report{
		Meta: Meta{
			ProjectName:    `demo<img src=x onerror=alert(2)>`,
			ProjectPath:    "/tmp/" + xssPayload,
			ScanDate:       "Oct 18, 2026",
			ScanDuration:   "1.2s",
			ScanCommand:    `chainfault scan </script><img src=x onerror=alert(3)>`,
			CommitsScanned: 1,
			CommitHash:     "abc1234",
			Branch:         "main",
		},
		ToolStatus: []ToolStatus{{Name: "gitleaks", OK: true}},
		Findings: []Finding{{
			ID:            "sec-1",
			TypeLabel:     "GitHub token",
			Location:      xssPayload + `:1`,
			Severity:      "critical",
			Score:         9,
			SecretKeyName: `token_"&` + xssPayload,
			MaskedSecret:  "ghp_****WxYz",
			FoundBy:       []string{"gitleaks", "trufflehog"},
			Commit:        Commit{Hash: "abc1234", Date: "Oct 18, 2026", Author: "dev"},
			CodeSnippet: CodeSnippet{
				Language: "python",
				Lines: []CodeLine{
					{Number: 1, Code: `token = "` + xssPayload + `"`, IsHighlighted: true},
				},
			},
		}},
	}
}

// writeXSSReport renders the report through the PRODUCTION path — the exported
// WriteHTML and the embedded templates.ReportHTML template — and returns the
// file contents. No helper re-implements the escaping: whatever WriteHTML does
// is exactly what a real `chainfault scan --html` writes to disk.
func writeXSSReport(t *testing.T, rep Report) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTML(path, rep); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	return string(data)
}

// xssInjectedJSON returns the raw JSON text inside the injection tag.
func xssInjectedJSON(t *testing.T, out string) string {
	t.Helper()
	const tag = `<script type="application/json" id="injected-report-data">`
	idx := strings.Index(out, tag)
	if idx < 0 {
		t.Fatalf("report is missing the injection tag %s", tag)
	}
	raw := out[idx+len(tag):]
	if end := strings.Index(raw, "</script>"); end >= 0 {
		raw = raw[:end]
	}
	return raw
}

// TestWriteHTMLNeutralizesScriptBreakoutPayload renders through the production
// WriteHTML path (embedded template, not a standalone helper) and asserts the
// two halves of the XSS contract from CHAINFAULT_DOC.md §15/§24:
//
//  1. the embedded report data carries the HTML-sensitive characters in their
//     escaped JSON form (< > &) instead of literally; and
//  2. the raw breakout substring never appears anywhere in the output, so the
//     </script> cannot close the tag and no <img onerror> can be injected.
//
// The payload is a fabricated string, not a real credential, and the test runs
// fully offline.
func TestWriteHTMLNeutralizesScriptBreakoutPayload(t *testing.T) {
	out := writeXSSReport(t, xssReport())
	injected := xssInjectedJSON(t, out)

	// Escaped forms must be present. Raw string literals so Go does not decode
	// the \uXXXX escapes into the characters they stand for.
	for _, esc := range []string{`\u003c`, `\u003e`, `\u0026`} {
		if !strings.Contains(injected, esc) {
			t.Errorf("injected report data does not contain the escaped form %s", esc)
		}
	}

	// The breakout payload must not survive anywhere in the file: not in the
	// injected JSON, not in the surrounding markup, not in the template body.
	const breakout = "</script><img"
	if strings.Contains(out, breakout) {
		t.Errorf("raw %q appears in the generated HTML — the script tag can be closed and markup injected", breakout)
	}
	// Guard the other half too: no unescaped <img from the payload either.
	if strings.Contains(out, `<img src=x onerror=alert(1)>`) {
		t.Error("unescaped <img src=x onerror=...> appears in the generated HTML")
	}

	// The escaping must not corrupt the data: unmarshalling the escaped JSON
	// must give back the original repository-controlled strings.
	var rep Report
	if err := json.Unmarshal([]byte(injected), &rep); err != nil {
		t.Fatalf("unmarshal injected report data: %v", err)
	}
	if len(rep.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(rep.Findings))
	}
	if got, want := rep.Findings[0].Location, xssPayload+`:1`; got != want {
		t.Errorf("location = %q, want %q", got, want)
	}
	if !strings.HasPrefix(rep.Findings[0].SecretKeyName, `token_"&`) {
		t.Errorf("secretKeyName = %q, want it to start with %q", rep.Findings[0].SecretKeyName, `token_"&`)
	}
	if rep.Meta.ProjectName != `demo<img src=x onerror=alert(2)>` {
		t.Errorf("meta.projectName = %q, want the payload round-tripped", rep.Meta.ProjectName)
	}
}

// TestEmbeddedTemplateHasNoPreviewArtifacts is a STRING-PRESENCE regression
// check on the embedded production template. It asserts the design/preview
// leftovers are gone by looking for their literal names in the rendered
// output — it does NOT execute JavaScript, open a browser, or observe any
// runtime behavior; a browser-level check would need a JS runtime, which these
// tests deliberately do not require.
func TestEmbeddedTemplateHasNoPreviewArtifacts(t *testing.T) {
	rep := Report{
		Meta: Meta{
			ProjectName:    "demo",
			ProjectPath:    "/tmp/demo",
			ScanDate:       "Oct 18, 2026",
			ScanDuration:   "1.2s",
			ScanCommand:    "chainfault scan /tmp/demo",
			CommitsScanned: 1,
			CommitHash:     "abc1234",
			Branch:         "main",
		},
		ToolStatus: []ToolStatus{{Name: "gitleaks", OK: true}},
		Findings:   []Finding{},
	}

	out := writeXSSReport(t, rep)

	// String-presence checks only (no browser, no JS runtime): these preview
	// artifacts must not appear in the production template. Leaving any of
	// them behind would let `?state=reveal` flip meta.reveal in a shipped
	// report (CHAINFAULT_DOC.md §15, §24.4).
	for _, banned := range []string{
		"SAMPLE_REPORT_DATA",
		"previewState",
		"state=reveal",
	} {
		if strings.Contains(out, banned) {
			t.Errorf("rendered report must not contain the preview artifact %q", banned)
		}
	}
}

// TestEmbeddedTemplateKeepsRevealGuardedEyeButton is another STRING-PRESENCE
// check (no JS runtime): the eye/reveal button is rendered only when the
// renderer decides a raw secret is available (`canReveal`), and the failed
// scanner tools block must survive for operational debugging.
func TestEmbeddedTemplateKeepsRevealGuardedEyeButton(t *testing.T) {
	rep := xssReport()

	for _, reveal := range []bool{false, true} {
		rep.Meta.Reveal = reveal
		out := writeXSSReport(t, rep)
		if !strings.Contains(out, `data-action="toggle-card-secret"`) {
			t.Errorf("reveal=%v: the guarded eye button is missing from the card", reveal)
		}
		if !strings.Contains(out, "Failed Scanner Tools") {
			t.Errorf("reveal=%v: the Failed Scanner Tools block is missing", reveal)
		}
	}
}
