package reporter

import (
	"bytes"
	"encoding/json"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/its-hixye/chainfault/internal/normalizer"
	"github.com/its-hixye/chainfault/templates"
)

// renderForTest renders the production HTML template the same way WriteHTML
// does, but into memory.
func renderForTest(t *testing.T, rep Report) string {
	t.Helper()

	jsonBytes, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	tmpl, err := template.New("report.html").Parse(templates.ReportHTML)
	if err != nil {
		t.Fatalf("parse template: %v", err)
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, pageData{ReportData: template.JS(jsonBytes)}); err != nil {
		t.Fatalf("execute template: %v", err)
	}
	return buf.String()
}

// TestRenderedTemplateHasNoPreviewLeftovers locks in the cleanup of the
// production template: no sample/preview data, no preview query-string states,
// and the report data must come from the injected JSON tag only.
func TestRenderedTemplateHasNoPreviewLeftovers(t *testing.T) {
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
		Findings: []Finding{{
			ID:            "sec-1",
			TypeLabel:     "AWS key",
			Location:      "config.py:1",
			Severity:      "critical",
			Score:         9,
			SecretKeyName: "AWS_SECRET_KEY",
			MaskedSecret:  "AKIA****************XMPL",
		}},
	}

	out := renderForTest(t, rep)

	for _, banned := range []string{"SAMPLE_REPORT_DATA", "previewState", "state=reveal", "isRevealState"} {
		if strings.Contains(out, banned) {
			t.Errorf("rendered report must not contain %q", banned)
		}
	}

	const tag = `<script type="application/json" id="injected-report-data">`
	idx := strings.Index(out, tag)
	if idx < 0 {
		t.Fatalf("rendered report is missing the injection tag %s", tag)
	}
	injected := out[idx+len(tag):]
	if end := strings.Index(injected, "</script>"); end >= 0 {
		injected = injected[:end]
	}
	if !strings.Contains(injected, `"findings"`) || !strings.Contains(injected, "AKIA****************XMPL") {
		t.Errorf("injected JSON tag does not carry the report data: %q", injected)
	}
}

// TestWriteHTMLInjectsDataOnlyReport is the file-level counterpart: the written
// report contains the injected JSON and none of the removed preview leftovers.
func TestWriteHTMLInjectsDataOnlyReport(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "report.html")

	rep := Report{
		Meta:     Meta{ProjectName: "demo", ProjectPath: "/tmp/demo", CommitsScanned: 1},
		Findings: []Finding{},
	}
	if err := WriteHTML(path, rep); err != nil {
		t.Fatalf("WriteHTML: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	out := string(data)

	for _, banned := range []string{"SAMPLE_REPORT_DATA", "previewState", "state=reveal", "isRevealState"} {
		if strings.Contains(out, banned) {
			t.Errorf("written report must not contain %q", banned)
		}
	}
	if !strings.Contains(out, `<script type="application/json" id="injected-report-data">`) {
		t.Error("written report is missing the injection tag")
	}
}

// badgesReport builds a one-finding report for the badge assertions. The card
// renderer is client-side, so these are STRING-PRESENCE checks on the rendered
// document (which embeds the renderer verbatim) plus a check of the injected
// JSON — no browser and no JS runtime, matching the existing template tests.
func badgesReport(verified bool) Report {
	return Report{
		Meta:       Meta{ProjectName: "demo", ProjectPath: "/tmp/demo", CommitsScanned: 1},
		ToolStatus: []ToolStatus{{Name: "gitleaks", OK: true}},
		Findings: []Finding{{
			ID:            "sec-1",
			TypeLabel:     "AWS key",
			Location:      "config.py:5",
			Severity:      "critical",
			Score:         9,
			SecretKeyName: "ENV_KEY",
			MaskedSecret:  "AKIA****************XMPL",
			Verified:      verified,
		}},
	}
}

// TestReportRendersVerifiedLiveBadge checks the verified marker reads "Verified
// live" (--verify only) and that the flag reaches the injected JSON unchanged.
func TestReportRendersVerifiedLiveBadge(t *testing.T) {
	out := renderForTest(t, badgesReport(true))

	if !strings.Contains(out, "Verified live") {
		t.Error(`the finding card must carry the "Verified live" badge`)
	}
	// The badge must stay driven by the verified flag.
	if !strings.Contains(out, "finding.verified") {
		t.Error("the verified badge must still be rendered from finding.verified")
	}
	// The old lowercase-only label is gone.
	const oldBadge = ">verified</span>"
	if strings.Contains(out, oldBadge) {
		t.Errorf(`the old lowercase badge %q must be gone`, oldBadge)
	}
	if !strings.Contains(out, `"verified":true`) {
		t.Error("a verified finding must inject verified:true into the report data")
	}

	unverified := renderForTest(t, badgesReport(false))
	if !strings.Contains(unverified, `"verified":false`) {
		t.Error("an unverified finding must inject verified:false into the report data")
	}
	if !strings.Contains(unverified, "Verified live") {
		t.Error("the badge template must stay in the document for unverified reports too")
	}
}

// TestReportHasNoDecoderBadge checks the decoder information is gone from the
// HTML report: the badge, the renderer branch and the JSON field that fed it.
func TestReportHasNoDecoderBadge(t *testing.T) {
	out := renderForTest(t, badgesReport(true))

	for _, banned := range []string{
		"decodedFrom",
		"decoded from",
		"Decoder Badge",
		"Decoder",
	} {
		if strings.Contains(out, banned) {
			t.Errorf("the HTML report must not contain decoder information (%q)", banned)
		}
	}
}

// TestBuildReportOmitsDecoderField is the JSON-contract half: even when the
// internal finding carries a decoder, the display shape must not.
func TestBuildReportOmitsDecoderField(t *testing.T) {
	rep := BuildReport(Meta{ProjectName: "demo"}, nil, []normalizer.Finding{
		{
			FilePath:    "config.py",
			Line:        5,
			SecretType:  "AWS key",
			SecretValue: repTestRaw,
			DecodedFrom: "BASE64",
			Verified:    true,
		},
	}, false)

	if len(rep.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(rep.Findings))
	}
	if !rep.Findings[0].Verified {
		t.Error("Verified must survive the conversion to the display shape")
	}

	data, err := json.Marshal(rep)
	if err != nil {
		t.Fatalf("marshal report: %v", err)
	}
	if strings.Contains(string(data), "decodedFrom") {
		t.Errorf("the report data must not carry a decoder field: %s", data)
	}
	if strings.Contains(string(data), "BASE64") {
		t.Errorf("the report data must not carry the decoder name: %s", data)
	}
}
