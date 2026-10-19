package reporter

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"os"
	"path/filepath"

	"github.com/its-hixye/chainfault/templates"
)

// pageData is the struct handed to the HTML template. ReportData is the only
// thing that is substituted into the template, at the single injection point
// `{{ .ReportData }}` (CHAINFAULT_DOC.md §15).
type pageData struct {
	ReportData template.JS
}

// WriteHTML renders the HTML report to outputPath.
//
// The template is parsed with html/template and the data is injected as
// template.JS so it is not escaped twice: json.Marshal already replaced every
// `<`, `>` and `&` with \u003c, \u0026, so a repository line containing
// `</script>` cannot close the tag or inject code.
//
// The file is written 0600 — owner read/write only — because with --reveal it
// contains full secrets (CHAINFAULT_DOC.md §19, §24).
func WriteHTML(outputPath string, rep Report) error {
	jsonBytes, err := json.Marshal(rep)
	if err != nil {
		return fmt.Errorf("encode report data: %w", err)
	}

	tmpl, err := template.New("report.html").Parse(templates.ReportHTML)
	if err != nil {
		return fmt.Errorf("parse report template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, pageData{ReportData: template.JS(jsonBytes)}); err != nil {
		return fmt.Errorf("render report template: %w", err)
	}

	if err := os.WriteFile(outputPath, buf.Bytes(), 0o600); err != nil {
		return fmt.Errorf("write report: %w", err)
	}
	// WriteFile only applies the mode when it creates the file; make sure an
	// overwrite of an existing, world-readable file is tightened too.
	if err := os.Chmod(outputPath, 0o600); err != nil {
		return fmt.Errorf("secure report permissions: %w", err)
	}
	return nil
}

// DefaultOutputPath builds the default report filename:
// chainfault-report-<project>-<YYYY-MM-DD-HHMM>.html in dir. The timestamp is
// in the name so an older report is never overwritten by a newer run.
func DefaultOutputPath(dir, projectName, timestamp string) string {
	name := fmt.Sprintf("chainfault-report-%s-%s.html", projectName, timestamp)
	return filepath.Join(dir, name)
}
