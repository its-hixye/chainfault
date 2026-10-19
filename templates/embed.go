// Package templates embeds the static assets Chainfault ships with.
//
// The HTML report template and the Gitleaks configuration live in this
// directory, so //go:embed can reach them (Go forbids embedding files from
// parent directories, which is why the assets are embedded here instead of in
// internal/reporter and internal/scanner).
package templates

import _ "embed"

// ReportHTML is the production HTML report template. It contains a single
// injection point: {{ .ReportData }} (CHAINFAULT_DOC.md §15).
//
//go:embed report.html
var ReportHTML string

// GitleaksConfig is the Gitleaks configuration Chainfault passes with -c so a
// scanned repository cannot change the scan rules (CHAINFAULT_DOC.md §21).
// Without `useDefault = true` this file would *replace* Gitleaks' built-in
// rules and the scan would silently find nothing.
//
//go:embed config.toml
var GitleaksConfig string
