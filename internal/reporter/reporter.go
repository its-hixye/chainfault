// Package reporter renders the merged findings of one scan. Both the terminal
// report and the HTML report are built from the same REPORT_DATA object, so a
// field can never appear in one report and be missing from the other
// (CHAINFAULT_DOC.md §15).
package reporter

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/its-hixye/chainfault/internal/gitutil"
	"github.com/its-hixye/chainfault/internal/normalizer"
	"github.com/its-hixye/chainfault/internal/risk"
)

// Meta is the `meta` object of REPORT_DATA.
type Meta struct {
	ProjectName    string `json:"projectName"`
	ProjectPath    string `json:"projectPath"`
	ScanDate       string `json:"scanDate"`
	ScanDuration   string `json:"scanDuration"`
	ScanCommand    string `json:"scanCommand"`
	CommitsScanned int    `json:"commitsScanned"`
	CommitHash     string `json:"commitHash"`
	Branch         string `json:"branch"`
	Reveal         bool   `json:"reveal"`
}

// ToolStatus is one element of the `toolStatus` array. `name` is the tool name
// and is displayed only here — never on a finding card.
type ToolStatus struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Reason string `json:"reason,omitempty"`
}

// Commit is the commit a secret was written in.
type Commit struct {
	Hash   string `json:"hash"`
	Date   string `json:"date"`
	Author string `json:"author"`
}

// CodeLine is one rendered line of the collapsible code context.
type CodeLine struct {
	Number        int    `json:"number"`
	Code          string `json:"code"`
	CodeRaw       string `json:"codeRaw,omitempty"`
	IsHighlighted bool   `json:"isHighlighted"`
}

// CodeSnippet is the collapsible code context of a finding.
type CodeSnippet struct {
	Language string     `json:"language"`
	Lines    []CodeLine `json:"lines"`
}

// Finding is one element of the `findings` array — the display shape of an
// internal secret (CHAINFAULT_DOC.md §15). Its field names are the contract
// between Chainfault and the HTML template.
type Finding struct {
	ID string `json:"id"`

	TypeLabel     string `json:"typeLabel"`
	Location      string `json:"location"`
	Severity      string `json:"severity"`
	Score         int    `json:"score"`
	SecretKeyName string `json:"secretKeyName"`

	MaskedSecret string `json:"maskedSecret"`
	// RawSecret is populated only with --reveal; it stays "" otherwise.
	RawSecret string `json:"rawSecret"`

	// Entropy and FoundBy are data only. They are never displayed and they do
	// not belong to the display contract of §15.
	Entropy float64  `json:"entropy"`
	FoundBy []string `json:"foundBy"`

	// There is no decoder field on purpose: which encoder a secret was found in
	// is internal scanner detail and is never displayed.

	Verified      bool `json:"verified"`
	SeenInCommits int  `json:"seenInCommits"`
	HistoryOnly   bool `json:"historyOnly"`
	IsTestFile    bool `json:"isTestFile"`

	Commit      Commit      `json:"commit"`
	CodeSnippet CodeSnippet `json:"codeSnippet"`
}

// Report is the whole REPORT_DATA object injected into the HTML template.
type Report struct {
	Meta       Meta         `json:"meta"`
	ToolStatus []ToolStatus `json:"toolStatus"`
	Findings   []Finding    `json:"findings"`
}

// Options carries everything needed to build both reports.
type Options struct {
	RepoDir string // the temporary clone the code context is read from
	Reveal  bool
}

// Enrich scores every finding, decides whether it is history-only, attaches its
// code context and returns the findings in report order.
//
// Report order is fixed even on ties (CHAINFAULT_DOC.md §15): score descending,
// then file path ascending, then line number, then secret type, then commit
// hash. The terminal report and the HTML report use the same slice.
func Enrich(ctx context.Context, opts Options, findings []normalizer.Finding) []normalizer.Finding {
	out := make([]normalizer.Finding, 0, len(findings))
	for _, f := range findings {
		f.IsTestFile = risk.IsTestFile(f.FilePath)
		f.Score = risk.Score(f.Category, f.IsTestFile)
		f.Severity = risk.Severity(f.Score)
		f.Language = Language(f.FilePath)
		f.HistoryOnly = isHistoryOnly(ctx, opts.RepoDir, f)
		f.CodeLines = codeContext(ctx, opts.RepoDir, f)
		f.SecretKeyName = normalizer.ExtractKeyName(targetLine(f.CodeLines))
		out = append(out, f)
	}

	maskContextLines(out, opts.Reveal)
	SortFindings(out)
	return out
}

// SortFindings applies the fixed report order (CHAINFAULT_DOC.md §15).
func SortFindings(findings []normalizer.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		if a.FilePath != b.FilePath {
			return a.FilePath < b.FilePath
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.SecretType != b.SecretType {
			return a.SecretType < b.SecretType
		}
		return a.CommitHash < b.CommitHash
	})
}

// isHistoryOnly reports whether the secret survives in the latest version of
// its file. A secret that only exists in the history is labelled history only;
// its commit is then shown by both reports (CHAINFAULT_DOC.md §14).
func isHistoryOnly(ctx context.Context, repoDir string, f normalizer.Finding) bool {
	if f.CommitHash == "" || f.FilePath == "" {
		return true
	}
	lines, err := gitutil.ShowLines(ctx, repoDir, "HEAD", f.FilePath)
	if err != nil {
		// The file no longer exists at HEAD at all.
		return true
	}
	needles := secretLineForms(f.SecretValue)
	if len(needles) == 0 {
		return false
	}
	for _, line := range lines {
		for _, needle := range needles {
			if strings.Contains(line, needle) {
				return false
			}
		}
	}
	return true
}

// secretLineForms returns the representations of a secret that can appear in a
// single source line. A multi-line PEM stored in JS/JSON is one source line with
// literal `\n` escapes, while TruffleHog may report the same key with real
// newlines; checking both forms keeps "history only" and context masking
// correct whichever tool supplied the representative value.
func secretLineForms(secret string) []string {
	raw := normalizer.TrimValue(secret)
	if raw == "" {
		return nil
	}
	forms := []string{raw}
	if normalizer.IsMultilineSecret(secret) {
		escaped := strings.NewReplacer("\r\n", `\n`, "\n", `\n`, "\r", `\n`).Replace(raw)
		if escaped != raw {
			forms = append(forms, escaped)
		}
	}
	return forms
}

// contextRadius is how many lines are shown before and after the secret line.
const contextRadius = 3

// codeContext reads 3 lines before + the secret line + 3 lines after from the
// file as it existed at the finding's commit — never from the current working
// tree, which also applies to a HEAD finding (CHAINFAULT_DOC.md §15).
func codeContext(ctx context.Context, repoDir string, f normalizer.Finding) []normalizer.CodeLine {
	if f.CommitHash == "" || f.FilePath == "" {
		return nil
	}
	lines, err := gitutil.ShowLines(ctx, repoDir, f.CommitHash, f.FilePath)
	if err != nil || len(lines) == 0 {
		return nil
	}
	target := f.Line
	if target < 1 || target > len(lines) {
		target = 1
	}
	first := target - contextRadius
	if first < 1 {
		first = 1
	}
	last := target + contextRadius
	if last > len(lines) {
		last = len(lines)
	}

	out := make([]normalizer.CodeLine, 0, last-first+1)
	for n := first; n <= last; n++ {
		out = append(out, normalizer.CodeLine{
			Number:        n,
			Code:          lines[n-1],
			IsHighlighted: n == target,
		})
	}
	return out
}

// targetLine returns the highlighted line of a snippet, if there is one.
func targetLine(lines []normalizer.CodeLine) string {
	for _, l := range lines {
		if l.IsHighlighted {
			return l.Code
		}
	}
	return ""
}

// maskContextLines removes every secret known to this report from the code
// context, not just the secret the snippet is anchored on: neighbouring lines
// can hold a second secret, and a report must not leak them (CHAINFAULT_DOC.md
// §15). Every known value is masked whatever its length — a short secret used
// to be skipped and leaked verbatim through the code context.
//
// With --reveal the ORIGINAL (unmasked) line is kept in CodeRaw for the reveal
// toggle. Without --reveal CodeRaw stays empty: an empty value is omitted from
// the injected JSON, so the raw line cannot reach the HTML at all. CodeRaw is
// never assigned an already-masked line.
func maskContextLines(findings []normalizer.Finding, reveal bool) {
	type pair struct{ raw, masked string }
	pairs := make([]pair, 0, len(findings))
	for _, f := range findings {
		for _, raw := range secretLineForms(f.SecretValue) {
			pairs = append(pairs, pair{raw: raw, masked: normalizer.Mask(raw)})
		}
	}
	// Longest first, so a secret that contains another one is masked whole.
	sort.SliceStable(pairs, func(i, j int) bool { return len(pairs[i].raw) > len(pairs[j].raw) })

	for i := range findings {
		lines := findings[i].CodeLines
		for j := range lines {
			// Snapshot the original line before masking.
			if reveal {
				lines[j].CodeRaw = lines[j].Code
			} else {
				lines[j].CodeRaw = ""
			}
			code := lines[j].Code
			for _, p := range pairs {
				code = strings.ReplaceAll(code, p.raw, p.masked)
			}
			lines[j].Code = code
		}
	}
}

// BuildReport converts the internal findings into the REPORT_DATA display shape.
func BuildReport(meta Meta, tools []ToolStatus, findings []normalizer.Finding, reveal bool) Report {
	rep := Report{
		Meta:       meta,
		ToolStatus: tools,
		Findings:   make([]Finding, 0, len(findings)),
	}
	for i, f := range findings {
		vf := Finding{
			ID:            fmt.Sprintf("sec-%d", i+1),
			TypeLabel:     normalizer.Sanitize(f.SecretType),
			Location:      fmt.Sprintf("%s:%d", normalizer.Sanitize(f.FilePath), f.Line),
			Severity:      f.Severity,
			Score:         f.Score,
			SecretKeyName: normalizer.Sanitize(f.SecretKeyName),
			MaskedSecret:  f.MaskedSecret,
			Entropy:       f.Entropy,
			FoundBy:       f.FoundBy,
			Verified:      f.Verified,
			SeenInCommits: f.SeenInCommits,
			HistoryOnly:   f.HistoryOnly,
			IsTestFile:    f.IsTestFile,
			Commit:        Commit{Hash: normalizer.ShortHash(f.CommitHash), Date: f.CommitDate, Author: normalizer.Sanitize(f.CommitAuthor)},
			CodeSnippet:   CodeSnippet{Language: f.Language},
		}
		if vf.FoundBy == nil {
			vf.FoundBy = []string{}
		}
		// A raw secret only ever reaches the report with --reveal.
		if reveal {
			vf.RawSecret = f.SecretValue
		}
		for _, l := range f.CodeLines {
			vf.CodeSnippet.Lines = append(vf.CodeSnippet.Lines, CodeLine{
				Number:        l.Number,
				Code:          l.Code,
				CodeRaw:       l.CodeRaw,
				IsHighlighted: l.IsHighlighted,
			})
		}
		rep.Findings = append(rep.Findings, vf)
	}
	return rep
}

// FileCount returns the number of distinct files a finding set touches; it is
// the "M files" of the terminal total line.
func FileCount(findings []normalizer.Finding) int {
	seen := make(map[string]struct{}, len(findings))
	for _, f := range findings {
		seen[f.FilePath] = struct{}{}
	}
	return len(seen)
}

// Language maps a file extension onto the language name shown next to the code
// context. Unknown extensions are reported as plain text.
func Language(filePath string) string {
	switch strings.ToLower(strings.TrimPrefix(filepath.Ext(filePath), ".")) {
	case "py":
		return "python"
	case "js", "mjs", "cjs", "jsx":
		return "javascript"
	case "ts", "tsx", "mts":
		return "typescript"
	case "go":
		return "go"
	case "rb":
		return "ruby"
	case "java", "kt", "kts":
		return "java"
	case "php":
		return "php"
	case "rs":
		return "rust"
	case "sh", "bash", "zsh", "env":
		return "shell"
	case "json":
		return "json"
	case "yml", "yaml":
		return "yaml"
	case "toml", "ini", "cfg", "conf", "properties":
		return "toml"
	case "sql":
		return "sql"
	case "html", "htm":
		return "html"
	case "css", "scss":
		return "css"
	case "md":
		return "markdown"
	default:
		return "text"
	}
}
