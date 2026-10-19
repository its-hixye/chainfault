package normalizer

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// gitleaksReport is one entry of the JSON array Gitleaks writes with -f json.
// Fields that Chainfault deliberately ignores (SymlinkFile, Message, Tags,
// EndLine/EndColumn, Fingerprint, Match, Email) are not decoded — see
// CHAINFAULT_DOC.md §10.
type gitleaksReport struct {
	RuleID      string  `json:"RuleID"`
	Description string  `json:"Description"`
	File        string  `json:"File"`
	StartLine   int     `json:"StartLine"`
	Secret      string  `json:"Secret"`
	Commit      string  `json:"Commit"`
	Author      string  `json:"Author"`
	Date        string  `json:"Date"`
	Entropy     float64 `json:"Entropy"`
}

// ParseGitleaksJSON turns a Gitleaks JSON report into internal findings.
func ParseGitleaksJSON(data []byte) ([]Finding, error) {
	var raw []gitleaksReport
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse gitleaks json: %w", err)
	}
	out := make([]Finding, 0, len(raw))
	for _, r := range raw {
		label, category := TypeLabel(r.RuleID, "", r.Description)
		out = append(out, Finding{
			FilePath:      NormalizePath(r.File),
			Line:          r.StartLine,
			SecretType:    label,
			Category:      category,
			SecretValue:   r.Secret,
			MaskedSecret:  Mask(r.Secret),
			CommitHash:    r.Commit,
			CommitDate:    NormalizeDate(r.Date),
			CommitAuthor:  CleanAuthor(r.Author),
			Entropy:       r.Entropy,
			DecodedFrom:   "",
			Verified:      false,
			FoundBy:       []string{ToolGitleaks},
			SeenInCommits: 1,
		})
	}
	return out, nil
}

// trufflehogLine is one line of the TruffleHog JSONL stream. TruffleHog mixes its
// log records into the same stream, so records without a DetectorName must be
// dropped (CHAINFAULT_DOC.md §10).
type trufflehogLine struct {
	DetectorName   string `json:"DetectorName"`
	DecoderName    string `json:"DecoderName"`
	Verified       bool   `json:"Verified"`
	Raw            string `json:"Raw"`
	RawV2          string `json:"RawV2"`
	SourceMetadata struct {
		Data struct {
			Git struct {
				Commit    string `json:"commit"`
				File      string `json:"file"`
				Email     string `json:"email"`
				Author    string `json:"author"`
				Timestamp string `json:"timestamp"`
				Line      int64  `json:"line"`
			} `json:"Git"`
		} `json:"Data"`
	} `json:"SourceMetadata"`
}

// ParseTruffleHogJSONL turns a TruffleHog JSONL stream into internal findings.
// Only records carrying a non-empty DetectorName are kept.
func ParseTruffleHogJSONL(data []byte) ([]Finding, error) {
	var out []Finding
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 1024*1024), 16*1024*1024)
	for sc.Scan() {
		lineBytes := bytes.TrimSpace(sc.Bytes())
		if len(lineBytes) == 0 {
			continue
		}
		var rec trufflehogLine
		if err := json.Unmarshal(lineBytes, &rec); err != nil {
			// A malformed log line is not a reason to fail the whole scan.
			continue
		}
		if rec.DetectorName == "" {
			// `info-0` log record, not a secret.
			continue
		}
		git := rec.SourceMetadata.Data.Git

		value := rec.Raw
		if value == "" {
			value = rec.RawV2
		}
		label, category := TypeLabel("", rec.DetectorName, "")

		// The git source records the commit author in `email` as "Name
		// <addr@example>"; some builds also carry a separate `author`.
		author := git.Author
		if strings.TrimSpace(author) == "" {
			author = git.Email
		}

		out = append(out, Finding{
			FilePath:      NormalizePath(git.File),
			Line:          int(git.Line),
			SecretType:    label,
			Category:      category,
			SecretValue:   value,
			MaskedSecret:  Mask(value),
			CommitHash:    git.Commit,
			CommitDate:    NormalizeDate(git.Timestamp),
			CommitAuthor:  CleanAuthor(author),
			Entropy:       0,
			DecodedFrom:   normalizeDecoder(rec.DecoderName),
			Verified:      rec.Verified,
			FoundBy:       []string{ToolTruffleHog},
			SeenInCommits: 1,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read trufflehog jsonl: %w", err)
	}
	return out, nil
}

// normalizeDecoder maps a TruffleHog DecoderName to the internal decodedFrom
// value. PLAIN is stored as the empty string so every display rule can simply
// ask "is a decoder set and is it not PLAIN".
func normalizeDecoder(name string) string {
	if strings.EqualFold(strings.TrimSpace(name), "PLAIN") {
		return ""
	}
	return strings.TrimSpace(name)
}

// NormalizeDate reduces a scanner timestamp to a plain YYYY-MM-DD date. Both
// tools emit ISO-8601 with varying offsets; the report only shows the day.
func NormalizeDate(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	for _, layout := range []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05 -0700",
		"2006-01-02T15:04:05",
		"2006-01-02",
	} {
		if t, err := time.Parse(layout, raw); err == nil {
			return t.UTC().Format("2006-01-02")
		}
	}
	return raw
}

// CleanAuthor keeps the author's display name only: no email address, no
// control characters.
func CleanAuthor(raw string) string {
	raw = Sanitize(strings.TrimSpace(raw))
	if i := strings.IndexAny(raw, "<("); i >= 0 {
		raw = raw[:i]
	}
	if i := strings.Index(raw, "@"); i >= 0 {
		raw = raw[:i]
	}
	return strings.TrimSpace(raw)
}

// ShortHash trims a commit hash to the 7 characters the reports display.
func ShortHash(hash string) string {
	hash = strings.TrimSpace(hash)
	if len(hash) > 7 {
		return hash[:7]
	}
	return hash
}
