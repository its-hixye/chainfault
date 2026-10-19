// Package risk turns a secret's category and location into the integer risk
// score (1-10) and the severity band shown by both reports
// (CHAINFAULT_DOC.md §11).
package risk

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/its-hixye/chainfault/internal/normalizer"
)

// Severity band names, lowercase in the data and uppercase in the reports.
const (
	Critical = "critical"
	High     = "high"
	Medium   = "medium"
	Low      = "low"
)

// baseScores is the score table of CHAINFAULT_DOC.md §11. Anything not in the
// table (CategoryUnknown) scores 5.
var baseScores = map[string]int{
	normalizer.CategoryCloudKeys:       9,
	normalizer.CategoryPrivateKeys:     9,
	normalizer.CategoryDBPasswords:     8,
	normalizer.CategoryAccountTokens:   8,
	normalizer.CategoryPaymentKeys:     8,
	normalizer.CategoryGeneralPassword: 7,
	normalizer.CategoryAPIServiceKeys:  6,
	normalizer.CategoryWebhooks:        5,
	normalizer.CategoryRandomText:      4,
	normalizer.CategoryUnknown:         5,
}

// testSegments are the path segments that mark a file as a test file. Compared
// case-insensitively against the full repository-relative path.
var testSegments = []string{
	"test", "tests", "__tests__",
	"spec", "specs",
	"fixtures", "testdata",
	"mocks", "examples",
}

// testGlobs are the filename patterns that mark a file as a test file.
var testGlobs = []string{
	"*.test.*", "*.spec.*", "*_test.*",
	"test_*.py", "conftest.py",
	"*.example", "*.sample",
}

// testPenalty is how many points a secret in a test file loses, with a floor of
// 1 so a secret is never scored zero and never disappears from the report.
const testPenalty = 2

// Score returns the integer risk score for a category. isTestFile drops the
// score by two points (floor 1). The result is always an integer 1-10 — no
// stage of the pipeline computes or stores a fractional score.
func Score(category string, isTestFile bool) int {
	base, ok := baseScores[category]
	if !ok {
		base = baseScores[normalizer.CategoryUnknown]
	}
	if isTestFile {
		base -= testPenalty
	}
	if base < 1 {
		base = 1
	}
	if base > 10 {
		base = 10
	}
	return base
}

// Severity maps an integer score onto a severity band: 9-10 critical, 7-8
// high, 4-6 medium, 1-3 low.
func Severity(score int) string {
	switch {
	case score >= 9:
		return Critical
	case score >= 7:
		return High
	case score >= 4:
		return Medium
	default:
		return Low
	}
}

// IsTestFile reports whether a repository-relative path belongs to a test,
// mock or fixture file (CHAINFAULT_DOC.md §11).
func IsTestFile(filePath string) bool {
	p := normalizer.NormalizePath(filePath)
	if p == "" {
		return false
	}
	lower := strings.ToLower(p)
	for _, seg := range strings.Split(lower, "/") {
		for _, want := range testSegments {
			if seg == want {
				return true
			}
		}
	}
	base := path.Base(lower)
	if base == "" || base == "." || base == "/" {
		return false
	}
	for _, glob := range testGlobs {
		if ok, err := filepath.Match(glob, base); err == nil && ok {
			return true
		}
	}
	return false
}
