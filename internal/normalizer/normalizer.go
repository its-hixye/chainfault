// Package normalizer converts the raw output of the two scanner tools into one
// unified internal secret shape (CHAINFAULT_DOC.md §10). It is also the single
// owner of the masking rule, the merge key and the secret-type naming table.
package normalizer

import (
	"strings"
	"unicode"
)

// Finding is the unified internal shape of a single secret. It is the only
// reference definition of the internal secret shape (CHAINFAULT_DOC.md §10);
// both the terminal report and the HTML report are rendered from a list of
// these, so neither report can drift from the other.
//
// Fields are exported so every downstream package can read them; nothing
// outside this module writes a Finding except Parse* and the risk/merger
// packages that enrich an already-parsed one.
type Finding struct {
	// ID is a stable identifier assigned after merging ("sec-1", "sec-2"...).
	ID string

	// FilePath is the project-relative path of the file the secret was in.
	FilePath string
	// Line is the 1-based line number the secret was found on.
	Line int

	// SecretType is the unified secret type; it is the card title (typeLabel).
	// Raw tool names (RuleID / DetectorName) are never displayed.
	SecretType string
	// Category is the risk class of SecretType (cloud keys, account tokens...).
	// The naming table sets both from the same row; risk turns it into a score.
	Category string

	// SecretValue is the raw secret. It only ever lives in memory.
	SecretValue string
	// MaskedSecret is the display-safe form of SecretValue.
	MaskedSecret string

	// SecretKeyName is the variable / config key the secret is assigned to.
	// Optional: empty when no unambiguous name could be extracted.
	SecretKeyName string

	// CommitHash / CommitDate / CommitAuthor describe where the secret was
	// written. CommitAuthor is the author name without the email address.
	CommitHash   string
	CommitDate   string
	CommitAuthor string

	// Verified is only ever true with Chainfault's --verify flag.
	Verified bool

	// Entropy is the Shannon entropy of the secret. Gitleaks only. It is kept
	// in the JSON as data and is never displayed (CHAINFAULT_DOC.md §15).
	Entropy float64

	// DecodedFrom is the encoding TruffleHog decoded the secret from
	// ("BASE64"...). TruffleHog only. Empty means the raw value was used.
	DecodedFrom string

	// FoundBy lists the tools that reported this secret. Collected during the
	// merge; kept in the JSON as data and never displayed.
	FoundBy []string

	// SeenInCommits is the number of commits the same secret appeared in.
	SeenInCommits int

	// HistoryOnly is true when the secret exists in the repository history but
	// not in the latest version of the file.
	HistoryOnly bool
	// IsTestFile is true when the secret lives in a test / mock / fixture file.
	IsTestFile bool

	// Score is the integer risk score, 1 to 10. It is never a float.
	Score int
	// Severity is derived from Score: critical / high / medium / low.
	Severity string

	// Language is the code language of the snippet, derived from the extension.
	Language string
	// CodeLines is 3 lines before + the secret line + 3 lines after, read from
	// the file at the finding's commit with `git show <commit>:<path>`.
	CodeLines []CodeLine
}

// CodeLine is a single rendered line of a code context snippet.
type CodeLine struct {
	Number        int
	Code          string
	CodeRaw       string // only populated when --reveal is on
	IsHighlighted bool
}

// Sanitize replaces control characters with a visible escape such as "\x1b"
// (CHAINFAULT_DOC.md §19). A hostile repository must not be able to move the
// cursor, clear a line or hide a secret from the terminal report.
func Sanitize(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r == '\n' || r == '\t' || r == '\r' {
			// Printable whitespace is kept; CR/LF never reach the report anyway.
			if r == '\r' {
				b.WriteString(`\x0d`)
				continue
			}
			b.WriteRune(r)
			continue
		}
		if r < 0x20 || r == 0x7f {
			const hex = "0123456789abcdef"
			b.WriteString(`\x`)
			b.WriteByte(hex[(r>>4)&0xf])
			b.WriteByte(hex[r&0xf])
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// Mask returns the display form of a secret (CHAINFAULT_DOC.md §19). The shape
// depends only on the length; there is no percentage rule.
//
//	>= 12 characters -> first4 + "****" + last4
//	7 to 11          -> first2 + "****" + last2
//	<= 6             -> first2 + "****"
func Mask(secret string) string {
	secret = Sanitize(strings.TrimRight(secret, "\r\n"))
	runes := []rune(secret)
	if len(runes) < 2 {
		return "****"
	}
	switch {
	case len(runes) >= 12:
		return string(runes[:4]) + "****" + string(runes[len(runes)-4:])
	case len(runes) >= 7:
		return string(runes[:2]) + "****" + string(runes[len(runes)-2:])
	default:
		return string(runes[:2]) + "****"
	}
}

// NormalizePath normalizes a repository-relative path for the merge key:
// forward slashes always, never a leading "./".
func NormalizePath(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	return strings.TrimPrefix(p, "/")
}

// TrimValue is the original single-line normalization: trim surrounding
// whitespace, surrounding quotes and a trailing newline. It is the exact
// substring a single-line secret has inside its source line.
//
// It is NOT the merge normalization (see NormalizeValue): it keeps the value
// byte-for-byte as the scanners reported it apart from the trims above, so it
// is the right rule whenever the value is compared against, or masked inside,
// real file content (code-context masking, "is it still in HEAD").
func TrimValue(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimSuffix(v, "\n")
	v = strings.TrimSpace(v)
	return strings.Trim(v, `"'`+"`")
}

// pemArmorPrefix / pemArmorEndPrefix mark the header and footer lines of a PEM
// block. Both tools may or may not include them in the reported secret, so they
// are not part of the merge key.
const (
	pemArmorPrefix    = "-----BEGIN "
	pemArmorEndPrefix = "-----END "
)

// IsMultilineSecret reports whether a raw secret value is a multi-line / PEM
// value. Multi-line values are the only ones where two tools can disagree about
// the *representation* of the same secret: a PEM stored in JS/JSON source is
// reported by Gitleaks with the literal two-character escape sequences `\n`,
// and by TruffleHog with real newline characters.
//
// Detection is deliberately generous but not trigger-happy: a literal `\n` /
// `\r` escape, PEM armor, or a line break that is not merely a trailing newline
// (which the single-line rule has always trimmed) is enough.
func IsMultilineSecret(v string) bool {
	if strings.Contains(v, `\n`) || strings.Contains(v, `\r`) || strings.Contains(v, pemArmorPrefix) {
		return true
	}
	return strings.ContainsAny(strings.TrimRight(v, "\r\n"), "\r\n")
}

// NormalizeValue normalizes a secret value for the merge key (CHAINFAULT_DOC.md
// §16).
//
// Single-line values keep exactly the historical behavior (TrimValue).
//
// Multi-line / PEM values are canonicalized instead: literal `\n` / `\r` escape
// sequences become real line breaks, blank lines and whitespace are dropped and
// the PEM BEGIN/END armor lines are removed. That makes the two representations
// of one PEM key — Gitleaks' escaped 1730-byte string and TruffleHog's real
// 1704-byte one — normalize to the same value and therefore merge.
//
// Deliberately no case folding — secrets are case-sensitive and
// over-normalizing would merge two different secrets.
func NormalizeValue(v string) string {
	if !IsMultilineSecret(v) {
		return TrimValue(v)
	}
	return normalizeMultiline(v)
}

// normalizeMultiline canonicalizes a multi-line / PEM value. The empty result
// is possible (a value that is nothing but PEM armor); in that case it falls
// back to TrimValue so an armored-but-empty finding never merges with an empty
// secret elsewhere in the same file.
func normalizeMultiline(v string) string {
	v = strings.NewReplacer(`\r\n`, "\n", `\n`, "\n", `\r`, "\n").Replace(v)

	lines := strings.Split(v, "\n")
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, pemArmorPrefix) || strings.HasPrefix(line, pemArmorEndPrefix) {
			continue
		}
		// A key body never contains meaningful whitespace; dropping it makes the
		// value insensitive to the line wrapping each tool happened to emit.
		kept = append(kept, strings.Join(strings.Fields(line), ""))
	}

	out := strings.Join(kept, "\n")
	if out == "" {
		return TrimValue(v)
	}
	return out
}

// MergeKey builds the merge key of a finding: normalized path + normalized
// value. Line numbers and commit hashes are deliberately not part of the key
// because both move as the file changes. Multi-line / PEM values are normalized
// here too, so the two tools' representations of one key share a key.
func MergeKey(filePath, secretValue string) string {
	return NormalizePath(filePath) + "\x00" + NormalizeValue(secretValue)
}

// Humanize turns a raw tool type name into something readable: "-" and "_" are
// dropped and the first letter is capitalized (CHAINFAULT_DOC.md §10, rule 3).
func Humanize(name string) string {
	name = strings.NewReplacer("-", "", "_", "").Replace(strings.TrimSpace(name))
	if name == "" {
		return name
	}
	runes := []rune(name)
	runes[0] = unicode.ToUpper(runes[0])
	return string(runes)
}
