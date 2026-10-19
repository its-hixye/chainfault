package merger

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/its-hixye/chainfault/internal/normalizer"
)

// fakeAWSKey is a fabricated AWS key id used only by these tests; it matches the
// AKIA shape the scanners emit but is not a real credential. It is assembled
// from two halves at compile time so no single line of this source file ever
// contains a complete, real-looking key (CHAINFAULT_DOC.md §22). The joined
// value is byte-for-byte the original key.
const fakeAWSKey = "AKIAQWERTYUI" + "OPASDFGH"

func find(label, value, path string, line int, commit string) normalizer.Finding {
	return normalizer.Finding{
		FilePath:      path,
		Line:          line,
		SecretType:    label,
		SecretValue:   value,
		MaskedSecret:  normalizer.Mask(value),
		CommitHash:    commit,
		CommitDate:    "2026-01-05",
		CommitAuthor:  "Ahmed",
		DecodedFrom:   "",
		FoundBy:       []string{},
		SeenInCommits: 1,
	}
}

func TestMergeDeduplicatesAcrossTools(t *testing.T) {
	a := find("AWS key", fakeAWSKey, "app/config.py", 4, "aaa")
	a.FoundBy = []string{normalizer.ToolGitleaks}
	b := find("AWS key", `"`+fakeAWSKey+`"`, "./app/config.py", 4, "aaa")
	b.FoundBy = []string{normalizer.ToolTruffleHog}

	got := Merge([]normalizer.Finding{a, b})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if len(got[0].FoundBy) != 2 {
		t.Fatalf("FoundBy = %v, want both tools", got[0].FoundBy)
	}
}

func TestMergeKeepsSmallestLine(t *testing.T) {
	// The same secret on several lines of one file is one finding, shown at
	// its first appearance (CHAINFAULT_DOC.md §16).
	later := find("Generic secret", "s3cr3t", "app/config.py", 40, "bbb")
	earlier := find("Generic secret", "s3cr3t", "app/config.py", 7, "aaa")

	got := Merge([]normalizer.Finding{later, earlier})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Line != 7 {
		t.Fatalf("Line = %d, want the smallest (7)", got[0].Line)
	}
}

func TestMergeCountsCommits(t *testing.T) {
	a := find("Generic secret", "s3cr3t", "app/config.py", 7, "aaa")
	b := find("Generic secret", "s3cr3t", "app/config.py", 9, "bbb")
	c := find("Generic secret", "s3cr3t", "app/config.py", 11, "aaa") // same commit again

	got := Merge([]normalizer.Finding{a, b, c})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].SeenInCommits != 2 {
		t.Fatalf("SeenInCommits = %d, want 2 distinct commits", got[0].SeenInCommits)
	}
}

func TestMergeKeepsDifferentFilesApart(t *testing.T) {
	a := find("Generic secret", "s3cr3t", "app/config.py", 7, "aaa")
	b := find("Generic secret", "s3cr3t", "app/other.py", 7, "aaa")

	if got := Merge([]normalizer.Finding{a, b}); len(got) != 2 {
		t.Fatalf("got %d findings, want 2 — the path is part of the key", len(got))
	}
}

func TestMergeDecoderTieBreak(t *testing.T) {
	// TruffleHog can emit the same secret twice, once PLAIN and once decoded.
	// The choice must be deterministic: keep the non-PLAIN decoder, and among
	// several of those take the alphabetically first (CHAINFAULT_DOC.md §16).
	plain := find("AWS key", fakeAWSKey, "app/config.py", 4, "aaa")
	plain.DecodedFrom = ""
	base64 := find("AWS key", fakeAWSKey, "app/config.py", 4, "aaa")
	base64.DecodedFrom = "BASE64"

	if got := Merge([]normalizer.Finding{plain, base64}); got[0].DecodedFrom != "BASE64" {
		t.Errorf("DecodedFrom = %q, want BASE64 (order must not matter)", got[0].DecodedFrom)
	}
	if got := Merge([]normalizer.Finding{base64, plain}); got[0].DecodedFrom != "BASE64" {
		t.Errorf("DecodedFrom = %q, want BASE64 (order must not matter)", got[0].DecodedFrom)
	}

	utf16 := find("AWS key", fakeAWSKey, "app/config.py", 4, "aaa")
	utf16.DecodedFrom = "UTF16"
	if got := Merge([]normalizer.Finding{base64, utf16}); got[0].DecodedFrom != "BASE64" {
		t.Errorf("DecodedFrom = %q, want the alphabetically first (BASE64)", got[0].DecodedFrom)
	}
}

func TestMergePrefersSpecificTypeOverGeneric(t *testing.T) {
	// When two tools label the same secret differently, the concrete label
	// wins over "Generic secret" (CHAINFAULT_DOC.md §10, rule 4).
	generic := find(normalizer.TypeLabelGeneric, "tok_live_x", "app/a.py", 1, "aaa")
	generic.FoundBy = []string{normalizer.ToolGitleaks}
	specific := find("AWS key", "tok_live_x", "app/a.py", 1, "aaa")
	specific.FoundBy = []string{normalizer.ToolTruffleHog}

	got := Merge([]normalizer.Finding{generic, specific})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].SecretType != "AWS key" {
		t.Fatalf("SecretType = %q, want the specific label", got[0].SecretType)
	}
}

// genPEMKey returns a freshly generated RSA private key in PEM form. The key is
// built at runtime so no key material is ever written into a source file of this
// repository (CHAINFAULT_DOC.md §22).
func genPEMKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
}

// escapeNewlines rewrites every real line break into the literal two-character
// sequence `\n`, the form a scanner reports for a PEM stored in JS/JSON source.
func escapeNewlines(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", `\n`), "\r", `\r`)
}

func TestMergeMultilineEscapedAndRealMerge(t *testing.T) {
	// The regression this fixes: one PEM in one file of one commit, reported by
	// Gitleaks as a string literal containing `\n` escapes and by TruffleHog with
	// real newlines, used to be reported twice.
	key := genPEMKey(t)

	gitleaks := find("Private key", escapeNewlines(key), "config/keys.js", 12, "abc123")
	gitleaks.FoundBy = []string{normalizer.ToolGitleaks}
	truffle := find("Private key", key, "config/keys.js", 12, "abc123")
	truffle.FoundBy = []string{normalizer.ToolTruffleHog}

	got := Merge([]normalizer.Finding{gitleaks, truffle})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1 — the two representations are one secret", len(got))
	}
	if len(got[0].FoundBy) != 2 {
		t.Fatalf("FoundBy = %v, want both tools", got[0].FoundBy)
	}
}

func TestMergeMultilineDifferentKeysStayApart(t *testing.T) {
	// Two different keys in one file of one commit are two separate leaks and must
	// not be collapsed by the multi-line normalization.
	a := find("Private key", genPEMKey(t), "config/keys.js", 12, "abc123")
	a.FoundBy = []string{normalizer.ToolGitleaks}
	b := find("Private key", escapeNewlines(genPEMKey(t)), "config/keys.js", 40, "abc123")
	b.FoundBy = []string{normalizer.ToolTruffleHog}

	got := Merge([]normalizer.Finding{a, b})
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2 — two distinct keys in one commit", len(got))
	}
	for _, f := range got {
		if f.SeenInCommits != 1 {
			t.Fatalf("SeenInCommits = %d, want 1 for a key seen in one commit", f.SeenInCommits)
		}
	}
}

func TestMergeMultilineSameValueAcrossCommits(t *testing.T) {
	// Multiline secrets group exactly like single-line secrets: the same key in
	// two commits is one finding that reports both commits.
	key := genPEMKey(t)
	older := find("Private key", key, "config/keys.js", 12, "aaa")
	older.FoundBy = []string{normalizer.ToolGitleaks}
	newer := find("Private key", escapeNewlines(key), "config/keys.js", 30, "bbb")
	newer.FoundBy = []string{normalizer.ToolTruffleHog}

	got := Merge([]normalizer.Finding{older, newer})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1 — the same value in two commits is one finding", len(got))
	}
	if got[0].SeenInCommits != 2 {
		t.Fatalf("SeenInCommits = %d, want 2 distinct commits", got[0].SeenInCommits)
	}
	if got[0].Line != 12 {
		t.Fatalf("Line = %d, want the smallest start line (12)", got[0].Line)
	}
}

func TestMergeMultilineToolLineOffsetUsesSmallestLine(t *testing.T) {
	// Gitleaks reports a JS-escaped PEM at line N, TruffleHog reports the same
	// decoded PEM at N+1 in the same file at HEAD. They are one finding, shown
	// deterministically at the smallest start line.
	key := genPEMKey(t)
	gitleaks := find("Private key", escapeNewlines(key), "config/keys.js", 12, "abc123")
	gitleaks.FoundBy = []string{normalizer.ToolGitleaks}
	truffle := find("Private key", key, "config/keys.js", 13, "abc123")
	truffle.FoundBy = []string{normalizer.ToolTruffleHog}

	got := Merge([]normalizer.Finding{truffle, gitleaks})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1 — same file, same key, same commit", len(got))
	}
	if got[0].Line != 12 {
		t.Fatalf("Line = %d, want the smallest start line (12)", got[0].Line)
	}
	if got[0].SeenInCommits != 1 {
		t.Fatalf("SeenInCommits = %d, want 1", got[0].SeenInCommits)
	}
	if len(got[0].FoundBy) != 2 {
		t.Fatalf("FoundBy = %v, want both tools", got[0].FoundBy)
	}
}

func TestMergeSingleLineUnchanged(t *testing.T) {
	// The multi-line exception must not leak into ordinary single-line secrets:
	// same value in several commits is still ONE finding counting its commits.
	a := find("Generic secret", "s3cr3t", "app/config.py", 7, "aaa")
	b := find("Generic secret", `"s3cr3t"`, "./app/config.py", 9, "bbb")
	c := find("Generic secret", "s3cr3t\n", "app/config.py", 11, "aaa")
	d := find("Generic secret", "'s3cr3t'", "app/config.py", 13, "ccc")

	got := Merge([]normalizer.Finding{a, b, c, d})
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].SeenInCommits != 3 {
		t.Fatalf("SeenInCommits = %d, want 3 distinct commits", got[0].SeenInCommits)
	}
	if got[0].Line != 7 {
		t.Fatalf("Line = %d, want the smallest (7)", got[0].Line)
	}
}
