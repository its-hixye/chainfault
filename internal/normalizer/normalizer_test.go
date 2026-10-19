package normalizer

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

// fakeAWSKey is a fabricated AWS key id used only by these tests; it matches the
// AKIA shape the scanners emit but is not a real credential. It is assembled
// from two halves at compile time so no single line of this source file ever
// contains a complete, real-looking key (CHAINFAULT_DOC.md §22). The joined
// value is byte-for-byte the original key.
const fakeAWSKey = "AKIAQWERTYUI" + "OPASDFGH"

func TestMask(t *testing.T) {
	cases := []struct {
		name   string
		secret string
		want   string
	}{
		{"long", fakeAWSKey, "AKIA****DFGH"},
		{"exactly twelve", "123456789012", "1234****9012"},
		{"eleven", "12345678901", "12****01"},
		{"seven", "1234567", "12****67"},
		{"six", "123456", "12****"},
		{"short", "abc", "ab****"},
		{"empty", "", "****"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Mask(tc.secret); got != tc.want {
				t.Fatalf("Mask(%q) = %q, want %q", tc.secret, got, tc.want)
			}
		})
	}
}

func TestMergeKeyNormalization(t *testing.T) {
	// The same secret written three different ways must produce one key.
	want := "app/config.py\x00s3cr3t"
	for _, tc := range []struct{ path, value string }{
		{"./app/config.py", `"s3cr3t"`},
		{"app/config.py", "'s3cr3t'"},
		{"app/config.py", "s3cr3t\n"},
		{"app/config.py", "  s3cr3t  "},
		{"app\\config.py", "`s3cr3t`"},
	} {
		if got := MergeKey(tc.path, tc.value); got != want {
			t.Errorf("MergeKey(%q, %q) = %q, want %q", tc.path, tc.value, got, want)
		}
	}
}

func TestMergeKeyIsCaseSensitive(t *testing.T) {
	// Secrets are case-sensitive: over-normalizing would merge two different
	// secrets into one (CHAINFAULT_DOC.md §16).
	if MergeKey("a.py", "Secret") == MergeKey("a.py", "secret") {
		t.Fatal("merge key must not fold case")
	}
}

func TestMergeKeyIsStable(t *testing.T) {
	// The key must be deterministic: the same path and secret must always
	// produce the same value.
	a := MergeKey("a.py", "x-secret")
	b := MergeKey("a.py", "x-secret")
	if a != b {
		t.Fatalf("merge key is not deterministic: %q != %q", a, b)
	}
}

func TestExtractKeyName(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string
	}{
		{"assignment", `AWS_SECRET_KEY = "AKIA..."`, "AWS_SECRET_KEY"},
		{"json key", `"password": "post..."`, "password"},
		{"const", `const API_TOKEN = 'ghp_...'`, "API_TOKEN"},
		{"export", `export DB_PASS=postgres123`, "DB_PASS"},
		{"no spaces", `TOKEN="abc"`, "TOKEN"},
		{"bracket access", `headers['Authorization'] = 'token ghp_x'`, "Authorization"},
		{"bare secret", `eyJhbGciOi` + `JIUzI1NiIs...`, ""},
		{"prose", `the value is AKIA here`, ""},
		{"url", `postgres://admin:hunter2@db:5432`, ""},
		{"empty", ``, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ExtractKeyName(tc.line); got != tc.want {
				t.Fatalf("ExtractKeyName(%q) = %q, want %q", tc.line, got, tc.want)
			}
		})
	}
}

func TestTypeLabelBothToolsAgree(t *testing.T) {
	// The same secret found by both tools must get the same label, because
	// both come from the same row of the table (CHAINFAULT_DOC.md §10).
	fromGitleaks, catA := TypeLabel("aws-access-token", "", "")
	fromTruffle, catB := TypeLabel("", "AWS", "")
	if fromGitleaks != fromTruffle {
		t.Fatalf("labels differ: %q vs %q", fromGitleaks, fromTruffle)
	}
	if fromGitleaks != "AWS key" {
		t.Fatalf("label = %q, want %q", fromGitleaks, "AWS key")
	}
	if catA != catB {
		t.Fatalf("categories differ: %q vs %q", catA, catB)
	}
}

func TestTypeLabelUnmappedFallsBack(t *testing.T) {
	// No table row: Gitleaks' Description wins, otherwise a humanized
	// detector name. Either way the category is the unknown one, scoring 5.
	label, category := TypeLabel("some-new-rule", "", "Detected something new")
	if label != "Detected something new" {
		t.Fatalf("label = %q", label)
	}
	if category != CategoryUnknown {
		t.Fatalf("category = %q, want %q", category, CategoryUnknown)
	}

	label, _ = TypeLabel("", "some-new-detector", "")
	if label != "Somenewdetector" {
		t.Fatalf("humanized label = %q, want %q", label, "Somenewdetector")
	}
}

func TestSanitizeControlCharacters(t *testing.T) {
	// A repository must not be able to drive the terminal around (CHAINFAULT_DOC.md §19).
	got := Sanitize("conf\x1b[31mig.json")
	want := `conf\x1b[31mig.json`
	if got != want {
		t.Fatalf("Sanitize = %q, want %q", got, want)
	}
}

func TestParseGitleaksJSON(t *testing.T) {
	in := []byte(`[
	  {"RuleID":"aws-access-token","Description":"AWS","File":"./app/config.py","StartLine":14,
	   "Secret":"` + fakeAWSKey + `","Commit":"abc123","Author":"Ahmed","Email":"a@b.c",
	   "Date":"2026-10-10T09:00:00Z","Entropy":4.1}
	]`)
	got, err := ParseGitleaksJSON(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	f := got[0]
	if f.FilePath != "app/config.py" {
		t.Errorf("FilePath = %q, want app/config.py", f.FilePath)
	}
	if f.SecretType != "AWS key" || f.Category != CategoryCloudKeys {
		t.Errorf("type/category = %q/%q", f.SecretType, f.Category)
	}
	if f.CommitDate != "2026-10-10" {
		t.Errorf("CommitDate = %q", f.CommitDate)
	}
	if f.MaskedSecret != "AKIA****DFGH" {
		t.Errorf("MaskedSecret = %q", f.MaskedSecret)
	}
	if len(f.FoundBy) != 1 || f.FoundBy[0] != ToolGitleaks {
		t.Errorf("FoundBy = %v", f.FoundBy)
	}
}

func TestParseTruffleHogJSONLDropsLogLines(t *testing.T) {
	// TruffleHog interleaves its info logs into the same JSONL stream; only
	// records with a DetectorName are secrets.
	in := []byte(`{"level":"info-0","ts":"2026-10-18T10:29:16+03:00","msg":"scanning repo"}
{"level":"info-0","ts":"2026-10-18T10:29:16+03:00","msg":"finished scanning"}
{"SourceMetadata":{"Data":{"Git":{"commit":"c0ffee","file":"app/config.py","email":"Ahmed <a@b.c>","timestamp":"2026-01-05 10:00:00 +0000","line":4}}},"DetectorName":"AWS","DecoderName":"BASE64","Verified":false,"Raw":"` + fakeAWSKey + `"}
{"SourceMetadata":{"Data":{"Git":{"commit":"c0ffee","file":"app/config.py","timestamp":"2026-01-05 10:00:00 +0000","line":4}}},"DetectorName":"AWS","DecoderName":"PLAIN","Raw":"` + fakeAWSKey + `"}
`)
	got, err := ParseTruffleHogJSONL(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2 (the two info-0 records must be dropped)", len(got))
	}
	if got[0].DecodedFrom != "BASE64" {
		t.Errorf("DecodedFrom = %q, want BASE64", got[0].DecodedFrom)
	}
	if got[1].DecodedFrom != "" {
		t.Errorf("PLAIN decoder must normalize to empty, got %q", got[1].DecodedFrom)
	}
	// The git source carries an "Name <email>" string and no separate author.
	if got[0].CommitAuthor != "Ahmed" {
		t.Errorf("CommitAuthor = %q, want Ahmed", got[0].CommitAuthor)
	}
	if got[0].CommitDate != "2026-01-05" {
		t.Errorf("CommitDate = %q", got[0].CommitDate)
	}
}

func TestParseTruffleHogJSONLKeepsVerifiedFlag(t *testing.T) {
	// One fake TruffleHog JSONL record; parsing must not make any network call.
	in := []byte(`{"SourceMetadata":{"Data":{"Git":{"commit":"c0ffee","file":"app/config.py","timestamp":"2026-01-05 10:00:00 +0000","line":4}}},"DetectorName":"AWS","DecoderName":"PLAIN","Verified":true,"Raw":"` + fakeAWSKey + `"}`)

	got, err := ParseTruffleHogJSONL(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if !got[0].Verified {
		t.Error("Verified=true from the TruffleHog record was not preserved")
	}
}

// genPEMKey returns a freshly generated RSA private key in PEM form. Keys are
// built at runtime on purpose: no key material is ever written into a source
// file of this repository (CHAINFAULT_DOC.md §22).
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
// sequence `\n`, exactly as a scanner sees a PEM stored inside JS/JSON source.
func escapeNewlines(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "\n", `\n`), "\r", `\r`)
}

func TestNormalizeValueSingleLineUnchanged(t *testing.T) {
	// Ordinary single-line values keep the historical rule exactly: trim, drop a
	// trailing newline, trim quotes (CHAINFAULT_DOC.md §16).
	cases := []struct{ name, in, want string }{
		{"plain", "s3cr3t", "s3cr3t"},
		{"padded", "  s3cr3t  ", "s3cr3t"},
		{"trailing newline", "s3cr3t\n", "s3cr3t"},
		{"double quoted", `"s3cr3t"`, "s3cr3t"},
		{"single quoted", "'s3cr3t'", "s3cr3t"},
		{"backticked", "`s3cr3t`", "s3cr3t"},
		{"aws key", fakeAWSKey, fakeAWSKey},
		{"url", "postgres://admin:hunter2@db:5432", "postgres://admin:hunter2@db:5432"},
		{"with spaces inside", "two word secret", "two word secret"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := NormalizeValue(tc.in); got != tc.want {
				t.Fatalf("NormalizeValue(%q) = %q, want %q", tc.in, got, tc.want)
			}
			if IsMultilineSecret(tc.in) {
				t.Fatalf("%q must not be classified as multi-line", tc.in)
			}
		})
	}
}

func TestNormalizeValueMultilineRepresentationsAgree(t *testing.T) {
	// Gitleaks reports a PEM stored in JS/JSON source with literal two-character
	// `\n` escapes; TruffleHog reports the real newlines. Both must normalize to
	// the same merge key, otherwise one leaked key is reported twice.
	pemText := genPEMKey(t)
	escaped := escapeNewlines(pemText)

	if len(pemText) == len(escaped) {
		t.Fatalf("the two representations must differ in length (%d)", len(pemText))
	}

	gotEscaped := NormalizeValue(escaped)
	gotReal := NormalizeValue(pemText)
	if gotEscaped != gotReal {
		t.Fatalf("representations did not normalize alike:\n escaped: %q\n   real: %q", gotEscaped, gotReal)
	}
	if want := MergeKey("config/keys.js", pemText); MergeKey("config/keys.js", escaped) != want {
		t.Fatal("merge keys of the two representations differ")
	}
}

func TestNormalizeValueMultilineIsCanonical(t *testing.T) {
	// The canonical form carries no PEM armor, no literal escape sequence and no
	// whitespace inside a line — only the key material.
	got := NormalizeValue(escapeNewlines(genPEMKey(t)))
	if strings.Contains(got, pemArmorPrefix) || strings.Contains(got, pemArmorEndPrefix) {
		t.Fatalf("PEM armor survived normalization: %q", got)
	}
	if strings.Contains(got, `\n`) || strings.Contains(got, `\r`) {
		t.Fatalf("a literal escape sequence survived normalization: %q", got)
	}
	for _, line := range strings.Split(got, "\n") {
		if line == "" || strings.Join(strings.Fields(line), "") != line {
			t.Fatalf("line %q is not whitespace-free", line)
		}
	}
}

func TestNormalizeValuePEMArmorIsOptional(t *testing.T) {
	// One tool may report the armor, the other not. The armor must not decide
	// whether two findings are the same secret.
	withArmor := genPEMKey(t)
	body := strings.Join(strings.Split(withArmor, "\n")[1:len(strings.Split(withArmor, "\n"))-1], "\n")

	if NormalizeValue(withArmor) != NormalizeValue(body) {
		t.Fatal("PEM BEGIN/END armor must not change the normalized value")
	}
	if NormalizeValue(withArmor) != NormalizeValue(escapeNewlines(withArmor)) {
		t.Fatal("escaped and real newlines must agree with armor present")
	}
}

func TestNormalizeValueKeepsDifferentKeysApart(t *testing.T) {
	// Two different keys must not collapse onto one normalized value, or two
	// separate leaks would be reported as one.
	first, second := genPEMKey(t), genPEMKey(t)
	if NormalizeValue(first) == NormalizeValue(second) {
		t.Fatal("two distinct generated keys normalized to the same value")
	}
	if MergeKey("config/keys.js", first) == MergeKey("config/keys.js", second) {
		t.Fatal("two distinct generated keys produced the same merge key")
	}
}

func TestNormalizeValueArmorOnlyDoesNotCollapseToEmpty(t *testing.T) {
	// A value made of nothing but armor has no canonical body, so it falls back to
	// the single-line rule instead of normalizing to empty — an empty merge-key
	// value would merge with any other empty secret in the same file.
	const armorOnly = "-----BEGIN RSA PRIVATE KEY-----\n-----END RSA PRIVATE KEY-----\n"
	if got := NormalizeValue(armorOnly); got == "" || got == armorOnly {
		t.Fatalf("NormalizeValue = %q, want the trimmed armor text", got)
	}
	if got := NormalizeValue("-----BEGIN FOO-----\n"); got == "" {
		t.Fatal("a non-empty value must never normalize to empty")
	}
}

func TestIsMultilineSecret(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"single line", "s3cr3t", false},
		{"trailing newline only", "s3cr3t\n", false},
		{"real newline", "a\nb", true},
		{"real cr", "a\rb", true},
		{"crlf", "a\r\nb", true},
		{"literal escape", `a\nb`, true},
		{"literal cr escape", `a\rb`, true},
		{"pem armor", "-----BEGIN RSA PRIVATE KEY-----", true},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsMultilineSecret(tc.in); got != tc.want {
				t.Fatalf("IsMultilineSecret(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestTrimValueKeepsSingleLineBytes(t *testing.T) {
	// TrimValue is the substring rule used against real file content; it must
	// never canonicalize a multi-line value.
	in := "  \"" + fakeAWSKey + "\"\n"
	if got := TrimValue(in); got != fakeAWSKey {
		t.Fatalf("TrimValue(%q) = %q, want %q", in, got, fakeAWSKey)
	}
}
