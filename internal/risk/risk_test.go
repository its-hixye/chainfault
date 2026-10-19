package risk

import "testing"

func TestScoreByCategory(t *testing.T) {
	// The score table of CHAINFAULT_DOC.md §11, one case per row.
	cases := map[string]int{
		"cloud keys":                     9,
		"private keys":                   9,
		"database passwords":             8,
		"account tokens":                 8,
		"payment keys":                   8,
		"general passwords":              7,
		"api service keys":               6,
		"webhooks":                       5,
		"random text":                    4,
		"unknown":                        5,
		"a category that does not exist": 5,
	}
	for category, want := range cases {
		if got := Score(category, false); got != want {
			t.Errorf("Score(%q) = %d, want %d", category, got, want)
		}
	}
}

func TestScoreIsAlwaysAnIntegerInRange(t *testing.T) {
	// The score is an integer 1-10: never a float, never zero, never above ten.
	for _, category := range []string{"cloud keys", "random text", "unknown", "", "nonsense"} {
		for _, isTest := range []bool{false, true} {
			got := Score(category, isTest)
			if got < 1 || got > 10 {
				t.Fatalf("Score(%q, %v) = %d, outside 1-10", category, isTest, got)
			}
		}
	}
}

func TestTestFilePenalty(t *testing.T) {
	// Two points off, with a floor of one (CHAINFAULT_DOC.md §11).
	if got := Score("cloud keys", true); got != 7 {
		t.Errorf("Score(cloud keys, test) = %d, want 7", got)
	}
	if got := Score("random text", true); got != 2 {
		t.Errorf("Score(random text, test) = %d, want 2", got)
	}
	// 4 - 2 would be 2; a hypothetical score of 1 must not drop to -1.
	if got := Score("", true); got != 3 {
		t.Errorf("Score(unknown, test) = %d, want 3", got)
	}
}

func TestSeverityBands(t *testing.T) {
	cases := map[int]string{
		10: Critical, 9: Critical,
		8: High, 7: High,
		6: Medium, 5: Medium, 4: Medium,
		3: Low, 2: Low, 1: Low,
	}
	for score, want := range cases {
		if got := Severity(score); got != want {
			t.Errorf("Severity(%d) = %q, want %q", score, got, want)
		}
	}
}

func TestIsTestFile(t *testing.T) {
	positives := []string{
		"tests/fixtures/sample.py",
		"app/test/helper.go",
		"src/__tests__/thing.js",
		"spec/models/user.rb",
		"specs/api_spec.rb",
		"pkg/testdata/blob.bin",
		"internal/mocks/client.go",
		"examples/demo.py",
		"pkg/util.test.ts",
		"pkg/util.spec.ts",
		"crypto_test.go",
		"test_helpers.py",
		"conftest.py",
		"settings.example",
		"settings.sample",
		// Case-insensitive on the whole path.
		"Tests/Fixtures/Sample.PY",
		"APP/TESTDATA/blob.bin",
	}
	for _, p := range positives {
		if !IsTestFile(p) {
			t.Errorf("IsTestFile(%q) = false, want true", p)
		}
	}

	negatives := []string{
		"app/config.py",
		"src/latest/attestation.ts",
		"contest/entry.go",
		"protest.md",
		"cmd/testing/main.go",
		"internal/attestation.rs",
		"",
	}
	for _, p := range negatives {
		if IsTestFile(p) {
			t.Errorf("IsTestFile(%q) = true, want false", p)
		}
	}
}
