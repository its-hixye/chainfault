package normalizer

// Tool names. These are internal identifiers used for the `foundBy` field and
// for the Failed Scanner Tools block of the HTML report — they are never
// rendered on a finding card (CHAINFAULT_DOC.md §15).
const (
	ToolGitleaks   = "gitleaks"
	ToolTruffleHog = "trufflehog"
)
