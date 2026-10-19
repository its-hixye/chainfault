package normalizer

import (
	"regexp"
	"strings"
)

// Categories are the risk classes of CHAINFAULT_DOC.md §11. The naming table
// (§10) maps every tool type name onto exactly one category, and the category
// is what determines the score — the tool's own wording never does.
const (
	CategoryCloudKeys       = "cloud keys"
	CategoryPrivateKeys     = "private keys"
	CategoryDBPasswords     = "database passwords"
	CategoryAccountTokens   = "account tokens"
	CategoryPaymentKeys     = "payment keys"
	CategoryGeneralPassword = "general passwords"
	CategoryAPIServiceKeys  = "api service keys"
	CategoryWebhooks        = "webhooks"
	CategoryRandomText      = "random text"
	CategoryUnknown         = "unknown"
)

// CategoryGeneralSecret is the type label used for Gitleaks' generic-api-key
// rule. It is the least specific label and always loses a merge against a
// concrete label (CHAINFAULT_DOC.md §10, rule 4).
const TypeLabelGeneric = "Generic secret"

// typeRow is one row of the naming table (CHAINFAULT_DOC.md §10). The label is
// the card title and the category is the risk class — they come from the same
// row, which is what makes the two tools produce an identical label for the
// same secret.
type typeRow struct {
	Label    string
	Category string
	Gitleaks []string
	Truffle  []string
}

// typeTable is the naming table, in the order of the document.
var typeTable = []typeRow{
	{"AWS key", CategoryCloudKeys, []string{"aws-access-token"}, []string{"AWS"}},
	{"Private key", CategoryPrivateKeys, []string{"private-key"}, []string{"PrivateKey"}},
	{"GitHub token", CategoryAccountTokens, []string{"github-pat", "github-oauth", "github-app-token", "github-fine-grained-pat", "github-refresh-token"}, []string{"Github", "GithubApp"}},
	{"GitLab token", CategoryAccountTokens, []string{"gitlab-pat", "gitlab-deploy-token", "gitlab-runner-authentication-token"}, []string{"Gitlab"}},
	{"Slack token", CategoryAccountTokens, []string{"slack-bot-token", "slack-user-token"}, []string{"Slack"}},
	{"Slack webhook", CategoryWebhooks, []string{"slack-webhook-url"}, []string{"SlackWebhook"}},
	{"Stripe key", CategoryPaymentKeys, []string{"stripe-access-token"}, []string{"Stripe"}},
	{"OpenAI key", CategoryAPIServiceKeys, []string{"openai-api-key"}, []string{"OpenAI"}},
	{"Google API key", CategoryCloudKeys, []string{"gcp-api-key"}, []string{"GCP"}},
	{"SendGrid key", CategoryAPIServiceKeys, []string{"sendgrid-api-token"}, []string{"Sendgrid"}},
	{"NPM token", CategoryAccountTokens, []string{"npm-access-token"}, []string{"NPM"}},
	{"PyPI token", CategoryAccountTokens, []string{"pypi-upload-token"}, []string{"PyPI"}},
	{"JWT", CategoryAccountTokens, []string{"jwt", "jwt-base64"}, []string{"JWT"}},
	{"Database password", CategoryDBPasswords, nil, []string{"Postgres", "MySQL", "MongoDB", "MSSQL", "Redis"}},
	{TypeLabelGeneric, CategoryGeneralPassword, []string{"generic-api-key"}, nil},
}

var (
	byRule     = map[string]typeRow{}
	byDetector = map[string]typeRow{}
)

func init() {
	for _, row := range typeTable {
		for _, r := range row.Gitleaks {
			byRule[strings.ToLower(r)] = row
		}
		for _, d := range row.Truffle {
			byDetector[strings.ToLower(d)] = row
		}
	}
}

// TypeLabel resolves the card title and the risk category for a secret.
//
// ruleID is Gitleaks' RuleID (empty for TruffleHog findings) and detectorName
// is TruffleHog's DetectorName (empty for Gitleaks findings). description is
// Gitleaks' Description, used only when nothing matched the table.
//
// Resolution order (CHAINFAULT_DOC.md §10): table match first; then Gitleaks'
// Description; then a humanized detector name. Anything unmapped lands in the
// "unknown" category, which scores 5.
func TypeLabel(ruleID, detectorName, description string) (label, category string) {
	if row, ok := byRule[strings.ToLower(strings.TrimSpace(ruleID))]; ok {
		return row.Label, row.Category
	}
	if row, ok := byDetector[strings.ToLower(strings.TrimSpace(detectorName))]; ok {
		return row.Label, row.Category
	}
	if d := strings.TrimSpace(description); d != "" {
		return d, CategoryUnknown
	}
	if n := strings.TrimSpace(detectorName); n != "" {
		return Humanize(n), CategoryUnknown
	}
	return TypeLabelGeneric, CategoryUnknown
}

// leadingKeyword matches a language keyword that may sit in front of the
// variable name: `export DB_PASS=...`, `const API_TOKEN = ...`.
var leadingKeyword = regexp.MustCompile(`^(?:export|const|var|let)\s+`)

// identifier matches the characters allowed in a variable / config key name.
var identifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.\-]*$`)

// bracketAccess matches `headers['Authorization']` and keeps the inner key.
var bracketAccess = regexp.MustCompile(`^.*\[["']([^"']+)["']\]$`)

// ExtractKeyName derives the secret's variable or config name from the code
// line it was found on (CHAINFAULT_DOC.md §10). It never guesses: when the
// line does not carry an unambiguous name before the `=` or `:` next to the
// secret, it returns an empty string and the report shows the masked value only.
func ExtractKeyName(codeLine string) string {
	line := strings.TrimSpace(Sanitize(codeLine))
	if line == "" {
		return ""
	}

	// Cut the line right before the secret so we never pick up the name of a
	// neighbouring assignment further to the left.
	if idx := strings.LastIndexAny(line, "=:"); idx >= 0 {
		name := strings.TrimSpace(line[:idx])
		name = stripCallParens(name)
		name = bracketAccess.ReplaceAllString(name, "$1")
		name = leadingKeyword.ReplaceAllString(name, "")
		name = strings.TrimSpace(strings.Trim(name, `"'`+"` \t"))
		if identifier.MatchString(name) {
			return name
		}
		return ""
	}

	// No `=` or `:` at all: a bare secret in the middle of prose or data. The
	// document says not to guess.
	return ""
}

// stripCallParens turns `f("password"` into `password` so JSON/YAML style keys
// embedded in a call still resolve, while `connect(...)` style names do not.
func stripCallParens(s string) string {
	s = strings.TrimSpace(s)
	if !strings.HasSuffix(s, "(") && !strings.HasSuffix(s, "(\"") && !strings.HasSuffix(s, "('") {
		return s
	}
	trimmed := strings.TrimRight(s, "(")
	return strings.TrimSpace(strings.Trim(trimmed, `"'`+"` \t"))
}
