package scanner

import "regexp"

// Severity levels for findings.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
)

// Rule is a named regex pattern used to detect a specific kind of secret.
type Rule struct {
	ID          string
	Description string
	Severity    Severity
	Pattern     *regexp.Regexp
	Remediation string
}

// Rules is the built-in set of secret-detection patterns.
// Patterns are intentionally conservative (prefer fewer false positives)
// and cover the most common real-world leaks.
var Rules = []Rule{
	{
		ID:          "aws-access-key-id",
		Description: "AWS Access Key ID",
		Severity:    SeverityCritical,
		Pattern:     regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`),
		Remediation: "Deactivate the key in IAM immediately, rotate it, and audit CloudTrail for unauthorized use since the commit date.",
	},
	{
		ID:          "aws-secret-access-key",
		Description: "AWS Secret Access Key (assigned to a variable)",
		Severity:    SeverityCritical,
		Pattern:     regexp.MustCompile(`(?i)(aws_secret_access_key|aws_secret_key)\s*[:=]\s*['"]?[A-Za-z0-9/+=]{40}['"]?`),
		Remediation: "Rotate the AWS secret key tied to this access key pair, then purge it from history.",
	},
	{
		ID:          "github-token",
		Description: "GitHub Personal Access / App Token",
		Severity:    SeverityCritical,
		Pattern:     regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{20,}\b`),
		Remediation: "Revoke the token at github.com/settings/tokens and generate a new one with minimal scopes.",
	},
	{
		ID:          "slack-token",
		Description: "Slack Token",
		Severity:    SeverityHigh,
		Pattern:     regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,}\b`),
		Remediation: "Revoke the token in the Slack app management console and reissue.",
	},
	{
		ID:          "private-key-block",
		Description: "Private Key (PEM block)",
		Severity:    SeverityCritical,
		Pattern:     regexp.MustCompile(`-----BEGIN (RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----`),
		Remediation: "Treat the key pair as fully compromised: revoke/replace it everywhere it is trusted (servers, CI, SSH authorized_keys).",
	},
	{
		ID:          "generic-db-connection-string",
		Description: "Database connection string with embedded credentials",
		Severity:    SeverityHigh,
		Pattern:     regexp.MustCompile(`(?i)(postgres|postgresql|mysql|mongodb(\+srv)?|redis):\/\/[^:\s'"]+:[^@\s'"]+@[^\s'"]+`),
		Remediation: "Rotate the database password and move credentials to a secrets manager or environment variables.",
	},
	{
		ID:          "jwt-token",
		Description: "JSON Web Token (JWT)",
		Severity:    SeverityMedium,
		Pattern:     regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`),
		Remediation: "If this is a long-lived or signing-relevant token, rotate the signing secret and invalidate issued tokens.",
	},
	{
		ID:          "generic-api-key-assignment",
		Description: "Generic API key / secret assigned to a variable",
		Severity:    SeverityMedium,
		Pattern:     regexp.MustCompile(`(?i)(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*['"][A-Za-z0-9_\-/+=]{16,}['"]`),
		Remediation: "Confirm whether this is a real credential; if so, rotate it and load it from a secrets manager instead.",
	},
}
