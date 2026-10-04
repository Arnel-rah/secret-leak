package scanner

import "fmt"

// Finding is a single detected secret, ready for reporting.
type Finding struct {
	RuleID      string   `json:"rule_id"`
	Description string   `json:"description"`
	Severity    Severity `json:"severity"`
	CommitHash  string   `json:"commit_hash"`
	CommitDate  string   `json:"commit_date"`
	Author      string   `json:"author"`
	File        string   `json:"file"`
	Line        int      `json:"line"`
	Match       string   `json:"match"`
	Remediation string   `json:"remediation"`
}

// ScanOptions controls what a Scan does.
type ScanOptions struct {
	RepoPath       string
	IncludeEntropy bool
}

// Scan walks the full reachable Git history of RepoPath and returns every
// secret-like finding from both named rules and (optionally) generic
// high-entropy token detection.
func Scan(opts ScanOptions) ([]Finding, error) {
	added, err := WalkAddedLines(opts.RepoPath)
	if err != nil {
		return nil, fmt.Errorf("walking git history: %w", err)
	}

	var findings []Finding

	for _, al := range added {
		matchedByRule := false

		for _, rule := range Rules {
			if loc := rule.Pattern.FindString(al.Content); loc != "" {
				findings = append(findings, Finding{
					RuleID:      rule.ID,
					Description: rule.Description,
					Severity:    rule.Severity,
					CommitHash:  shortHash(al.CommitHash),
					CommitDate:  al.CommitDate,
					Author:      al.CommitAuthor,
					File:        al.FilePath,
					Line:        al.LineNumber,
					Match:       redact(loc),
					Remediation: rule.Remediation,
				})
				matchedByRule = true
			}
		}

		if opts.IncludeEntropy && !matchedByRule {
			for _, tok := range FindHighEntropyTokens(al.Content) {
				findings = append(findings, Finding{
					RuleID:      "high-entropy-token",
					Description: "Generic high-entropy string (possible secret)",
					Severity:    SeverityLow,
					CommitHash:  shortHash(al.CommitHash),
					CommitDate:  al.CommitDate,
					Author:      al.CommitAuthor,
					File:        al.FilePath,
					Line:        al.LineNumber,
					Match:       redact(tok),
					Remediation: "Manually verify whether this is a real credential before ignoring; if so, rotate and remove it from history.",
				})
			}
		}
	}

	return findings, nil
}

func shortHash(h string) string {
	if len(h) > 10 {
		return h[:10]
	}
	return h
}

// redact keeps the first 4 and last 4 characters of a matched secret and
// masks the middle, so reports can be shared without re-leaking the secret.
func redact(s string) string {
	if len(s) <= 10 {
		return "****"
	}
	return s[:4] + "…redacted…" + s[len(s)-4:]
}
