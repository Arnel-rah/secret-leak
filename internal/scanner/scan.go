package scanner

import "fmt"

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

type ScanOptions struct {
	RepoPath       string
	IncludeEntropy bool
}


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

func redact(s string) string {
	if len(s) <= 10 {
		return "****"
	}
	return s[:4] + "…redacted…" + s[len(s)-4:]
}
