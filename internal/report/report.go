package report

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"sort"
	"strings"

	"github.com/Arnel-rah/secret-leak/internal/scanner"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
)

var severityOrder = map[scanner.Severity]int{
	scanner.SeverityCritical: 0,
	scanner.SeverityHigh:     1,
	scanner.SeverityMedium:   2,
	scanner.SeverityLow:      3,
}

var severityColor = map[scanner.Severity]string{
	scanner.SeverityCritical: colorRed,
	scanner.SeverityHigh:     colorRed,
	scanner.SeverityMedium:   colorYellow,
	scanner.SeverityLow:      colorGray,
}

func SortFindings(findings []scanner.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if severityOrder[findings[i].Severity] != severityOrder[findings[j].Severity] {
			return severityOrder[findings[i].Severity] < severityOrder[findings[j].Severity]
		}
		return findings[i].File < findings[j].File
	})
}

func PrintCLI(findings []scanner.Finding, noColor bool) {
	c := func(code string) string {
		if noColor {
			return ""
		}
		return code
	}

	if len(findings) == 0 {
		fmt.Printf("%s✓ No secrets detected across scanned history.%s\n", c(colorCyan), c(colorReset))
		return
	}

	fmt.Printf("%s%d finding(s) across Git history:%s\n\n", c(colorBold), len(findings), c(colorReset))

	for i, f := range findings {
		sevColor := c(severityColor[f.Severity])
		fmt.Printf("%s[%d] %s%-8s%s %s\n", c(colorGray), i+1, sevColor, f.Severity, c(colorReset), f.Description)
		fmt.Printf("    file:   %s:%d\n", f.File, f.Line)
		fmt.Printf("    commit: %s (%s) by %s\n", f.CommitHash, f.CommitDate, f.Author)
		fmt.Printf("    match:  %s\n", f.Match)
		fmt.Printf("    fix:    %s\n\n", f.Remediation)
	}

	summary := map[scanner.Severity]int{}
	for _, f := range findings {
		summary[f.Severity]++
	}
	fmt.Printf("%sSummary:%s critical=%d high=%d medium=%d low=%d\n",
		c(colorBold), c(colorReset),
		summary[scanner.SeverityCritical], summary[scanner.SeverityHigh],
		summary[scanner.SeverityMedium], summary[scanner.SeverityLow])
}

func WriteJSON(findings []scanner.Finding, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(findings)
}

func WriteHTML(findings []scanner.Finding, path string) error {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">`)
	b.WriteString(`<title>Secrets Leak Audit Report</title><style>`)
	b.WriteString(`body{font-family:ui-monospace,Menlo,Consolas,monospace;background:#0b0c0f;color:#e6e6e6;padding:2rem;max-width:960px;margin:auto}`)
	b.WriteString(`h1{color:#fff}table{width:100%;border-collapse:collapse;margin-top:1rem}`)
	b.WriteString(`th,td{text-align:left;padding:.5rem;border-bottom:1px solid #2a2d34;vertical-align:top;font-size:.85rem}`)
	b.WriteString(`th{color:#9aa0a6;text-transform:uppercase;font-size:.7rem;letter-spacing:.05em}`)
	b.WriteString(`.sev-CRITICAL,.sev-HIGH{color:#ff6b6b}.sev-MEDIUM{color:#ffd166}.sev-LOW{color:#9aa0a6}`)
	b.WriteString(`.empty{color:#4ade80;margin-top:1rem}</style></head><body>`)
	b.WriteString(`<h1>Secrets Leak Audit Report</h1>`)

	if len(findings) == 0 {
		b.WriteString(`<p class="empty">✓ No secrets detected across scanned history.</p>`)
	} else {
		fmt.Fprintf(&b, `<p>%d finding(s) across Git history.</p>`, len(findings))
		b.WriteString(`<table><tr><th>Severity</th><th>Rule</th><th>File:Line</th><th>Commit</th><th>Match</th><th>Remediation</th></tr>`)
		for _, f := range findings {
			fmt.Fprintf(&b, `<tr><td class="sev-%s">%s</td><td>%s</td><td>%s:%d</td><td>%s</td><td>%s</td><td>%s</td></tr>`,
				html.EscapeString(string(f.Severity)), html.EscapeString(string(f.Severity)),
				html.EscapeString(f.Description),
				html.EscapeString(f.File), f.Line,
				html.EscapeString(f.CommitHash),
				html.EscapeString(f.Match),
				html.EscapeString(f.Remediation))
		}
		b.WriteString(`</table>`)
	}
	b.WriteString(`</body></html>`)

	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func HighestSeverity(findings []scanner.Finding) scanner.Severity {
	best := -1
	var bestSev scanner.Severity
	for _, f := range findings {
		if rank := severityOrder[f.Severity]; best == -1 || rank < best {
			best = rank
			bestSev = f.Severity
		}
	}
	return bestSev
}
