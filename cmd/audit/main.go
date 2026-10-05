
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/Arnel-rah/secrets-leak-auditor/internal/report"
	"github.com/Arnel-rah/secrets-leak-auditor/internal/scanner"
)

func main() {
	var (
		repoPath = flag.String("repo", ".", "path to the Git repository to scan")
		jsonOut  = flag.String("json", "", "write JSON report to this path")
		htmlOut  = flag.String("html", "", "write HTML report to this path")
		noColor  = flag.Bool("no-color", false, "disable ANSI colors in CLI output")
		entropy  = flag.Bool("entropy", true, "also flag generic high-entropy tokens (lower confidence)")
		ciMode   = flag.Bool("ci", false, "exit non-zero if any finding at or above --fail-on is detected")
		failOn   = flag.String("fail-on", "high", "minimum severity that triggers CI failure: critical|high|medium|low")
	)
	flag.Parse()

	if _, err := os.Stat(*repoPath); err != nil {
		fmt.Fprintf(os.Stderr, "error: repo path %q is not accessible: %v\n", *repoPath, err)
		os.Exit(2)
	}

	findings, err := scanner.Scan(scanner.ScanOptions{
		RepoPath:       *repoPath,
		IncludeEntropy: *entropy,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: scan failed: %v\n", err)
		os.Exit(2)
	}

	report.SortFindings(findings)
	report.PrintCLI(findings, *noColor)

	if *jsonOut != "" {
		if err := report.WriteJSON(findings, *jsonOut); err != nil {
			fmt.Fprintf(os.Stderr, "error: writing JSON report: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("\nJSON report written to %s\n", *jsonOut)
	}

	if *htmlOut != "" {
		if err := report.WriteHTML(findings, *htmlOut); err != nil {
			fmt.Fprintf(os.Stderr, "error: writing HTML report: %v\n", err)
			os.Exit(2)
		}
		fmt.Printf("HTML report written to %s\n", *htmlOut)
	}

	if *ciMode && shouldFail(findings, *failOn) {
		fmt.Fprintf(os.Stderr, "\nCI gate failed: findings at or above severity %q were detected.\n", *failOn)
		os.Exit(1)
	}
}

func shouldFail(findings []scanner.Finding, failOn string) bool {
	threshold := severityRank(failOn)
	for _, f := range findings {
		if severityRank(string(f.Severity)) <= threshold {
			return true
		}
	}
	return false
}

func severityRank(s string) int {
	switch s {
	case "critical", "CRITICAL":
		return 0
	case "high", "HIGH":
		return 1
	case "medium", "MEDIUM":
		return 2
	case "low", "LOW":
		return 3
	default:
		return 1
	}
}
