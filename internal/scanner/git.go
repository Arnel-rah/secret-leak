package scanner

import (
	"bufio"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// AddedLine represents one line added in some commit's diff, with enough
// context to report and remediate it.
type AddedLine struct {
	CommitHash   string
	CommitDate   string
	CommitAuthor string
	FilePath     string
	LineNumber   int
	Content      string
}

var diffGitRe = "diff --git a/"

// WalkAddedLines runs `git log --all -p` over repoPath and yields every line
// that was *added* in any commit on any reachable branch, including commits
// that were later reverted or force-pushed over locally — this is what lets
// the auditor catch secrets that were committed and then "removed" in a
// later commit (removal does not erase it from history).
func WalkAddedLines(repoPath string) ([]AddedLine, error) {
	cmd := exec.Command("git", "-C", repoPath, "log", "--all", "-p",
		"--no-color", "--no-renames", "--pretty=format:@@COMMIT@@%H@@%aI@@%an")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("creating stdout pipe: %w", err)
	}
	var stderrBuf strings.Builder
	cmd.Stderr = &stderrBuf

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting git log: %w", err)
	}

	var (
		lines       []AddedLine
		curHash     string
		curDate     string
		curAuthor   string
		curFile     string
		newFileLine int
	)

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)

	for scanner.Scan() {
		line := scanner.Text()

		switch {
		case strings.HasPrefix(line, "@@COMMIT@@"):
			parts := strings.SplitN(line, "@@", 4)
			// parts: ["", "COMMIT", hash@@date@@author] -- SplitN with "@@" sep
			// Simpler: re-split manually.
			rest := strings.TrimPrefix(line, "@@COMMIT@@")
			fields := strings.SplitN(rest, "@@", 3)
			if len(fields) == 3 {
				curHash, curDate, curAuthor = fields[0], fields[1], fields[2]
			}
			_ = parts

		case strings.HasPrefix(line, diffGitRe):
			// diff --git a/path b/path
			trimmed := strings.TrimPrefix(line, diffGitRe)
			if idx := strings.Index(trimmed, " b/"); idx != -1 {
				curFile = trimmed[:idx]
			}

		case strings.HasPrefix(line, "@@ "):
			// Hunk header: @@ -a,b +c,d @@ ...
			newFileLine = parseHunkNewStart(line)

		case strings.HasPrefix(line, "+++") || strings.HasPrefix(line, "---"):
			// file marker lines, ignore

		case strings.HasPrefix(line, "+"):
			content := strings.TrimPrefix(line, "+")
			lines = append(lines, AddedLine{
				CommitHash:   curHash,
				CommitDate:   curDate,
				CommitAuthor: curAuthor,
				FilePath:     curFile,
				LineNumber:   newFileLine,
				Content:      content,
			})
			newFileLine++

		case strings.HasPrefix(line, "-"):
			// removed line, doesn't advance new-file line counter

		default:
			// context line in a hunk advances the new-file counter too
			if newFileLine > 0 {
				newFileLine++
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading git log output: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return nil, fmt.Errorf("git log failed: %w (stderr: %s)", err, stderrBuf.String())
	}

	return lines, nil
}

// parseHunkNewStart extracts the starting line number of the "new" side of a
// unified diff hunk header, e.g. "@@ -12,3 +15,4 @@ func foo() {" -> 15.
func parseHunkNewStart(header string) int {
	plusIdx := strings.Index(header, "+")
	if plusIdx == -1 {
		return 0
	}
	rest := header[plusIdx+1:]
	end := strings.IndexAny(rest, ", @")
	if end == -1 {
		end = len(rest)
	}
	n, err := strconv.Atoi(rest[:end])
	if err != nil {
		return 0
	}
	return n
}
