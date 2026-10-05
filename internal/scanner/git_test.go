package scanner

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func initTestRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	run := func(args ...string) {
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v failed: %v\n%s", args, err, out)
		}
	}

	run("init", "-q")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "Test")

	secretFile := filepath.Join(dir, "secret.txt")
	accessKey := "AKIA" + "ABCDEFGHIJKLMNOP"
	writeFile(t, secretFile, accessKey+"\n")
	run("add", ".")
	run("commit", "-q", "-m", "add secret")

	removeFile(t, secretFile)
	run("add", ".")
	run("commit", "-q", "-m", "remove secret")

	return dir
}

func TestWalkAddedLinesFindsSecretEvenAfterDeletion(t *testing.T) {
	dir := initTestRepo(t)

	added, err := WalkAddedLines(dir)
	if err != nil {
		t.Fatalf("WalkAddedLines failed: %v", err)
	}

	found := false
	for _, a := range added {
		if a.Content == "AKIA"+"ABCDEFGHIJKLMNOP" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected to find the secret line added in history, got %d added lines", len(added))
	}
}

func TestScanEndToEndOnFixtureRepo(t *testing.T) {
	dir := initTestRepo(t)

	findings, err := Scan(ScanOptions{RepoPath: dir, IncludeEntropy: true})
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}
	if len(findings) == 0 {
		t.Fatal("expected at least one finding from the fixture repo, got none")
	}

	hasCritical := false
	for _, f := range findings {
		if f.RuleID == "aws-access-key-id" {
			hasCritical = true
		}
	}
	if !hasCritical {
		t.Errorf("expected an aws-access-key-id finding, got: %+v", findings)
	}
}
