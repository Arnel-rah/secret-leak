# Secrets Leak Auditor

A CLI that scans a Git repository's **entire history** — not just the current
checkout — for leaked secrets: AWS keys, GitHub tokens, Slack tokens, private
keys, database connection strings, JWTs, and generic high-entropy strings.

## Why this exists

Deleting a file that contains a secret does not remove it from Git history.
The commit that added it is still reachable, and anyone who clones the repo
can recover the key with `git log -p` or `git show <commit>`. This is one of
the most common and most overlooked causes of credential leaks, especially on
small teams without a dedicated security process.

`secrets-leak-auditor` walks every commit reachable from every branch
(`git log --all`), inspects every **added** line in every diff, and flags
anything that matches a known secret shape or looks random enough to be one.
It then produces a prioritized report with concrete remediation steps —
not just "a secret was found here."

## Features

- **Full-history scanning** — catches secrets even if they were removed in a
  later commit. Rewriting history (`git filter-repo`, `BFG`) is the only real
  fix; this tool tells you whether you need to.
- **Named detection rules** for AWS keys, GitHub/Slack tokens, private key
  blocks, database connection strings, JWTs, and generic key/secret
  assignments — each with its own remediation advice.
- **Generic high-entropy detection** (Shannon entropy) as a lower-confidence
  fallback for secrets that don't match a known shape.
- **Redacted output** — matches are shown as `AKIA…redacted…MNOP`, so a report
  can be shared with a team without re-leaking the secret.
- **CLI, JSON, and HTML reports.**
- **CI gate mode** — exit non-zero when findings at or above a chosen
  severity are detected, so a pull request can be blocked automatically.

## Install / Build

```bash
go build -o audit ./cmd/audit
```

or, once pushed to GitHub:

```bash
go install github.com/Arnel-rah/secret-leak/cmd/audit@latest
```

## Usage

```bash
# Scan the current directory's Git history
./audit --repo .

# Write JSON + HTML reports
./audit --repo . --json report.json --html report.html

# CI mode: fail the build if anything HIGH or above is found
./audit --repo . --ci --fail-on high
```

### Flags

| Flag         | Default | Description                                               |
|--------------|---------|-------------------------------------------------------------|
| `--repo`     | `.`     | Path to the Git repository to scan                          |
| `--json`     | —       | Write a JSON report to this path                             |
| `--html`     | —       | Write an HTML report to this path                            |
| `--no-color` | `false` | Disable ANSI colors in CLI output                            |
| `--entropy`  | `true`  | Also flag generic high-entropy tokens (lower confidence)     |
| `--ci`       | `false` | Exit 1 if findings at/above `--fail-on` are detected          |
| `--fail-on`  | `high`  | Minimum severity that triggers CI failure                    |

## Example output

```
3 finding(s) across Git history:

[1] CRITICAL  AWS Access Key ID
    file:   app.go:3
    commit: b61da3d6cb (2026-10-04T19:40:46+03:00) by Test Committer
    match:  AKIA…redacted…MNOP
    fix:    Deactivate the key in IAM immediately, rotate it, and audit
            CloudTrail for unauthorized use since the commit date.
...

Summary: critical=1 high=1 medium=0 low=1
```

## Using it in CI

See `.github/workflows/ci.yml` for this repo's own self-audit, and
`.github/workflows/example-usage.yml` for a copy-pasteable workflow that
gates pull requests in **any other repository** on newly introduced secrets.

```bash
audit --repo . --ci --fail-on high
```

Note: CI checkouts must use `fetch-depth: 0` — a shallow clone has no history
to scan.

## If the auditor finds something

1. **Rotate the credential immediately.** Assume it's compromised the moment
   it was committed, even to a private repo — it may already be cached by
   forks, CI logs, or local clones.
2. **Purge it from history** with `git filter-repo` (preferred) or the BFG
   Repo-Cleaner, then force-push and have all collaborators re-clone.
3. **Move the replacement to a secrets manager** or environment variable
   that is never committed (and add the file to `.gitignore`).

## Design notes / limitations

- Detection is diff-based (`git log -p`), scanning only *added* lines. This
  mirrors how real leaks happen (a line is added once) and avoids re-flagging
  every unchanged line in every commit.
- Entropy-based findings are intentionally marked `LOW` confidence — they are
  a starting point for manual review, not a guaranteed secret.
- No allowlist/suppression mechanism yet (e.g. per-line `#pragma: allowlist`
  comments) — straightforward to add as a follow-up (`internal/scanner`).
- Patterns favor precision over recall: a tool that cries wolf gets ignored.

## Project structure

```
cmd/audit/            CLI entrypoint and flag handling
internal/scanner/     Git history walking, detection rules, entropy check
internal/report/      CLI / JSON / HTML report rendering
.github/workflows/    Self-audit CI + example consumer workflow
```
