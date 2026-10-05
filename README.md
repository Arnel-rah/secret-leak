# Secret Leak Auditor

![Go version](https://img.shields.io/badge/go-1.24%2B-00ADD8?logo=go&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-blue)

Scan a Git repository's **complete reachable history** for leaked
credentials, tokens, private keys, and suspicious high-entropy strings.
Reports include severity, commit context, redacted matches, and remediation
guidance.

> Removing a secret from the current files is not enough. If it was committed,
> it may still be recoverable from Git history.

## Highlights

- **Full-history scanning** across all reachable branches.
- **Named rules** for AWS, GitHub, Slack, JWT, database URLs, private keys,
  and generic secret assignments.
- **Entropy detection** for unknown, randomly generated tokens.
- **Safe redaction** in terminal, JSON, and HTML reports.
- **CI gating** with configurable severity thresholds.

## Quick start

### Install from GitHub

```bash
go install github.com/Arnel-rah/secret-leak/cmd/audit@latest
```

Ensure Go's binary directory is on your `PATH` if necessary:

```bash
export PATH="$PATH:$(go env GOPATH)/bin"
```

### Scan a repository

```bash
audit --repo /path/to/repository --no-color
```

### Build from source

```bash
git clone https://github.com/Arnel-rah/secret-leak.git
cd secret-leak
go build -o audit ./cmd/audit
./audit --repo .
```

## Usage

```bash
# Scan the current repository
audit --repo .

# Generate JSON and HTML reports
audit --repo . --json audit-report.json --html audit-report.html

# Fail CI on HIGH or CRITICAL findings
audit --repo . --ci --fail-on high --no-color

# Disable generic entropy detection
audit --repo . --entropy=false
```

The scanner examines **added lines** from `git log --all -p`, so it can find a
secret even when the file was deleted in a later commit.

## Command-line flags

| Flag | Default | Description |
| --- | --- | --- |
| `--repo` | `.` | Git repository path to scan |
| `--json` | — | Write a JSON report to this path |
| `--html` | — | Write an HTML report to this path |
| `--no-color` | `false` | Disable ANSI colors in terminal output |
| `--entropy` | `true` | Detect generic high-entropy tokens |
| `--ci` | `false` | Exit with code `1` when the threshold is reached |
| `--fail-on` | `high` | Minimum threshold: `critical`, `high`, `medium`, or `low` |

Exit codes:

- `0`: scan completed and the CI threshold was not reached;
- `1`: findings reached the configured `--fail-on` threshold;
- `2`: invalid input or a scan/reporting error.

## Example output

```text
3 finding(s) across Git history:

[1] CRITICAL  AWS Access Key ID
    file:   app.go:3
    commit: b61da3d6cb (2026-10-04T19:40:46+03:00) by Test Committer
    match:  AKIA…redacted…MNOP
    fix:    Deactivate the key in IAM immediately, rotate it, and audit
            CloudTrail for unauthorized use since the commit date.

Summary: critical=1 high=1 medium=0 low=1
```

## GitHub Actions

For complete history, the checkout must use `fetch-depth: 0`:

```yaml
- uses: actions/checkout@v4
  with:
    fetch-depth: 0

- uses: actions/setup-go@v5
  with:
    go-version: "1.24"

- name: Install auditor
  run: go install github.com/Arnel-rah/secret-leak/cmd/audit@latest

- name: Audit repository
  run: audit --repo . --no-color --ci --fail-on high --json audit-report.json
```

See [.github/workflows/ci.yml](.github/workflows/ci.yml) for this project's
self-audit and
[.github/workflows/example-usage.yml](.github/workflows/example-usage.yml) for
the reusable consumer example.

## Automated organization scans

The workflow
[`.github/workflows/organization-audit.yml`](.github/workflows/organization-audit.yml)
can scan a configured list of repositories every day and send an email when
findings reach the configured threshold.

Before enabling it, configure these repository-level settings. The workflow
discovers all non-archived repositories accessible to the audit token,
including repositories owned by or accessible through organizations.

| Setting | Type | Example |
| --- | --- | --- |
| `ALERT_EMAIL` | Variable | `sadiarnel145@gmail.com` |
| `GH_AUDIT_TOKEN` | Secret | Fine-grained token with read access to all target repositories |
| `SMTP_HOST` | Secret | `smtp.gmail.com` |
| `SMTP_PORT` | Secret | `587` |
| `SMTP_USERNAME` | Secret | `sadiarnel145@gmail.com` |
| `SMTP_PASSWORD` | Secret | Gmail app password |

For Gmail, enable two-step verification and create an **app password** for
the workflow. Store that generated 16-character password as the
`SMTP_PASSWORD` GitHub Actions secret; never commit it to the repository.

Create `GH_AUDIT_TOKEN` as a fine-grained token with **Metadata: Read-only** and
**Contents: Read-only** access for every organization and repository that
should be scanned. The token owner must also be allowed to access those
organizations. Reports are uploaded as redacted artifacts and are retained for
30 days.

## When a secret is found

1. **Revoke or rotate it immediately.** Treat a committed credential as
   compromised, even if the repository was private.
2. **Purge it from Git history** with
   [`git filter-repo`](https://github.com/newren/git-filter-repo) or BFG, then
   force-push the rewritten history.
3. **Move the replacement** to a secrets manager or environment variable, and
   keep local secret files out of Git.
4. **Review access logs** such as AWS CloudTrail when applicable.

## Design notes and limitations

- Detection is diff-based and scans only added lines.
- Entropy findings are `LOW` confidence and require manual verification.
- Patterns favor precision over recall to reduce alert fatigue.
- There is currently no allowlist or suppression syntax.

## Project layout

```text
cmd/audit/            CLI entrypoint and flag handling
internal/scanner/     Git history walking, rules, and entropy detection
internal/report/      Terminal, JSON, and HTML report rendering
.github/workflows/    CI and consumer workflow examples
```

## Development

```bash
go test ./...
go build ./...
```

## License

This project is released under the MIT License.
