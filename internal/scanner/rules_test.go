package scanner

import (
	"strings"
	"testing"
)

func TestRulesDetectKnownSecretShapes(t *testing.T) {
	cases := []struct {
		name    string
		ruleID  string
		content string
	}{
		{"aws access key", "aws-access-key-id",
			`key := "` + strings.Join([]string{"AK", "IAAB", "CDEF", "GHIJ", "KLMN", "OP"}, "") + `"`},
		{"aws secret key", "aws-secret-access-key",
			`aws_secret_access_key = "` + strings.Join([]string{
				"wJal", "rXUt", "nFEM", "I/K7", "MDEN", "G/bP", "xRfi", "CYEX", "AMPLE", "KEY",
			}, "") + `"`},
		{"github token", "github-token",
			`GITHUB_TOKEN=` + strings.Join([]string{
				"ghp_", "1234", "5678", "90ab", "cdef", "ghij", "klmn", "opqr", "stuv", "wxyz", "12",
			}, "")},
		{"slack token", "slack-token",
			`token: ` + strings.Join([]string{
				"xoxb", "-", "1234", "5678", "90ab", "cdef", "ghij", "klmn", "opqr", "stuv", "wx",
			}, "")},
		{"private key", "private-key-block",
			`-----BEGIN ` + "RSA PRIVATE KEY" + `-----`},
		{"db connection string", "generic-db-connection-string",
			`url = "postgres://admin:` + "hunter2" + `@db.internal:5432/prod"`},
		{"jwt", "jwt-token",
			`Authorization: ` + strings.Join([]string{
				"******", ".eyJ", "zdWI", "iOiI", "xMjM", "0NTY", "3ODkw", "In0.",
				"dBjf", "tJeZ", "4CVP", "-mB9", "2K27", "uhbU", "JU1p", "1r_w", "W1gF", "WFOE", "jXk.",
				"sign", "atur", "e-pa", "rt-1", "2345", "67890",
			}, "")},
		{"generic api key", "generic-api-key-assignment",
			`api_key = "` + "sk_live_" + `abcdefghijklmnopqrstuvwx"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matched := false
			for _, rule := range Rules {
				if rule.Pattern.MatchString(tc.content) && rule.ID == tc.ruleID {
					matched = true
				}
			}
			if !matched {
				t.Errorf("expected rule %q to match content %q, no rule matched", tc.ruleID, tc.content)
			}
		})
	}
}

func TestRulesDoNotFlagOrdinaryCode(t *testing.T) {
	benign := []string{
		`fmt.Println("hello world")`,
		`const maxRetries = 3`,
		`import "net/http"`,
		`// TODO: refactor this function`,
		`SELECT * FROM users WHERE id = ?`,
	}

	for _, content := range benign {
		for _, rule := range Rules {
			if rule.Pattern.MatchString(content) {
				t.Errorf("rule %q unexpectedly matched benign content %q", rule.ID, content)
			}
		}
	}
}
