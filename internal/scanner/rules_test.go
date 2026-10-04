package scanner

import "testing"

func TestRulesDetectKnownSecretShapes(t *testing.T) {
	cases := []struct {
		name    string
		ruleID  string
		content string
	}{
		{"aws access key", "aws-access-key-id",
			`key := "` + "AKIA" + `ABCDEFGHIJKLMNOP"`},
		{"aws secret key", "aws-secret-access-key",
			`aws_secret_access_key = "[TEST_AWS_SECRET_KEY]"`},
		{"github token", "github-token",
			`GITHUB_TOKEN=` + "ghp_" + `1234567890abcdefghijklmnopqrstuvwxyz12`},
		{"slack token", "slack-token",
			`token: ` + "xoxb-" + `1234567890-abcdefghijklmnopqrstuvwx`},
		{"private key", "private-key-block",
			`-----BEGIN ` + "RSA PRIVATE KEY" + `-----`},
		{"db connection string", "generic-db-connection-string",
			`url = "postgres://admin:` + "hunter2" + `@db.internal:5432/prod"`},
		{"jwt", "jwt-token",
			`Authorization: ` + "eyJhbGciOiJIUzI1NiJ9" + `.[TEST_JWT]`},
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