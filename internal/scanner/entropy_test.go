package scanner

import "testing"

func TestShannonEntropyOrdering(t *testing.T) {
	low := shannonEntropy("aaaaaaaaaaaaaaaaaaaaaaaa")
	high := shannonEntropy("Xk9#mQ2$vL8pR4&nJ7!wT1@z")
	if high <= low {
		t.Errorf("expected high-entropy string to score above repetitive string, got high=%.2f low=%.2f", high, low)
	}
}

func TestFindHighEntropyTokensSkipsShortAndLowEntropy(t *testing.T) {
	line := "this is just a normal sentence with no secrets in it at all"
	if hits := FindHighEntropyTokens(line); len(hits) != 0 {
		t.Errorf("expected no entropy hits in plain English sentence, got %v", hits)
	}
}

func TestFindHighEntropyTokensFlagsRandomToken(t *testing.T) {
	line := `token = "[TEST_ENTROPY_TOKEN]"`
	hits := FindHighEntropyTokens(line)
	if len(hits) == 0 {
		t.Errorf("expected at least one high-entropy token to be flagged in %q", line)
	}
}
