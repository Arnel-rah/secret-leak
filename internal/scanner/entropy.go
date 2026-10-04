package scanner

import (
	"math"
	"regexp"
)

// tokenCandidate matches bare high-entropy tokens that aren't caught by a
// named rule: long runs of base64/hex-like characters assigned to something,
// or simply standalone in a config/env line.
var tokenCandidateRe = regexp.MustCompile(`[A-Za-z0-9_\-+/=]{24,}`)

// shannonEntropy computes the Shannon entropy (bits per character) of s.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, r := range s {
		freq[r]++
	}
	n := float64(len(s))
	var entropy float64
	for _, count := range freq {
		p := count / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// EntropyFindingMinLength is the minimum token length considered.
const EntropyFindingMinLength = 24

// EntropyThreshold is the minimum bits-per-character to flag a token as
// likely-random (and therefore a plausible secret). Tuned conservatively to
// avoid flagging ordinary words, URLs, or hashes-as-identifiers.
const EntropyThreshold = 4.3

// FindHighEntropyTokens scans a line for standalone tokens that look like
// randomly generated secrets based on Shannon entropy, skipping tokens that
// are purely numeric or purely lowercase (common in hashes/UUIDs already
// treated as non-secret identifiers would still be flagged, so callers
// should treat entropy hits as the lowest-confidence rule).
func FindHighEntropyTokens(line string) []string {
	var hits []string
	for _, tok := range tokenCandidateRe.FindAllString(line, -1) {
		if len(tok) < EntropyFindingMinLength {
			continue
		}
		if shannonEntropy(tok) >= EntropyThreshold {
			hits = append(hits, tok)
		}
	}
	return hits
}
