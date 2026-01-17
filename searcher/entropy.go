package searcher

import (
	"math"
	"strings"
)

// EntropyCalculator calculates Shannon entropy for strings
type EntropyCalculator struct {
	minLength            int
	highEntropyThreshold float64
}

// NewEntropyCalculator creates a new entropy calculator
func NewEntropyCalculator() *EntropyCalculator {
	return &EntropyCalculator{
		minLength:            8,
		highEntropyThreshold: 4.5,
	}
}

// CalculateEntropy calculates Shannon entropy for a given string
// High entropy (>4.5) typically indicates random/encrypted data like tokens or keys
func (ec *EntropyCalculator) CalculateEntropy(text string) float64 {
	if len(text) < ec.minLength {
		return 0
	}

	// Count character frequencies
	frequencies := make(map[rune]int)
	for _, char := range text {
		frequencies[char]++
	}

	// Calculate Shannon entropy
	entropy := 0.0
	length := float64(len(text))

	for _, count := range frequencies {
		if count == 0 {
			continue
		}
		frequency := float64(count) / length
		entropy -= frequency * math.Log2(frequency)
	}

	return entropy
}

// IsHighEntropy returns true if the string has high entropy (likely a secret/token)
func (ec *EntropyCalculator) IsHighEntropy(text string) bool {
	return ec.CalculateEntropy(text) >= ec.highEntropyThreshold
}

// ExtractPotentialSecrets extracts potential secrets from text based on entropy
// Looks for continuous alphanumeric+special char sequences with high entropy
func (ec *EntropyCalculator) ExtractPotentialSecrets(text string) []string {
	var secrets []string
	var currentSecret strings.Builder

	for _, char := range text {
		// Include alphanumeric and common secret characters
		if isSecretCharacter(char) {
			currentSecret.WriteRune(char)
		} else {
			if currentSecret.Len() >= ec.minLength {
				candidate := currentSecret.String()
				if ec.IsHighEntropy(candidate) {
					secrets = append(secrets, candidate)
				}
			}
			currentSecret.Reset()
		}
	}

	// Check last candidate
	if currentSecret.Len() >= ec.minLength {
		candidate := currentSecret.String()
		if ec.IsHighEntropy(candidate) {
			secrets = append(secrets, candidate)
		}
	}

	return secrets
}

// isSecretCharacter checks if a character is likely part of a secret
func isSecretCharacter(char rune) bool {
	return (char >= 'a' && char <= 'z') ||
		(char >= 'A' && char <= 'Z') ||
		(char >= '0' && char <= '9') ||
		char == '-' || char == '_' || char == '=' ||
		char == '+' || char == '/' || char == ':' ||
		char == '.' || char == '~'
}

// AnalyzeString performs comprehensive entropy analysis
func (ec *EntropyCalculator) AnalyzeString(text string) (entropy float64, isHighEntropy bool, suspicionLevel string) {
	entropy = ec.CalculateEntropy(text)
	isHighEntropy = ec.IsHighEntropy(text)

	if entropy >= 5.5 {
		suspicionLevel = "very_high"
	} else if entropy >= 4.5 {
		suspicionLevel = "high"
	} else if entropy >= 3.5 {
		suspicionLevel = "medium"
	} else {
		suspicionLevel = "low"
	}

	return
}
