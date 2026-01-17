package searcher

// RiskScorer calculates comprehensive risk scores for findings
type RiskScorer struct {
	entropyCalculator *EntropyCalculator
}

// NewRiskScorer creates a new risk scorer
func NewRiskScorer() *RiskScorer {
	return &RiskScorer{
		entropyCalculator: NewEntropyCalculator(),
	}
}

// CalculateRiskScore calculates a composite risk score (0-100)
// considering pattern severity, entropy, and context
func (rs *RiskScorer) CalculateRiskScore(pattern *DetectedPattern) float64 {
	// Base score from severity (0-40 points)
	severityScore := float64(pattern.Severity.Score()) * 10.0

	// Entropy bonus (0-30 points)
	entropyScore := rs.calculateEntropyBonus(pattern.MatchText)

	// Pattern length bonus (0-20 points) - longer matches are more suspicious
	lengthScore := rs.calculateLengthBonus(pattern.MatchText)

	// Additional context clues (0-10 points)
	contextScore := rs.calculateContextBonus(pattern)

	totalScore := severityScore + entropyScore + lengthScore + contextScore

	// Cap at 100
	if totalScore > 100 {
		totalScore = 100
	}

	return totalScore
}

// calculateEntropyBonus returns bonus points (0-30) based on entropy
func (rs *RiskScorer) calculateEntropyBonus(matchText string) float64 {
	entropy := rs.entropyCalculator.CalculateEntropy(matchText)

	if entropy >= 5.5 {
		return 30.0
	} else if entropy >= 4.5 {
		return 20.0
	} else if entropy >= 3.5 {
		return 10.0
	}
	return 0.0
}

// calculateLengthBonus returns bonus points (0-20) based on match length
// Longer secrets are generally more complex and suspicious
func (rs *RiskScorer) calculateLengthBonus(matchText string) float64 {
	length := len(matchText)

	if length >= 64 {
		return 20.0
	} else if length >= 32 {
		return 15.0
	} else if length >= 16 {
		return 10.0
	} else if length >= 8 {
		return 5.0
	}
	return 0.0
}

// calculateContextBonus returns bonus points (0-10) based on context
func (rs *RiskScorer) calculateContextBonus(pattern *DetectedPattern) float64 {
	score := 0.0

	// Check for keywords indicating higher risk
	lowerContext := pattern.Context
	riskKeywords := []string{
		"password", "secret", "token", "key", "private",
		"credential", "auth", "api", "access", "aws",
	}

	for _, keyword := range riskKeywords {
		if contains(lowerContext, keyword) {
			score += 2.0
		}
	}

	// Cap at 10
	if score > 10.0 {
		score = 10.0
	}

	return score
}

// AssignSeverityFromRiskScore determines a severity level from a risk score
func (rs *RiskScorer) AssignSeverityFromRiskScore(riskScore float64) Severity {
	if riskScore >= 75 {
		return Critical
	} else if riskScore >= 50 {
		return High
	} else if riskScore >= 25 {
		return Medium
	}
	return Low
}

// contains checks if a string contains a substring (case-insensitive)
func contains(text, substr string) bool {
	lower := toLower(text)
	return stringContains(lower, toLower(substr))
}

// toLower converts a string to lowercase
func toLower(s string) string {
	result := make([]byte, len(s))
	for i, c := range []byte(s) {
		if c >= 'A' && c <= 'Z' {
			result[i] = c + 32
		} else {
			result[i] = c
		}
	}
	return string(result)
}

// stringContains checks if a string contains a substring
func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
