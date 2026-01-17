package searcher

import (
	"testing"
)

// TestNewRiskScorer creates and validates risk scorer
func TestNewRiskScorer(t *testing.T) {
	scorer := NewRiskScorer()

	if scorer == nil {
		t.Fatal("NewRiskScorer returned nil")
	}

	if scorer.entropyCalculator == nil {
		t.Fatal("Risk scorer entropy calculator is nil")
	}
}

// TestCalculateRiskScore tests risk score calculation
func TestCalculateRiskScore(t *testing.T) {
	scorer := NewRiskScorer()

	tests := []struct {
		pattern          *DetectedPattern
		minExpectedScore float64
		maxExpectedScore float64
	}{
		{
			&DetectedPattern{
				Type:      PatternCreditCard,
				Severity:  Critical,
				MatchText: "4532015112830366",
				Context:   "credit card: 4532015112830366",
			},
			50.0, // 40 (critical) + 10 (length) = 50
			100.0,
		},
		{
			&DetectedPattern{
				Type:      PatternEmail,
				Severity:  Medium,
				MatchText: "user@example.com",
				Context:   "email: user@example.com",
			},
			10.0, // Should be lower due to medium severity
			40.0,
		},
		{
			&DetectedPattern{
				Type:      PatternPassword,
				Severity:  Critical,
				MatchText: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP",
				Context:   "password=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP",
			},
			40.0,
			100.0,
		},
	}

	for i, test := range tests {
		score := scorer.CalculateRiskScore(test.pattern)

		if score < test.minExpectedScore || score > test.maxExpectedScore {
			t.Errorf("Test %d: expected score between %.1f-%.1f, got %.1f",
				i, test.minExpectedScore, test.maxExpectedScore, score)
		}
	}
}

// TestSeverityFromRiskScore tests severity assignment from risk score
func TestSeverityFromRiskScore(t *testing.T) {
	scorer := NewRiskScorer()

	tests := []struct {
		riskScore        float64
		expectedSeverity Severity
	}{
		{10.0, Low},
		{30.0, Medium},
		{60.0, High},
		{80.0, Critical},
		{95.0, Critical},
	}

	for _, test := range tests {
		severity := scorer.AssignSeverityFromRiskScore(test.riskScore)

		if severity != test.expectedSeverity {
			t.Errorf("Risk score %.1f: expected %s, got %s",
				test.riskScore, test.expectedSeverity, severity)
		}
	}
}

// TestCalculateEntropyBonus tests entropy bonus calculation
func TestCalculateEntropyBonus(t *testing.T) {
	scorer := NewRiskScorer()

	tests := []struct {
		text        string
		minExpected float64
		maxExpected float64
	}{
		{"aaaaaaaaaa", 0.0, 0.0},                                      // Low entropy
		{"Random123!@#", 10.0, 30.0},                                  // Medium-high entropy
		{"sk_live_abc123def456ghi789jk_secret_very_long", 20.0, 30.0}, // Very high entropy + long
	}

	for _, test := range tests {
		// We access the private method via a pattern
		pattern := &DetectedPattern{MatchText: test.text}
		bonus := scorer.calculateEntropyBonus(pattern.MatchText)

		if bonus < test.minExpected || bonus > test.maxExpected {
			t.Errorf("Text '%s': expected bonus between %.1f-%.1f, got %.1f",
				test.text, test.minExpected, test.maxExpected, bonus)
		}
	}
}

// TestCalculateLengthBonus tests length bonus calculation
func TestCalculateLengthBonus(t *testing.T) {
	scorer := NewRiskScorer()

	tests := []struct {
		text     string
		minBonus float64
		maxBonus float64
	}{
		{"short", 0.0, 0.0},                       // Too short
		{"medium_length", 0.0, 5.0},               // Short
		{"longer_length_string", 5.0, 10.0},       // Medium
		{"a" + repeatString("b", 40), 15.0, 20.0}, // Long
		{"a" + repeatString("b", 70), 20.0, 20.0}, // Very long
	}

	for _, test := range tests {
		bonus := scorer.calculateLengthBonus(test.text)

		if bonus < test.minBonus || bonus > test.maxBonus {
			t.Errorf("Text length %d: expected bonus between %.1f-%.1f, got %.1f",
				len(test.text), test.minBonus, test.maxBonus, bonus)
		}
	}
}

// TestCalculateContextBonus tests context bonus calculation
func TestCalculateContextBonus(t *testing.T) {
	scorer := NewRiskScorer()

	tests := []struct {
		pattern  *DetectedPattern
		minBonus float64
	}{
		{
			&DetectedPattern{Context: "random text"},
			0.0,
		},
		{
			&DetectedPattern{Context: "password=secret123"},
			1.0,
		},
		{
			&DetectedPattern{Context: "api_key: secret token with private data"},
			5.0,
		},
	}

	for _, test := range tests {
		bonus := scorer.calculateContextBonus(test.pattern)

		if bonus < test.minBonus {
			t.Errorf("Context '%s': expected bonus >= %.1f, got %.1f",
				test.pattern.Context, test.minBonus, bonus)
		}
	}
}

// TestContainsHelper tests the contains helper function
func TestContains(t *testing.T) {
	tests := []struct {
		text     string
		substr   string
		expected bool
	}{
		{"password=secret", "password", true},
		{"PASSWORD=secret", "password", true},
		{"Secret token", "token", true},
		{"just text", "missing", false},
		{"", "anything", false},
	}

	for _, test := range tests {
		result := contains(test.text, test.substr)

		if result != test.expected {
			t.Errorf("contains('%s', '%s'): expected %v, got %v",
				test.text, test.substr, test.expected, result)
		}
	}
}

// TestToLower tests the toLower helper function
func TestToLower(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"HELLO", "hello"},
		{"Hello World", "hello world"},
		{"123ABC", "123abc"},
		{"already_lower", "already_lower"},
		{"MiXeD_CaSe", "mixed_case"},
	}

	for _, test := range tests {
		result := toLower(test.input)

		if result != test.expected {
			t.Errorf("toLower('%s'): expected '%s', got '%s'",
				test.input, test.expected, result)
		}
	}
}

// TestStringContains tests the stringContains helper function
func TestStringContains(t *testing.T) {
	tests := []struct {
		text     string
		substr   string
		expected bool
	}{
		{"hello world", "world", true},
		{"hello world", "hello", true},
		{"hello world", "not_here", false},
		{"", "", true},
		{"test", "t", true},
	}

	for _, test := range tests {
		result := stringContains(test.text, test.substr)

		if result != test.expected {
			t.Errorf("stringContains('%s', '%s'): expected %v, got %v",
				test.text, test.substr, test.expected, result)
		}
	}
}

// Helper function for tests
func repeatString(s string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += s
	}
	return result
}

// Benchmark risk score calculation
func BenchmarkCalculateRiskScore(b *testing.B) {
	scorer := NewRiskScorer()
	pattern := &DetectedPattern{
		Type:      PatternCreditCard,
		Severity:  Critical,
		MatchText: "4532015112830366",
		Context:   "credit card: 4532015112830366",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scorer.CalculateRiskScore(pattern)
	}
}
