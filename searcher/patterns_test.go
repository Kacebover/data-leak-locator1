package searcher

import (
	"testing"
)

// TestNewPatterns creates and validates pattern initialization
func TestNewPatterns(t *testing.T) {
	patterns := NewPatterns()

	if patterns == nil {
		t.Fatal("NewPatterns returned nil")
	}

	if len(patterns.patterns) == 0 {
		t.Error("NewPatterns should have initialized patterns")
	}
}

// TestPasswordPattern tests password detection pattern
func TestPasswordPattern(t *testing.T) {
	patterns := NewPatterns()

	tests := []struct {
		text       string
		shouldFind bool
	}{
		{"password=secret123", true},
		{"password: mypass", true},
		{"Password='anotherpass'", true},
		{"no password here", false},
		{"passwd field", false},
	}

	for _, test := range tests {
		detections := patterns.FindAll(test.text)
		found := false
		for _, det := range detections {
			if det.Type == PatternPassword {
				found = true
				break
			}
		}

		if found != test.shouldFind {
			t.Errorf("Password pattern: text='%s', expected=%v, got=%v", test.text, test.shouldFind, found)
		}
	}
}

// TestEmailPattern tests email detection
func TestEmailPattern(t *testing.T) {
	patterns := NewPatterns()

	tests := []struct {
		text       string
		shouldFind bool
	}{
		{"Contact: user@example.com", true},
		{"admin@company.co.uk", true},
		{"invalid.email@", false},
		{"@nodomain.com", false},
	}

	for _, test := range tests {
		detections := patterns.FindAll(test.text)
		found := false
		for _, det := range detections {
			if det.Type == PatternEmail {
				found = true
				break
			}
		}

		if found != test.shouldFind {
			t.Errorf("Email pattern: text='%s', expected=%v, got=%v", test.text, test.shouldFind, found)
		}
	}
}

// TestCreditCardPattern tests credit card detection
func TestCreditCardPattern(t *testing.T) {
	patterns := NewPatterns()

	tests := []struct {
		text       string
		shouldFind bool
	}{
		{"Card: 4532015112830366", true}, // Valid Visa
		{"5425233010103010", true},       // Valid Mastercard
		{"1234567890123456", false},      // Invalid
		{"Card number hidden", false},
	}

	for _, test := range tests {
		detections := patterns.FindAll(test.text)
		found := false
		for _, det := range detections {
			if det.Type == PatternCreditCard {
				found = true
				break
			}
		}

		if found != test.shouldFind {
			t.Errorf("Credit Card pattern: text='%s', expected=%v, got=%v", test.text, test.shouldFind, found)
		}
	}
}

// TestAPIKeyPattern tests API key detection
func TestAPIKeyPattern(t *testing.T) {
	patterns := NewPatterns()

	tests := []struct {
		text       string
		shouldFind bool
	}{
		{"api_key=sk_live_abcdefghijklmnop", true},
		{"API-KEY: very_long_api_key_string_value", true},
		{"short_key", false},
	}

	for _, test := range tests {
		detections := patterns.FindAll(test.text)
		found := false
		for _, det := range detections {
			if det.Type == PatternAPIKey {
				found = true
				break
			}
		}

		if found != test.shouldFind {
			t.Errorf("API Key pattern: text='%s', expected=%v, got=%v", test.text, test.shouldFind, found)
		}
	}
}

// TestAWSKeyPattern tests AWS key detection
func TestAWSKeyPattern(t *testing.T) {
	patterns := NewPatterns()

	tests := []struct {
		text       string
		shouldFind bool
	}{
		{"Key: AKIAIOSFODNN7EXAMPLE", true},
		{"aws_key = AKIAIOSFODNN7EXAMPLE", true},
		{"AKIA is a prefix but not enough chars", false},
	}

	for _, test := range tests {
		detections := patterns.FindAll(test.text)
		found := false
		for _, det := range detections {
			if det.Type == PatternAWSKey {
				found = true
				break
			}
		}

		if found != test.shouldFind {
			t.Errorf("AWS Key pattern: text='%s', expected=%v, got=%v", test.text, test.shouldFind, found)
		}
	}
}

// TestPrivateKeyPattern tests private key detection
func TestPrivateKeyPattern(t *testing.T) {
	patterns := NewPatterns()

	text := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"

	detections := patterns.FindAll(text)
	found := false
	for _, det := range detections {
		if det.Type == PatternPrivateKey {
			found = true
			break
		}
	}

	if !found {
		t.Error("Failed to detect private key")
	}
}

// TestMultiplePatterns tests detection of multiple patterns in one text
func TestMultiplePatterns(t *testing.T) {
	patterns := NewPatterns()

	text := `
	email = admin@example.com
	password = secretPass123
	api_key = sk_live_veryverylongapikeystringhere
	`

	detections := patterns.FindAll(text)

	if len(detections) < 3 {
		t.Errorf("Expected at least 3 pattern detections, got %d", len(detections))
	}

	hasEmail := false
	hasPassword := false
	hasAPIKey := false

	for _, det := range detections {
		switch det.Type {
		case PatternEmail:
			hasEmail = true
		case PatternPassword:
			hasPassword = true
		case PatternAPIKey:
			hasAPIKey = true
		}
	}

	if !hasEmail || !hasPassword || !hasAPIKey {
		t.Error("Expected to find email, password, and API key patterns")
	}
}

// TestJSONSecretPattern tests JSON secret detection
func TestJSONSecretPattern(t *testing.T) {
	patterns := NewPatterns()

	text := `{"api_key": "sk_live_secretkey123", "password": "hidden123"}`

	detections := patterns.FindAll(text)

	if len(detections) < 1 {
		t.Error("Failed to detect JSON secrets")
	}
}

// TestPatternSeverity tests that patterns have correct severity levels
func TestPatternSeverity(t *testing.T) {
	patterns := NewPatterns()

	// Get a pattern and check severity
	pattern := patterns.GetPatternByType(PatternCreditCard)
	if pattern == nil {
		t.Fatal("Failed to get credit card pattern")
	}

	if pattern.Severity != Critical {
		t.Errorf("Credit card should have Critical severity, got %s", pattern.Severity)
	}

	emailPattern := patterns.GetPatternByType(PatternEmail)
	if emailPattern == nil {
		t.Fatal("Failed to get email pattern")
	}

	if emailPattern.Severity != Medium {
		t.Errorf("Email should have Medium severity, got %s", emailPattern.Severity)
	}
}

// TestEmptyText tests pattern matching with empty text
func TestEmptyText(t *testing.T) {
	patterns := NewPatterns()

	detections := patterns.FindAll("")

	if len(detections) != 0 {
		t.Errorf("Empty text should return no detections, got %d", len(detections))
	}
}

// TestNoMatches tests text with no matching patterns
func TestNoMatches(t *testing.T) {
	patterns := NewPatterns()

	text := "This is just a regular sentence with no sensitive data at all."

	detections := patterns.FindAll(text)

	if len(detections) != 0 {
		t.Errorf("Regular text should return no detections, got %d", len(detections))
	}
}
