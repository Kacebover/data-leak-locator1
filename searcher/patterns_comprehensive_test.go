package searcher

import (
	"strings"
	"testing"
)

// TestPatternDetection_Passwords tests password pattern detection
func TestPatternDetection_Passwords(t *testing.T) {
	patterns := NewPatterns()
	
	tests := []struct {
		name        string
		input       string
		shouldMatch bool
		patternType PatternType
	}{
		// Should match
		{"Simple password assignment", "password=secret123", true, PatternPassword},
		{"Password with quotes", `password="mysecret"`, true, PatternPassword},
		{"Password with single quotes", "password='mysecret'", true, PatternPassword},
		{"PASSWORD uppercase", "PASSWORD=Secret", true, PatternPassword},
		{"Password with colon", "password: secretvalue", true, PatternPassword},
		{"Password with spaces", "password = secret123", true, PatternPassword},
		
		// Should not match
		{"Empty password", "password=", false, PatternPassword},
		{"Just the word password", "password", false, PatternPassword},
		{"Password in URL path", "/reset-password", false, PatternPassword},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := patterns.FindAll(tt.input)
			found := false
			for _, m := range matches {
				if m.Type == tt.patternType {
					found = true
					break
				}
			}
			if found != tt.shouldMatch {
				t.Errorf("Pattern detection for %q: got match=%v, want match=%v", tt.input, found, tt.shouldMatch)
			}
		})
	}
}

// TestPatternDetection_AWSKeys tests AWS key pattern detection
func TestPatternDetection_AWSKeys(t *testing.T) {
	patterns := NewPatterns()
	
	tests := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		// Valid AWS Access Key IDs (start with AKIA)
		{"Valid AWS key", "AKIAIOSFODNN7EXAMPLE", true},
		{"AWS key in context", "aws_access_key_id = AKIAIOSFODNN7EXAMPLE", true},
		{"AWS key with quotes", `"AKIAIOSFODNN7EXAMPLE"`, true},
		
		// Invalid patterns
		{"Too short AKIA", "AKIAIOSFODN", false},
		{"Wrong prefix", "BKIAIOSFODNN7EXAMPLE", false},
		{"Lowercase", "akiaiosfodnn7example", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := patterns.FindAll(tt.input)
			found := false
			for _, m := range matches {
				if m.Type == PatternAWSKey {
					found = true
					break
				}
			}
			if found != tt.shouldMatch {
				t.Errorf("AWS key detection for %q: got match=%v, want match=%v", tt.input, found, tt.shouldMatch)
			}
		})
	}
}

// TestPatternDetection_GitHubTokens tests GitHub token pattern detection
func TestPatternDetection_GitHubTokens(t *testing.T) {
	patterns := NewPatterns()
	
	tests := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		// Valid GitHub tokens
		{"Personal access token", "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234", true},
		{"OAuth token", "gho_1234567890abcdefghijklmnopqrstuvwxyz1234", true},
		{"User-to-server token", "ghu_1234567890abcdefghijklmnopqrstuvwxyz1234", true},
		{"Server-to-server token", "ghs_1234567890abcdefghijklmnopqrstuvwxyz1234", true},
		{"Refresh token", "ghr_1234567890abcdefghijklmnopqrstuvwxyz1234", true},
		
		// Invalid patterns
		{"Too short", "ghp_123456", false},
		{"Wrong prefix", "ghx_1234567890abcdefghijklmnopqrstuvwxyz1234", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := patterns.FindAll(tt.input)
			found := false
			for _, m := range matches {
				if m.Type == PatternGitHubToken {
					found = true
					break
				}
			}
			if found != tt.shouldMatch {
				t.Errorf("GitHub token detection for %q: got match=%v, want match=%v", tt.input, found, tt.shouldMatch)
			}
		})
	}
}

// TestPatternDetection_PrivateKeys tests private key pattern detection
func TestPatternDetection_PrivateKeys(t *testing.T) {
	patterns := NewPatterns()
	
	tests := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		// Valid private key headers
		{"RSA private key", "-----BEGIN RSA PRIVATE KEY-----", true},
		{"Generic private key", "-----BEGIN PRIVATE KEY-----", true},
		{"EC private key", "-----BEGIN EC PRIVATE KEY-----", false}, // Pattern doesn't include EC
		{"DSA private key", "-----BEGIN DSA PRIVATE KEY-----", false},
		
		// Should not match
		{"Public key", "-----BEGIN PUBLIC KEY-----", false},
		{"Certificate", "-----BEGIN CERTIFICATE-----", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := patterns.FindAll(tt.input)
			found := false
			for _, m := range matches {
				if m.Type == PatternPrivateKey {
					found = true
					break
				}
			}
			if found != tt.shouldMatch {
				t.Errorf("Private key detection for %q: got match=%v, want match=%v", tt.input, found, tt.shouldMatch)
			}
		})
	}
}

// TestPatternDetection_CreditCards tests credit card pattern detection
func TestPatternDetection_CreditCards(t *testing.T) {
	patterns := NewPatterns()
	
	tests := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		// Valid credit card patterns
		{"Visa 16 digit", "4111111111111111", true},
		{"Visa 13 digit", "4222222222222", true},
		{"Mastercard", "5425233430109903", true},
		{"Amex", "378282246310005", true},
		{"Discover", "6011000990139424", true},
		
		// In context
		{"Card in text", "My card is 4111111111111111", true},
		{"Card with label", "credit_card: 5425233430109903", true},
		
		// Should not match (but our regex might still match - it doesn't do Luhn)
		{"Short number", "411111111111", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := patterns.FindAll(tt.input)
			found := false
			for _, m := range matches {
				if m.Type == PatternCreditCard {
					found = true
					break
				}
			}
			if found != tt.shouldMatch {
				t.Errorf("Credit card detection for %q: got match=%v, want match=%v", tt.input, found, tt.shouldMatch)
			}
		})
	}
}

// TestPatternDetection_Emails tests email pattern detection
func TestPatternDetection_Emails(t *testing.T) {
	patterns := NewPatterns()
	
	tests := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		// Valid emails
		{"Simple email", "user@example.com", true},
		{"Email with subdomain", "user@mail.example.com", true},
		{"Email with plus", "user+tag@example.com", true},
		{"Email with dots", "first.last@example.com", true},
		{"Email with numbers", "user123@example.com", true},
		
		// In context
		{"Email in sentence", "Contact us at support@company.org", true},
		{"Email in JSON", `"email": "admin@example.com"`, true},
		
		// Should not match
		{"At sign only", "@", false},
		{"No domain", "user@", false},
		{"No user", "@example.com", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := patterns.FindAll(tt.input)
			found := false
			for _, m := range matches {
				if m.Type == PatternEmail {
					found = true
					break
				}
			}
			if found != tt.shouldMatch {
				t.Errorf("Email detection for %q: got match=%v, want match=%v", tt.input, found, tt.shouldMatch)
			}
		})
	}
}

// TestPatternDetection_SSN tests Social Security Number pattern detection
func TestPatternDetection_SSN(t *testing.T) {
	patterns := NewPatterns()
	
	tests := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		// Valid SSN format (simplified pattern for Go RE2 compatibility)
		{"Valid SSN", "219-09-9999", true},
		{"SSN in context", "SSN: 078-05-1120", true},
		{"Another valid SSN", "457-55-5462", true},
		{"SSN starting with 0", "078-05-1234", true},
		
		// Invalid - starts with 9xx (pattern excludes these)
		{"Invalid area 9xx", "900-45-6789", false},
		
		// Wrong format
		{"No dashes", "219099999", false},
		{"Wrong separators", "219.09.9999", false},
		
		// Note: Simplified pattern can't exclude 000, 666, 00 group, or 0000 serial
		// Those would require lookaheads which Go RE2 doesn't support
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := patterns.FindAll(tt.input)
			found := false
			for _, m := range matches {
				if m.Type == PatternSSN {
					found = true
					break
				}
			}
			if found != tt.shouldMatch {
				t.Errorf("SSN detection for %q: got match=%v, want match=%v", tt.input, found, tt.shouldMatch)
			}
		})
	}
}

// TestPatternDetection_JSONSecrets tests JSON secret pattern detection
func TestPatternDetection_JSONSecrets(t *testing.T) {
	patterns := NewPatterns()
	
	tests := []struct {
		name        string
		input       string
		shouldMatch bool
	}{
		// Valid JSON secrets
		{"API key in JSON", `"api_key": "abcdefgh12345678"`, true},
		{"Password in JSON", `"password": "secretvalue123"`, true},
		{"Token in JSON", `"token": "abcdefghijklmnop"`, true},
		{"Secret in JSON", `"secret": "mysecretvalue12"`, true},
		
		// Should not match
		{"Short value", `"api_key": "short"`, false},
		{"Non-secret key", `"username": "myuser"`, false},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := patterns.FindAll(tt.input)
			found := false
			for _, m := range matches {
				if m.Type == PatternJSONSecret {
					found = true
					break
				}
			}
			if found != tt.shouldMatch {
				t.Errorf("JSON secret detection for %q: got match=%v, want match=%v", tt.input, found, tt.shouldMatch)
			}
		})
	}
}

// TestPatternDetection_MultiplePatterns tests detection of multiple patterns in same line
func TestPatternDetection_MultiplePatterns(t *testing.T) {
	patterns := NewPatterns()
	
	// Line with multiple secrets
	input := "password=secret123 AKIAIOSFODNN7EXAMPLE email@example.com"
	
	matches := patterns.FindAll(input)
	
	// Should find at least password, AWS key, and email
	foundTypes := make(map[PatternType]bool)
	for _, m := range matches {
		foundTypes[m.Type] = true
	}
	
	expectedTypes := []PatternType{PatternPassword, PatternAWSKey, PatternEmail}
	for _, pt := range expectedTypes {
		if !foundTypes[pt] {
			t.Errorf("Expected to find pattern type %s in multi-pattern line", pt)
		}
	}
}

// TestPatternDetection_Severity tests that severities are correctly assigned
func TestPatternDetection_Severity(t *testing.T) {
	patterns := NewPatterns()
	
	tests := []struct {
		input            string
		expectedSeverity Severity
		patternType      PatternType
	}{
		{"password=secret123", Critical, PatternPassword},
		{"AKIAIOSFODNN7EXAMPLE", Critical, PatternAWSKey},
		{"-----BEGIN RSA PRIVATE KEY-----", Critical, PatternPrivateKey},
		{"4111111111111111", Critical, PatternCreditCard},
		{"user@example.com", Medium, PatternEmail},
		{"219-09-9999", High, PatternSSN}, // Valid SSN format
	}
	
	for _, tt := range tests {
		t.Run(string(tt.patternType), func(t *testing.T) {
			matches := patterns.FindAll(tt.input)
			for _, m := range matches {
				if m.Type == tt.patternType {
					if m.Severity != tt.expectedSeverity {
						t.Errorf("Pattern %s has severity %s, expected %s", tt.patternType, m.Severity, tt.expectedSeverity)
					}
					return
				}
			}
			t.Errorf("Pattern type %s not found in matches", tt.patternType)
		})
	}
}

// TestPatternDetection_MatchPositions tests that match positions are correct
func TestPatternDetection_MatchPositions(t *testing.T) {
	patterns := NewPatterns()
	
	input := "prefix password=secret suffix"
	matches := patterns.FindAll(input)
	
	for _, m := range matches {
		if m.Type == PatternPassword {
			matchText := input[m.StartIndex:m.EndIndex]
			if !strings.Contains(matchText, "password") || !strings.Contains(matchText, "secret") {
				t.Errorf("Match position incorrect: got %q at [%d:%d]", matchText, m.StartIndex, m.EndIndex)
			}
			return
		}
	}
	t.Error("Password pattern not found")
}

// BenchmarkPatternMatching benchmarks pattern matching performance
func BenchmarkPatternMatching(b *testing.B) {
	patterns := NewPatterns()
	input := "password=secret123 AKIAIOSFODNN7EXAMPLE user@example.com 4111111111111111"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		patterns.FindAll(input)
	}
}

// BenchmarkPatternMatchingLongText benchmarks pattern matching on longer text
func BenchmarkPatternMatchingLongText(b *testing.B) {
	patterns := NewPatterns()
	
	// Create a long text with some secrets
	var builder strings.Builder
	for i := 0; i < 100; i++ {
		builder.WriteString("This is line ")
		builder.WriteString(string(rune('0' + i%10)))
		builder.WriteString(" of normal text without any secrets.\n")
	}
	builder.WriteString("password=hidden_secret_here\n")
	for i := 0; i < 100; i++ {
		builder.WriteString("More normal text on line ")
		builder.WriteString(string(rune('0' + i%10)))
		builder.WriteString(".\n")
	}
	
	input := builder.String()
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		patterns.FindAll(input)
	}
}

