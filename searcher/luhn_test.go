package searcher

import "testing"

func TestLuhnValidator_IsValid(t *testing.T) {
	validator := NewLuhnValidator()
	
	tests := []struct {
		name     string
		cardNum  string
		expected bool
	}{
		// Valid card numbers
		{"Valid Visa 1", "4111111111111111", true},
		{"Valid Visa 2", "4532015112830366", true},
		{"Valid Mastercard", "5425233430109903", true},
		{"Valid Amex", "378282246310005", true},
		{"Valid Discover", "6011000990139424", true},
		{"Valid JCB", "3530111333300000", true},
		
		// Valid with formatting
		{"Valid with dashes", "4111-1111-1111-1111", true},
		{"Valid with spaces", "4111 1111 1111 1111", true},
		{"Valid with mixed format", "4111-1111 1111-1111", true},
		
		// Invalid card numbers
		{"Invalid Luhn", "4111111111111112", false},
		{"Too short", "41111111111", false},
		{"Too long", "41111111111111111111", false},
		{"Contains letters", "4111111111111a11", false},
		{"All zeros", "0000000000000000", true}, // Actually passes Luhn
		{"Random invalid", "1234567890123456", false},
		{"Empty string", "", false},
		{"Single digit", "4", false},
		
		// Edge cases
		{"13 digit valid", "4222222222222", true},
		{"19 digit number", "6011111111111111117", false}, // Not all 19-digit are valid
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := validator.IsValid(tt.cardNum)
			if result != tt.expected {
				t.Errorf("IsValid(%q) = %v, expected %v", tt.cardNum, result, tt.expected)
			}
		})
	}
}

func TestLuhnValidator_GetCardType(t *testing.T) {
	validator := NewLuhnValidator()
	
	tests := []struct {
		name         string
		cardNum      string
		expectedType string
	}{
		{"Visa", "4111111111111111", "Visa"},
		{"Mastercard", "5425233430109903", "Mastercard"},
		{"American Express", "378282246310005", "American Express"},
		{"Discover 60xx", "6011000990139424", "Discover"},
		{"JCB", "3530111333300000", "JCB"},
		{"Diners Club 36", "36000000000000", "Diners Club"},
		{"Unknown", "9999999999999999", "Unknown"},
		{"Empty", "", "Unknown"},
	}
	
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cardType := validator.GetCardType(tt.cardNum)
			if cardType != tt.expectedType {
				t.Errorf("GetCardType(%q) = %q, expected %q", tt.cardNum, cardType, tt.expectedType)
			}
		})
	}
}

func TestLuhnValidator_ValidateAndClassify(t *testing.T) {
	validator := NewLuhnValidator()
	
	// Test valid card
	valid, cardType := validator.ValidateAndClassify("4111111111111111")
	if !valid {
		t.Error("Expected valid card to be validated")
	}
	if cardType != "Visa" {
		t.Errorf("Expected Visa, got %s", cardType)
	}
	
	// Test invalid card
	valid, cardType = validator.ValidateAndClassify("1234567890123456")
	if valid {
		t.Error("Expected invalid card to fail validation")
	}
	if cardType != "" {
		t.Errorf("Expected empty card type for invalid card, got %s", cardType)
	}
}

func TestCleanCardNumber(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"4111111111111111", "4111111111111111"},
		{"4111-1111-1111-1111", "4111111111111111"},
		{"4111 1111 1111 1111", "4111111111111111"},
		{"4111-1111 1111-1111", "4111111111111111"},
		{"   4111   ", "4111"},
		{"", ""},
	}
	
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := cleanCardNumber(tt.input)
			if result != tt.expected {
				t.Errorf("cleanCardNumber(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestLuhnCheck(t *testing.T) {
	tests := []struct {
		number   string
		expected bool
	}{
		{"4111111111111111", true},
		{"4111111111111112", false},
		{"0", true},  // Single zero passes
		{"00", true}, // Double zero passes
		{"79927398713", true}, // Known valid Luhn number
		{"79927398710", false},
	}
	
	for _, tt := range tests {
		t.Run(tt.number, func(t *testing.T) {
			result := luhnCheck(tt.number)
			if result != tt.expected {
				t.Errorf("luhnCheck(%q) = %v, expected %v", tt.number, result, tt.expected)
			}
		})
	}
}

func BenchmarkLuhnCheck(b *testing.B) {
	validator := NewLuhnValidator()
	cardNumber := "4111111111111111"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.IsValid(cardNumber)
	}
}

func BenchmarkLuhnCheckWithFormatting(b *testing.B) {
	validator := NewLuhnValidator()
	cardNumber := "4111-1111-1111-1111"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		validator.IsValid(cardNumber)
	}
}

