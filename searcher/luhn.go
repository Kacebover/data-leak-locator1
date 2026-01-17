package searcher

// LuhnValidator validates credit card numbers using the Luhn algorithm
type LuhnValidator struct{}

// NewLuhnValidator creates a new Luhn validator
func NewLuhnValidator() *LuhnValidator {
	return &LuhnValidator{}
}

// IsValid checks if a card number passes the Luhn check
func (lv *LuhnValidator) IsValid(cardNumber string) bool {
	// Remove spaces and dashes
	cleaned := cleanCardNumber(cardNumber)

	// Must be at least 13 digits and at most 19 digits
	if len(cleaned) < 13 || len(cleaned) > 19 {
		return false
	}

	// Check if all characters are digits
	for _, c := range cleaned {
		if c < '0' || c > '9' {
			return false
		}
	}

	return luhnCheck(cleaned)
}

// cleanCardNumber removes spaces and dashes from card number
func cleanCardNumber(cardNumber string) string {
	result := make([]byte, 0, len(cardNumber))
	for _, c := range cardNumber {
		if c != ' ' && c != '-' {
			result = append(result, byte(c))
		}
	}
	return string(result)
}

// luhnCheck performs the Luhn algorithm check
func luhnCheck(number string) bool {
	sum := 0
	isSecond := false

	// Process from right to left
	for i := len(number) - 1; i >= 0; i-- {
		digit := int(number[i] - '0')

		if isSecond {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}

		sum += digit
		isSecond = !isSecond
	}

	return sum%10 == 0
}

// GetCardType returns the card type based on the card number prefix
func (lv *LuhnValidator) GetCardType(cardNumber string) string {
	cleaned := cleanCardNumber(cardNumber)

	if len(cleaned) < 2 {
		return "Unknown"
	}

	// Check prefixes
	switch {
	case cleaned[0] == '4':
		return "Visa"
	case cleaned[0] == '5' && cleaned[1] >= '1' && cleaned[1] <= '5':
		return "Mastercard"
	case cleaned[0] == '3' && (cleaned[1] == '4' || cleaned[1] == '7'):
		return "American Express"
	case cleaned[:2] == "60" || cleaned[:2] == "65":
		return "Discover"
	case cleaned[:2] == "35":
		return "JCB"
	case cleaned[:2] == "36" || cleaned[:2] == "38":
		return "Diners Club"
	default:
		return "Unknown"
	}
}

// ValidateAndClassify validates a card number and returns its type if valid
func (lv *LuhnValidator) ValidateAndClassify(cardNumber string) (bool, string) {
	if lv.IsValid(cardNumber) {
		return true, lv.GetCardType(cardNumber)
	}
	return false, ""
}
