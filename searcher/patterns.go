package searcher

import (
	"regexp"
)

// PatternType represents the category of sensitive data detected
type PatternType string

const (
	// Credentials
	PatternPassword    PatternType = "password"
	PatternAPIKey      PatternType = "api_key"
	PatternToken       PatternType = "token"
	PatternPrivateKey  PatternType = "private_key"
	PatternAWSKey      PatternType = "aws_key"
	PatternGitHubToken PatternType = "github_token"

	// Personal Data
	PatternEmail       PatternType = "email"
	PatternPhoneNumber PatternType = "phone_number"
	PatternSSN         PatternType = "ssn"
	PatternPassport    PatternType = "passport"

	// Financial Data
	PatternCreditCard PatternType = "credit_card"
	PatternIBAN       PatternType = "iban"
	PatternBIC        PatternType = "bic"

	// Configuration & Secrets
	PatternEnvVar     PatternType = "env_var"
	PatternJSONSecret PatternType = "json_secret"
	PatternYAMLSecret PatternType = "yaml_secret"

	// Hardcoded Secrets
	PatternHardcodedSecret PatternType = "hardcoded_secret"
	PatternConnectionStr   PatternType = "connection_string"
)

// Pattern defines a regex pattern and its metadata
type Pattern struct {
	Type        PatternType
	Regex       *regexp.Regexp
	Severity    Severity
	Description string
}

// Patterns contains all detection patterns
type Patterns struct {
	patterns []*Pattern
}

// NewPatterns creates a new Patterns instance with all predefined patterns
func NewPatterns() *Patterns {
	p := &Patterns{
		patterns: make([]*Pattern, 0),
	}

	// Credentials Patterns
	p.addPattern(PatternPassword, `(?i)(password\s*[=:]\s*['"]?[^\s'";]+['"]?)`, Critical, "Password assignment detected")
	p.addPattern(PatternAPIKey, `(?i)(api[_-]?key\s*[=:]\s*['"]?[^\s'";]{20,}['"]?)`, Critical, "API Key detected")
	p.addPattern(PatternToken, `(?i)(token\s*[=:]\s*['"]?[A-Za-z0-9\-_.]{20,}['"]?)`, Critical, "Authentication token detected")
	p.addPattern(PatternPrivateKey, `-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY`, Critical, "Private key detected")
	p.addPattern(PatternAWSKey, `(AKIA[0-9A-Z]{16})`, Critical, "AWS Access Key detected")
	p.addPattern(PatternGitHubToken, `(gh[pousr]_[A-Za-z0-9_]{36,255})`, Critical, "GitHub token detected")

	// Personal Data Patterns
	p.addPattern(PatternEmail, `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`, Medium, "Email address detected")
	p.addPattern(PatternPhoneNumber, `(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b`, Medium, "Phone number detected")
	// SSN pattern - Go RE2 doesn't support lookaheads, so we use a simpler pattern
	// This matches XXX-XX-XXXX where first digit is 0-8 (excludes 9xx and catches most valid SSNs)
	p.addPattern(PatternSSN, `\b[0-8]\d{2}-[0-9]{2}-[0-9]{4}\b`, High, "Social Security Number detected")
	p.addPattern(PatternPassport, `(?i)passport\s*[:=]\s*([A-Z]{1,2}[0-9]{6,9})`, High, "Passport number detected")

	// Financial Data Patterns
	p.addPattern(PatternCreditCard, `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b`, Critical, "Credit card number detected")
	p.addPattern(PatternIBAN, `\b[A-Z]{2}[0-9]{2}[A-Z0-9]{1,30}\b`, High, "IBAN detected")
	p.addPattern(PatternBIC, `\b[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?\b`, Medium, "BIC code detected")

	// Configuration & Secrets Patterns
	p.addPattern(PatternEnvVar, `(?i)export\s+[A-Z_][A-Z0-9_]*\s*=\s*['"]?[^\s'";]+['"]?`, High, "Environment variable assignment detected")
	p.addPattern(PatternJSONSecret, `(?i)(["\']?(api_key|password|secret|token|private_key|access_key)["\']?\s*:\s*["\']?[A-Za-z0-9\-_.]{8,}["\']?)`, High, "JSON secret detected")
	p.addPattern(PatternYAMLSecret, `(?i)([a-z_]+_key|secret|password)\s*:\s*[A-Za-z0-9\-_.]{8,}`, High, "YAML secret detected")

	// Hardcoded Secrets
	p.addPattern(PatternConnectionStr, `(?i)(connection_string|database_url|db_connection)\s*[=:]\s*['"]?[^\s'";]+['"]?`, High, "Connection string detected")
	p.addPattern(PatternHardcodedSecret, `(?i)(secret|api_secret|private_secret)\s*[=:]\s*['"]?[A-Za-z0-9\-_.=+/]{16,}['"]?`, Critical, "Hardcoded secret detected")

	return p
}

// addPattern adds a pattern to the patterns list
func (p *Patterns) addPattern(patternType PatternType, regexStr string, severity Severity, description string) {
	regex, err := regexp.Compile(regexStr)
	if err != nil {
		// Skip invalid patterns
		return
	}

	p.patterns = append(p.patterns, &Pattern{
		Type:        patternType,
		Regex:       regex,
		Severity:    severity,
		Description: description,
	})
}

// FindAll returns all patterns matching in the given text
func (p *Patterns) FindAll(text string) []*DetectedPattern {
	var results []*DetectedPattern

	for _, pattern := range p.patterns {
		matches := pattern.Regex.FindAllStringIndex(text, -1)
		for _, match := range matches {
			results = append(results, &DetectedPattern{
				Type:        pattern.Type,
				Pattern:     pattern.Regex.String(),
				Severity:    pattern.Severity,
				Description: pattern.Description,
				StartIndex:  match[0],
				EndIndex:    match[1],
				MatchText:   text[match[0]:match[1]],
			})
		}
	}

	return results
}

// GetPatternByType returns all patterns of a specific type
func (p *Patterns) GetPatternByType(patternType PatternType) *Pattern {
	for _, pattern := range p.patterns {
		if pattern.Type == patternType {
			return pattern
		}
	}
	return nil
}
