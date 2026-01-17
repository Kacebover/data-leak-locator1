package searcher

import (
	"regexp"
	"strings"
	"unicode"
)

// MRZParser parses and validates Machine Readable Zone data
type MRZParser struct {
	// Character weights for check digit calculation
	charWeights map[rune]int
}

// MRZType represents the type of MRZ
type MRZType int

const (
	MRZTypeTD1   MRZType = iota // ID card (3 lines, 30 chars)
	MRZTypeTD2                   // Travel document (2 lines, 36 chars)
	MRZTypeTD3                   // Passport (2 lines, 44 chars)
	MRZTypeMRVA                  // Visa type A (2 lines, 44 chars)
	MRZTypeMRVB                  // Visa type B (2 lines, 36 chars)
	MRZTypeUnknown
)

// ParsedMRZ contains fully parsed MRZ data with validation
type ParsedMRZ struct {
	Type           MRZType  `json:"type"`
	TypeCode       string   `json:"type_code"`        // P, I, A, C, V
	IssuingCountry string   `json:"issuing_country"`
	Surname        string   `json:"surname"`
	GivenNames     string   `json:"given_names"`
	DocumentNumber string   `json:"document_number"`
	Nationality    string   `json:"nationality"`
	DateOfBirth    string   `json:"date_of_birth"`    // YYMMDD
	Sex            string   `json:"sex"`              // M, F, <
	ExpiryDate     string   `json:"expiry_date"`      // YYMMDD
	PersonalNumber string   `json:"personal_number,omitempty"`
	OptionalData1  string   `json:"optional_data_1,omitempty"`
	OptionalData2  string   `json:"optional_data_2,omitempty"`
	
	// Validation results
	IsValid           bool    `json:"is_valid"`
	ValidationScore   float64 `json:"validation_score"` // 0-100
	CheckDigitResults map[string]bool `json:"check_digit_results"`
	
	// Raw data
	RawLines []string `json:"raw_lines"`
	Errors   []string `json:"errors,omitempty"`
}

// NewMRZParser creates a new MRZ parser
func NewMRZParser() *MRZParser {
	parser := &MRZParser{
		charWeights: make(map[rune]int),
	}
	
	// Initialize character weights (ICAO 9303)
	// 0-9 = 0-9, A-Z = 10-35, < = 0
	for i := 0; i <= 9; i++ {
		parser.charWeights[rune('0'+i)] = i
	}
	for i := 0; i < 26; i++ {
		parser.charWeights[rune('A'+i)] = 10 + i
	}
	parser.charWeights['<'] = 0
	
	return parser
}

// ParseMRZ attempts to parse MRZ from text
func (p *MRZParser) ParseMRZ(text string) *ParsedMRZ {
	// Clean and split into lines
	lines := p.extractMRZLines(text)
	if len(lines) == 0 {
		return nil
	}
	
	result := &ParsedMRZ{
		RawLines:          lines,
		CheckDigitResults: make(map[string]bool),
	}
	
	// Determine MRZ type based on line count and length
	result.Type = p.determineMRZType(lines)
	
	switch result.Type {
	case MRZTypeTD3:
		p.parseTD3(lines, result)
	case MRZTypeTD2, MRZTypeMRVB:
		p.parseTD2(lines, result)
	case MRZTypeTD1:
		p.parseTD1(lines, result)
	default:
		result.Errors = append(result.Errors, "Неизвестный формат MRZ")
		return result
	}
	
	// Calculate validation score
	p.calculateValidationScore(result)
	
	return result
}

// extractMRZLines extracts MRZ-like lines from text
func (p *MRZParser) extractMRZLines(text string) []string {
	var mrzLines []string
	lines := strings.Split(text, "\n")
	
	for _, line := range lines {
		cleaned := p.cleanMRZLine(line)
		if p.isMRZLine(cleaned) {
			mrzLines = append(mrzLines, cleaned)
		}
	}
	
	// Try to find consecutive MRZ lines
	return p.findConsecutiveMRZLines(mrzLines)
}

// cleanMRZLine cleans a potential MRZ line
func (p *MRZParser) cleanMRZLine(line string) string {
	line = strings.TrimSpace(line)
	line = strings.ToUpper(line)
	
	// Common OCR corrections
	replacements := map[string]string{
		"O": "0", // Often confused
		" ": "",  // Remove spaces
		"«": "<", // Sometimes OCR reads < as «
		"»": "<",
		"−": "<", // Dash variants
		"-": "<",
		"–": "<",
		"—": "<",
		"_": "<",
	}
	
	// Be careful with O->0, only if surrounded by other alphanums
	// For simplicity, remove spaces
	line = strings.ReplaceAll(line, " ", "")
	
	for old, new := range replacements {
		if old != "O" { // Skip O for now
			line = strings.ReplaceAll(line, old, new)
		}
	}
	
	return line
}

// isMRZLine checks if a line could be MRZ
func (p *MRZParser) isMRZLine(line string) bool {
	// MRZ lines are 30, 36, or 44 characters
	validLengths := map[int]bool{30: true, 36: true, 44: true}
	
	if len(line) < 28 || len(line) > 46 {
		return false
	}
	
	// Check character composition
	validChars := 0
	for _, r := range line {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '<' {
			validChars++
		}
	}
	
	ratio := float64(validChars) / float64(len(line))
	
	// Must be at least 90% valid MRZ characters
	if ratio < 0.9 {
		return false
	}
	
	// Extra points for exact length
	_, isExact := validLengths[len(line)]
	return ratio > 0.95 || (ratio > 0.85 && isExact)
}

// findConsecutiveMRZLines finds the best set of consecutive MRZ lines
func (p *MRZParser) findConsecutiveMRZLines(lines []string) []string {
	if len(lines) == 0 {
		return nil
	}
	
	// Group by length
	byLength := make(map[int][]string)
	for _, line := range lines {
		l := len(line)
		byLength[l] = append(byLength[l], line)
	}
	
	// Prefer TD3 (44 chars, 2 lines)
	if lines44, ok := byLength[44]; ok && len(lines44) >= 2 {
		return lines44[:2]
	}
	
	// Then TD2/MRVB (36 chars, 2 lines)
	if lines36, ok := byLength[36]; ok && len(lines36) >= 2 {
		return lines36[:2]
	}
	
	// Then TD1 (30 chars, 3 lines)
	if lines30, ok := byLength[30]; ok && len(lines30) >= 3 {
		return lines30[:3]
	}
	
	// Return whatever we have
	if len(lines) >= 2 {
		return lines[:2]
	}
	return lines
}

// determineMRZType determines MRZ type from lines
func (p *MRZParser) determineMRZType(lines []string) MRZType {
	if len(lines) == 0 {
		return MRZTypeUnknown
	}
	
	firstLine := lines[0]
	
	// Check first character for type
	if len(firstLine) >= 44 && len(lines) >= 2 && len(lines[1]) >= 44 {
		if firstLine[0] == 'P' {
			return MRZTypeTD3
		}
		if firstLine[0] == 'V' {
			return MRZTypeMRVA
		}
	}
	
	if len(firstLine) >= 36 && len(lines) >= 2 && len(lines[1]) >= 36 {
		if firstLine[0] == 'V' {
			return MRZTypeMRVB
		}
		return MRZTypeTD2
	}
	
	if len(firstLine) >= 30 && len(lines) >= 3 {
		return MRZTypeTD1
	}
	
	return MRZTypeUnknown
}

// parseTD3 parses passport MRZ (2 lines of 44 chars)
func (p *MRZParser) parseTD3(lines []string, result *ParsedMRZ) {
	if len(lines) < 2 || len(lines[0]) < 44 || len(lines[1]) < 44 {
		result.Errors = append(result.Errors, "Недостаточно данных для TD3")
		return
	}
	
	line1 := lines[0]
	line2 := lines[1]
	
	// Line 1: P<CCCSURNAME<<GIVEN<NAMES<<<<<<<<<<<<<<<<
	result.TypeCode = string(line1[0])
	result.IssuingCountry = p.cleanFiller(line1[2:5])
	
	// Parse names
	namePart := line1[5:44]
	names := strings.SplitN(namePart, "<<", 2)
	if len(names) >= 1 {
		result.Surname = p.cleanFiller(names[0])
	}
	if len(names) >= 2 {
		result.GivenNames = strings.ReplaceAll(p.cleanFiller(names[1]), "<", " ")
		result.GivenNames = strings.TrimSpace(result.GivenNames)
	}
	
	// Line 2: DOCUMENT#<CHECK NATIONALITY DOB CHECK SEX EXPIRY CHECK OPTIONAL<<CHECK
	result.DocumentNumber = p.cleanFiller(line2[0:9])
	docCheck := int(line2[9] - '0')
	result.CheckDigitResults["document_number"] = p.validateCheckDigit(line2[0:9], docCheck)
	
	result.Nationality = p.cleanFiller(line2[10:13])
	result.DateOfBirth = line2[13:19]
	dobCheck := int(line2[19] - '0')
	result.CheckDigitResults["date_of_birth"] = p.validateCheckDigit(line2[13:19], dobCheck)
	
	result.Sex = string(line2[20])
	result.ExpiryDate = line2[21:27]
	expCheck := int(line2[27] - '0')
	result.CheckDigitResults["expiry_date"] = p.validateCheckDigit(line2[21:27], expCheck)
	
	result.PersonalNumber = p.cleanFiller(line2[28:42])
	personalCheck := int(line2[42] - '0')
	result.CheckDigitResults["personal_number"] = p.validateCheckDigit(line2[28:42], personalCheck)
	
	// Overall check digit
	overallData := line2[0:10] + line2[13:20] + line2[21:43]
	overallCheck := int(line2[43] - '0')
	result.CheckDigitResults["overall"] = p.validateCheckDigit(overallData, overallCheck)
}

// parseTD2 parses 36-character MRZ (2 lines)
func (p *MRZParser) parseTD2(lines []string, result *ParsedMRZ) {
	if len(lines) < 2 || len(lines[0]) < 36 || len(lines[1]) < 36 {
		result.Errors = append(result.Errors, "Недостаточно данных для TD2")
		return
	}
	
	line1 := lines[0]
	line2 := lines[1]
	
	result.TypeCode = string(line1[0])
	result.IssuingCountry = p.cleanFiller(line1[2:5])
	
	namePart := line1[5:36]
	names := strings.SplitN(namePart, "<<", 2)
	if len(names) >= 1 {
		result.Surname = p.cleanFiller(names[0])
	}
	if len(names) >= 2 {
		result.GivenNames = strings.ReplaceAll(p.cleanFiller(names[1]), "<", " ")
	}
	
	result.DocumentNumber = p.cleanFiller(line2[0:9])
	result.Nationality = p.cleanFiller(line2[10:13])
	result.DateOfBirth = line2[13:19]
	result.Sex = string(line2[20])
	result.ExpiryDate = line2[21:27]
	result.OptionalData1 = p.cleanFiller(line2[28:35])
}

// parseTD1 parses ID card MRZ (3 lines of 30 chars)
func (p *MRZParser) parseTD1(lines []string, result *ParsedMRZ) {
	if len(lines) < 3 {
		result.Errors = append(result.Errors, "Недостаточно данных для TD1")
		return
	}
	
	line1 := lines[0]
	line2 := lines[1]
	line3 := lines[2]
	
	if len(line1) < 30 || len(line2) < 30 || len(line3) < 30 {
		result.Errors = append(result.Errors, "Неверная длина строк TD1")
		return
	}
	
	result.TypeCode = string(line1[0])
	result.IssuingCountry = p.cleanFiller(line1[2:5])
	result.DocumentNumber = p.cleanFiller(line1[5:14])
	result.OptionalData1 = p.cleanFiller(line1[15:30])
	
	result.DateOfBirth = line2[0:6]
	result.Sex = string(line2[7])
	result.ExpiryDate = line2[8:14]
	result.Nationality = p.cleanFiller(line2[15:18])
	result.OptionalData2 = p.cleanFiller(line2[18:29])
	
	namePart := line3[0:30]
	names := strings.SplitN(namePart, "<<", 2)
	if len(names) >= 1 {
		result.Surname = p.cleanFiller(names[0])
	}
	if len(names) >= 2 {
		result.GivenNames = strings.ReplaceAll(p.cleanFiller(names[1]), "<", " ")
	}
}

// cleanFiller removes < fillers from a string
func (p *MRZParser) cleanFiller(s string) string {
	s = strings.ReplaceAll(s, "<", " ")
	s = strings.TrimSpace(s)
	// Collapse multiple spaces
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	return s
}

// validateCheckDigit validates an MRZ check digit
func (p *MRZParser) validateCheckDigit(data string, checkDigit int) bool {
	// ICAO 9303 check digit algorithm
	weights := []int{7, 3, 1}
	sum := 0
	
	for i, r := range strings.ToUpper(data) {
		weight := weights[i%3]
		value, ok := p.charWeights[r]
		if !ok {
			return false
		}
		sum += value * weight
	}
	
	calculated := sum % 10
	return calculated == checkDigit
}

// calculateValidationScore calculates overall validation score
func (p *MRZParser) calculateValidationScore(result *ParsedMRZ) {
	score := 0.0
	totalChecks := 0
	passedChecks := 0
	
	for _, passed := range result.CheckDigitResults {
		totalChecks++
		if passed {
			passedChecks++
		}
	}
	
	if totalChecks > 0 {
		score += float64(passedChecks) / float64(totalChecks) * 40 // Up to 40 points for check digits
	}
	
	// Points for having data
	if result.Surname != "" {
		score += 10
	}
	if result.GivenNames != "" {
		score += 10
	}
	if result.DocumentNumber != "" {
		score += 10
	}
	if result.DateOfBirth != "" && p.isValidDate(result.DateOfBirth) {
		score += 10
	}
	if result.ExpiryDate != "" && p.isValidDate(result.ExpiryDate) {
		score += 10
	}
	if result.Nationality != "" && len(result.Nationality) == 3 {
		score += 5
	}
	if result.Sex == "M" || result.Sex == "F" || result.Sex == "<" {
		score += 5
	}
	
	result.ValidationScore = score
	result.IsValid = score >= 50 && passedChecks > 0
}

// isValidDate checks if a date string (YYMMDD) is valid
func (p *MRZParser) isValidDate(date string) bool {
	if len(date) != 6 {
		return false
	}
	
	for _, r := range date {
		if r < '0' || r > '9' {
			return false
		}
	}
	
	month := (int(date[2]-'0') * 10) + int(date[3]-'0')
	day := (int(date[4]-'0') * 10) + int(date[5]-'0')
	
	return month >= 1 && month <= 12 && day >= 1 && day <= 31
}

// DetectMRZInText attempts to find and parse MRZ in text
func DetectMRZInText(text string) *ParsedMRZ {
	parser := NewMRZParser()
	return parser.ParseMRZ(text)
}

// MRZPatternMatcher provides regex-based MRZ detection
type MRZPatternMatcher struct {
	patterns []*regexp.Regexp
}

// NewMRZPatternMatcher creates a new pattern matcher
func NewMRZPatternMatcher() *MRZPatternMatcher {
	patterns := []string{
		// TD3 Line 1 (Passport)
		`P[A-Z<][A-Z<]{3}[A-Z<]{39}`,
		
		// TD3 Line 2
		`[A-Z0-9<]{9}[0-9][A-Z<]{3}[0-9]{7}[MF<][0-9]{7}[A-Z0-9<]{14}[0-9]`,
		
		// TD1 Line 1
		`[IACT][A-Z<][A-Z<]{3}[A-Z0-9<]{25}`,
		
		// TD1 Line 2
		`[0-9]{7}[MF<][0-9]{7}[A-Z<]{3}[A-Z0-9<]{11}[0-9]`,
		
		// Generic MRZ line (high confidence)
		`[A-Z0-9<]{30,44}`,
	}
	
	compiled := make([]*regexp.Regexp, 0)
	for _, p := range patterns {
		if r, err := regexp.Compile(p); err == nil {
			compiled = append(compiled, r)
		}
	}
	
	return &MRZPatternMatcher{patterns: compiled}
}

// FindMRZ finds MRZ patterns in text
func (m *MRZPatternMatcher) FindMRZ(text string) []string {
	var found []string
	seenLines := make(map[string]bool)
	
	// Clean text
	text = strings.ToUpper(text)
	
	for _, pattern := range m.patterns {
		matches := pattern.FindAllString(text, -1)
		for _, match := range matches {
			// Only add if it looks like real MRZ
			if m.looksLikeMRZ(match) && !seenLines[match] {
				found = append(found, match)
				seenLines[match] = true
			}
		}
	}
	
	return found
}

// looksLikeMRZ validates that a string looks like real MRZ
func (m *MRZPatternMatcher) looksLikeMRZ(s string) bool {
	if len(s) < 28 {
		return false
	}
	
	// Count valid characters
	validCount := 0
	fillerCount := 0
	digitCount := 0
	letterCount := 0
	
	for _, r := range s {
		if r >= 'A' && r <= 'Z' {
			validCount++
			letterCount++
		} else if r >= '0' && r <= '9' {
			validCount++
			digitCount++
		} else if r == '<' {
			validCount++
			fillerCount++
		}
	}
	
	ratio := float64(validCount) / float64(len(s))
	
	// Must be mostly valid chars
	if ratio < 0.95 {
		return false
	}
	
	// Must have mix of letters and digits (or fillers)
	if letterCount == 0 || (digitCount == 0 && fillerCount == 0) {
		return false
	}
	
	// First char should be type indicator for real MRZ
	firstChar := s[0]
	validFirstChars := "PIACV" // Passport, ID, Admin, Consular, Visa
	if strings.ContainsRune(validFirstChars, rune(firstChar)) {
		return true
	}
	
	// Or it's a second/third line (starts with digit or letter)
	return unicode.IsDigit(rune(firstChar)) || unicode.IsUpper(rune(firstChar))
}

