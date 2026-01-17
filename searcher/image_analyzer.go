package searcher

import (
	"bytes"
	"image"
	"image/draw"
	_ "image/gif"
	"image/jpeg"
	_ "image/png"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

// ImageAnalyzer performs multi-signal document detection in images
type ImageAnalyzer struct {
	ocrEnabled    bool
	tessClient    TessClient // Interface for Tesseract
	mrzPatterns   []*regexp.Regexp
	keywordScores map[string]int
	docTypeScores map[string]int
}

// TessClient interface for Tesseract operations (allows mocking)
type TessClient interface {
	SetImage(path string) error
	Text() (string, error)
	Close() error
}

// ImageAnalysisResult contains all detection signals and final score
type ImageAnalysisResult struct {
	FilePath     string  `json:"file_path"`
	FinalScore   float64 `json:"final_score"`   // 0-100
	Confidence   string  `json:"confidence"`    // "Высокая", "Средняя", "Низкая"
	DocumentType string  `json:"document_type"` // Detected document type
	IsDocument   bool    `json:"is_document"`   // Score > threshold

	// Individual signal scores
	Signals *DetectionSignals `json:"signals"`

	// Extracted data
	ExtractedText string   `json:"extracted_text,omitempty"`
	MRZData       *MRZData `json:"mrz_data,omitempty"`
	Keywords      []string `json:"keywords,omitempty"`

	// Metadata
	ImageWidth  int     `json:"image_width"`
	ImageHeight int     `json:"image_height"`
	AspectRatio float64 `json:"aspect_ratio"`
}

// DetectionSignals contains individual signal scores
type DetectionSignals struct {
	// MRZ detection (0-70 points)
	MRZScore    float64 `json:"mrz_score"`
	MRZValid    bool    `json:"mrz_valid"`
	MRZChecksum bool    `json:"mrz_checksum"`

	// Keyword detection (0-30 points)
	KeywordScore  float64 `json:"keyword_score"`
	KeywordsFound int     `json:"keywords_found"`

	// Barcode detection (0-20 points)
	BarcodeScore float64 `json:"barcode_score"`
	BarcodeType  string  `json:"barcode_type,omitempty"`

	// Face detection (0-15 points)
	FaceScore            float64 `json:"face_score"`
	FaceDetected         bool    `json:"face_detected"`
	FaceInExpectedRegion bool    `json:"face_in_expected_region"`

	// Document geometry (0-15 points)
	GeometryScore     float64 `json:"geometry_score"`
	AspectRatioMatch  bool    `json:"aspect_ratio_match"`
	RectangleDetected bool    `json:"rectangle_detected"`
	IsPassportPhoto   bool    `json:"is_passport_photo"` // True if just a photo, not a document

	// Rotation detection
	Rotation int `json:"rotation,omitempty"` // 0, 90, 180, or 270 degrees

	// Text structure (0-20 points)
	StructureScore float64 `json:"structure_score"`
	HasDatePattern bool    `json:"has_date_pattern"`
	HasNamePattern bool    `json:"has_name_pattern"`

	// Image quality (0-10 points)
	QualityScore float64 `json:"quality_score"`
	Resolution   string  `json:"resolution"` // "low", "medium", "high"
}

// MRZData contains parsed MRZ information
type MRZData struct {
	Type           string   `json:"type"` // P, ID, V, etc.
	Country        string   `json:"country"`
	Surname        string   `json:"surname"`
	GivenNames     string   `json:"given_names"`
	DocumentNumber string   `json:"document_number"`
	Nationality    string   `json:"nationality"`
	DateOfBirth    string   `json:"date_of_birth"`
	Sex            string   `json:"sex"`
	ExpiryDate     string   `json:"expiry_date"`
	PersonalNumber string   `json:"personal_number,omitempty"`
	RawLines       []string `json:"raw_lines"`
	IsValid        bool     `json:"is_valid"`
}

// Signal weights for final score calculation
var signalWeights = map[string]float64{
	"mrz":       0.35, // MRZ is strongest signal
	"keywords":  0.20,
	"barcode":   0.12,
	"face":      0.10,
	"geometry":  0.08,
	"structure": 0.10,
	"quality":   0.05,
}

// Document aspect ratios (width/height) - ordered by priority
// Using slice for ordered matching
type docRatio struct {
	docType string
	ratio   float64
}

var documentAspectRatiosList = []docRatio{
	{"passport_page", 0.70},   // Passport page (portrait)
	{"passport_closed", 1.42}, // Closed/spread passport
	{"passport_card", 1.37},   // Passport card format
	{"id_card", 1.58},         // ID-1 format (credit card size)
	{"a4_portrait", 0.71},     // A4 portrait (lower priority than passport_page)
}

// Legacy map for compatibility
var documentAspectRatios = map[string]float64{
	"passport_page":   0.70,
	"id_card":         1.58,
	"passport_closed": 1.42,
	"a4_portrait":     0.71,
	"passport_card":   1.37,
}

// Aspect ratios for photos (NOT documents - should be excluded)
var photoAspectRatios = map[string]float64{
	"passport_photo_35x45": 0.78, // 35x45mm passport photo (just face)
	"passport_photo_30x40": 0.75, // 30x40mm photo
	"photo_3x4":            0.75, // 3x4 cm photo
}

// NewImageAnalyzer creates a new image analyzer
func NewImageAnalyzer(ocrEnabled bool) *ImageAnalyzer {
	ia := &ImageAnalyzer{
		ocrEnabled:    ocrEnabled,
		mrzPatterns:   compileMRZPatterns(),
		keywordScores: initKeywordScores(),
		docTypeScores: initDocTypeScores(),
	}
	return ia
}

// compileMRZPatterns compiles regex patterns for MRZ detection
func compileMRZPatterns() []*regexp.Regexp {
	patterns := []string{
		// TD1 (ID cards, 3 lines of 30 chars)
		`[A-Z][A-Z<][A-Z<]{3}[A-Z0-9<]{25}`,
		`[0-9]{6}[0-9<][MFX<][0-9]{6}[0-9<][A-Z<]{3}[A-Z0-9<]{11}[0-9<]`,

		// TD2 (2 lines of 36 chars)
		`[A-Z][A-Z<][A-Z<]{3}[A-Z<]{31}`,

		// TD3/Passport (2 lines of 44 chars)
		`P[A-Z<][A-Z<]{3}[A-Z<]{39}`,
		`[A-Z0-9<]{9}[0-9][A-Z<]{3}[0-9]{6}[0-9][MFX<][0-9]{6}[0-9][A-Z0-9<]{14}[0-9<][0-9]`,

		// Generic MRZ line patterns
		`[A-Z<]{2}[A-Z<]{3}[A-Z<]{30,42}`,
		`[A-Z0-9<]{30,44}`,
	}

	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		if r, err := regexp.Compile(p); err == nil {
			compiled = append(compiled, r)
		}
	}
	return compiled
}

// initKeywordScores initializes keyword detection weights
func initKeywordScores() map[string]int {
	return map[string]int{
		// High confidence keywords
		"passport": 15, "паспорт": 15, "reisepass": 15, "passeport": 15,
		"mrz": 20, "machine readable": 15,

		// Medium confidence
		"surname": 10, "фамилия": 10, "nom": 10, "nachname": 10,
		"given name": 10, "имя": 10, "prénom": 10, "vorname": 10,
		"nationality": 10, "гражданство": 10, "nationalité": 10,
		"date of birth": 10, "дата рождения": 10, "geburtsdatum": 10,
		"sex": 5, "пол": 5, "geschlecht": 5,
		"place of birth": 8, "место рождения": 8,
		"date of issue": 8, "дата выдачи": 8,
		"date of expiry": 8, "срок действия": 8, "valid until": 8,
		"authority": 6, "орган выдачи": 6,
		"signature": 6, "подпись": 6,

		// Document types
		"driver": 12, "водительское": 12, "führerschein": 12, "permis": 12,
		"license": 10, "удостоверение": 10, "licen": 10,
		"identity card": 12, "удостоверение личности": 12,
		"id card": 12, "id-karte": 12, "carte d'identité": 12,
		"visa": 12, "виза": 12,
		"residence permit": 12, "вид на жительство": 12,
		"work permit": 10, "разрешение на работу": 10,

		// Russian specific
		"код подразделения": 10, "снилс": 15, "инн": 12,
		"серия": 8, "номер": 6,

		// Partial keywords (for garbled OCR output)
		"passpo": 10, "passp": 8, "aspor": 8,
		"surnam": 8, "urnam": 6,
		"birth": 8, "irth": 5,
		"expir": 8, "xpir": 5,
		"nation": 8, "ation": 5,
		"given": 8, "iven": 5,
		"russia": 10, "ussia": 8, "росси": 10,
		"holder": 8, "older": 5,
		"issuing": 8, "ssuing": 5,

		// Common OCR misreads
		"pass0rt": 10, "passp0rt": 10, "passpcrt": 10,
		"b1rth": 6, "d0b": 6,
		"кем выдан": 8, "действителен": 6,

		// Personal data indicators
		"personal": 5, "персональные": 5,
		"confidential": 5, "конфиденциально": 5,
		"photo": 4, "фото": 4,
	}
}

// initDocTypeScores initializes document type detection
func initDocTypeScores() map[string]int {
	return map[string]int{
		"passport":       100,
		"id_card":        95,
		"driver_license": 90,
		"visa":           85,
		"residence":      80,
		"work_permit":    75,
		"snils":          70,
		"inn":            70,
	}
}

// AnalyzeImage performs full multi-signal analysis of an image
// It tries multiple rotations (0°, 90°, 180°, 270°) and returns the best result
func (ia *ImageAnalyzer) AnalyzeImage(imagePath string) (*ImageAnalysisResult, error) {
	// First, try with original orientation
	result, err := ia.analyzeImageAtRotation(imagePath, 0)
	if err != nil {
		return nil, err
	}

	// If score is high enough, return immediately (no need to try rotations)
	if result.FinalScore >= 50 {
		return result, nil
	}

	// Try other rotations (90°, 180°, 270°) to find rotated documents
	rotations := []int{90, 180, 270}
	bestResult := result
	bestScore := result.FinalScore

	for _, rotation := range rotations {
		rotatedResult, err := ia.analyzeImageAtRotation(imagePath, rotation)
		if err != nil {
			continue // Skip failed rotations
		}

		if rotatedResult.FinalScore > bestScore {
			bestScore = rotatedResult.FinalScore
			bestResult = rotatedResult
			bestResult.Signals.Rotation = rotation
		}

		// If we found a high confidence match, stop trying
		if bestScore >= 70 {
			break
		}
	}

	return bestResult, nil
}

// analyzeImageAtRotation analyzes an image at a specific rotation
func (ia *ImageAnalyzer) analyzeImageAtRotation(imagePath string, rotation int) (*ImageAnalysisResult, error) {
	result := &ImageAnalysisResult{
		FilePath: imagePath,
		Signals:  &DetectionSignals{},
	}

	// Load image
	file, err := os.Open(imagePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	img, _, err := image.Decode(file)
	if err != nil {
		result.Signals.QualityScore = 0
	} else {
		// Apply rotation if needed
		if rotation != 0 {
			img = rotateImage(img, rotation)
		}

		bounds := img.Bounds()
		result.ImageWidth = bounds.Dx()
		result.ImageHeight = bounds.Dy()
		if result.ImageHeight > 0 {
			result.AspectRatio = float64(result.ImageWidth) / float64(result.ImageHeight)
		}

		// Analyze image quality
		ia.analyzeImageQuality(result, img)

		// Analyze geometry (aspect ratio matching)
		ia.analyzeGeometry(result)
	}

	// OCR analysis (if enabled)
	if ia.ocrEnabled {
		// For rotated images, we need to save a temp file and run OCR on it
		if rotation != 0 && img != nil {
			tempPath, err := ia.saveRotatedImage(img, imagePath, rotation)
			if err == nil {
				ia.performOCRAnalysis(result, tempPath)
				os.Remove(tempPath) // Clean up temp file
			}
		} else {
			ia.performOCRAnalysis(result, imagePath)
		}
	}

	// Calculate final score
	ia.calculateFinalScore(result)

	return result, nil
}

// rotateImage rotates an image by the specified degrees (90, 180, 270)
func rotateImage(img image.Image, degrees int) image.Image {
	bounds := img.Bounds()
	w, h := bounds.Dx(), bounds.Dy()

	switch degrees {
	case 90:
		// 90° clockwise: new dimensions are (h, w)
		// Pixel at (x, y) in original goes to (h-1-y, x) in rotated
		rotated := image.NewRGBA(image.Rect(0, 0, h, w))
		// Iterate over original image coordinates
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				// Rotated image coordinates: (h-1-y, x)
				// X coordinate: h-1-y (range: 0 to h-1) ✓
				// Y coordinate: x (range: 0 to w-1) ✓
				rotated.Set(h-1-y, x, img.At(x+bounds.Min.X, y+bounds.Min.Y))
			}
		}
		return rotated

	case 180:
		// 180°: same dimensions
		rotated := image.NewRGBA(image.Rect(0, 0, w, h))
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				rotated.Set(w-1-x, h-1-y, img.At(x+bounds.Min.X, y+bounds.Min.Y))
			}
		}
		return rotated

	case 270:
		// 270° clockwise (= 90° counter-clockwise): new dimensions are (h, w)
		// Pixel at (x, y) in original goes to (y, w-1-x) in rotated
		rotated := image.NewRGBA(image.Rect(0, 0, h, w))
		// Iterate over original image dimensions
		for y := 0; y < h; y++ {
			for x := 0; x < w; x++ {
				// Map to rotated coordinates: (y, w-1-x)
				// rotated.Set(x_coord, y_coord, color)
				// x_coord = y (range: 0 to h-1) ✓
				// y_coord = w-1-x (range: w-1 down to 0, i.e., [0, w-1]) ✓
				rotated.Set(y, w-1-x, img.At(x+bounds.Min.X, y+bounds.Min.Y))
			}
		}
		return rotated

	default:
		return img
	}
}

// saveRotatedImage saves a rotated image to a temp file for OCR
func (ia *ImageAnalyzer) saveRotatedImage(img image.Image, originalPath string, rotation int) (string, error) {
	// Create temp file
	ext := filepath.Ext(originalPath)
	tempFile, err := os.CreateTemp("", "rotated_*"+ext)
	if err != nil {
		return "", err
	}
	defer tempFile.Close()

	// Convert to RGBA if needed
	rgba, ok := img.(*image.RGBA)
	if !ok {
		bounds := img.Bounds()
		rgba = image.NewRGBA(bounds)
		draw.Draw(rgba, bounds, img, bounds.Min, draw.Src)
	}

	// Encode as JPEG (works with Tesseract)
	err = jpeg.Encode(tempFile, rgba, &jpeg.Options{Quality: 95})
	if err != nil {
		os.Remove(tempFile.Name())
		return "", err
	}

	return tempFile.Name(), nil
}

// analyzeImageQuality analyzes image quality signals
func (ia *ImageAnalyzer) analyzeImageQuality(result *ImageAnalysisResult, img image.Image) {
	bounds := img.Bounds()
	pixels := bounds.Dx() * bounds.Dy()

	// Resolution score
	if pixels > 2000000 { // > 2 MP
		result.Signals.QualityScore = 10
		result.Signals.Resolution = "high"
	} else if pixels > 500000 { // > 0.5 MP
		result.Signals.QualityScore = 7
		result.Signals.Resolution = "medium"
	} else {
		result.Signals.QualityScore = 3
		result.Signals.Resolution = "low"
	}
}

// analyzeGeometry analyzes document geometry
func (ia *ImageAnalyzer) analyzeGeometry(result *ImageAnalysisResult) {
	ratio := result.AspectRatio
	pixels := result.ImageWidth * result.ImageHeight

	// Check if it's a small passport photo (35x45mm format)
	// Passport photos are typically small images (< 500K pixels)
	// and have specific aspect ratio around 0.77-0.78
	isSmallImage := pixels < 500000 // Less than 500K pixels
	for _, photoRatio := range photoAspectRatios {
		tolerance := 0.05 // Tight tolerance for passport photos
		if math.Abs(ratio-photoRatio) < tolerance && isSmallImage {
			// This is likely just a passport photo, not a document
			result.DocumentType = "passport_photo"
			result.Signals.GeometryScore = 0
			result.Signals.IsPassportPhoto = true
			return
		}
	}

	// Check if aspect ratio matches known document types (in priority order)
	for _, docRatio := range documentAspectRatiosList {
		// Also check inverted ratio (rotated image)
		tolerance := 0.08 // Tight tolerance for specific match
		if math.Abs(ratio-docRatio.ratio) < tolerance ||
			math.Abs((1/ratio)-docRatio.ratio) < tolerance {
			result.Signals.AspectRatioMatch = true
			result.Signals.GeometryScore = 12
			result.DocumentType = docRatio.docType
			return
		}
	}

	// Partial match - reduced score
	if result.DocumentType == "" {
		for _, docRatio := range documentAspectRatiosList {
			tolerance := 0.15
			if math.Abs(ratio-docRatio.ratio) < tolerance ||
				math.Abs((1/ratio)-docRatio.ratio) < tolerance {
				result.Signals.GeometryScore = 5
				result.DocumentType = docRatio.docType
				return
			}
		}
	}
}

// performOCRAnalysis performs OCR and text-based analysis
func (ia *ImageAnalyzer) performOCRAnalysis(result *ImageAnalysisResult, imagePath string) {
	// Try to use gosseract if available
	text, err := ia.extractTextFromImage(imagePath)
	if err != nil {
		return
	}

	result.ExtractedText = text
	textLower := strings.ToLower(text)

	// MRZ detection
	ia.detectMRZ(result, text)

	// Keyword detection
	ia.detectKeywords(result, textLower)

	// Date pattern detection
	ia.detectDatePatterns(result, text)

	// Name pattern detection
	ia.detectNamePatterns(result, text)

	// Barcode/code pattern detection
	ia.detectCodePatterns(result, text)
}

// extractTextFromImage uses gosseract to extract text
func (ia *ImageAnalyzer) extractTextFromImage(imagePath string) (string, error) {
	// Try to use gosseract if available
	if ia.tessClient != nil {
		if err := ia.tessClient.SetImage(imagePath); err != nil {
			return "", err
		}
		return ia.tessClient.Text()
	}

	// Fallback: try to load gosseract dynamically
	// This will be replaced with actual gosseract calls when the library is available
	return ia.fallbackOCR(imagePath)
}

// fallbackOCR provides basic text extraction without full OCR
func (ia *ImageAnalyzer) fallbackOCR(imagePath string) (string, error) {
	// Read file content and look for embedded text (PDFs, etc.)
	content, err := os.ReadFile(imagePath)
	if err != nil {
		return "", err
	}

	// Extract any readable ASCII text from the file
	var textBuilder bytes.Buffer
	for _, b := range content {
		if b >= 32 && b <= 126 {
			textBuilder.WriteByte(b)
		} else if b == '\n' || b == '\r' || b == '\t' {
			textBuilder.WriteByte(' ')
		}
	}

	return textBuilder.String(), nil
}

// detectMRZ detects and parses MRZ (Machine Readable Zone)
func (ia *ImageAnalyzer) detectMRZ(result *ImageAnalysisResult, text string) {
	// Clean text and look for MRZ patterns
	lines := strings.Split(text, "\n")
	var mrzLines []string

	for _, line := range lines {
		// Clean line
		line = strings.TrimSpace(line)
		line = strings.ToUpper(line)

		// Replace common OCR errors
		line = strings.ReplaceAll(line, "O", "0") // OCR often confuses O and 0
		line = strings.ReplaceAll(line, " ", "")  // Remove spaces

		// Check if line looks like MRZ (mostly uppercase letters, numbers, and <)
		if ia.looksLikeMRZ(line) {
			mrzLines = append(mrzLines, line)
		}
	}

	// Try to find valid MRZ patterns
	for _, pattern := range ia.mrzPatterns {
		for _, line := range mrzLines {
			if pattern.MatchString(line) {
				result.Signals.MRZScore = 60
				result.Signals.MRZValid = true

				// Parse MRZ data
				mrzData := ia.parseMRZ(mrzLines)
				if mrzData != nil && mrzData.IsValid {
					result.MRZData = mrzData
					result.Signals.MRZScore = 70
					result.Signals.MRZChecksum = true
					result.DocumentType = "passport"
				}
				return
			}
		}
	}

	// Partial MRZ detection
	if len(mrzLines) > 0 {
		result.Signals.MRZScore = 30
	}
}

// looksLikeMRZ checks if a line resembles MRZ format
func (ia *ImageAnalyzer) looksLikeMRZ(line string) bool {
	if len(line) < 20 {
		return false
	}

	validChars := 0
	for _, r := range line {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '<' {
			validChars++
		}
	}

	ratio := float64(validChars) / float64(len(line))
	return ratio > 0.85
}

// parseMRZ parses MRZ lines into structured data
func (ia *ImageAnalyzer) parseMRZ(lines []string) *MRZData {
	if len(lines) < 2 {
		return nil
	}

	mrz := &MRZData{
		RawLines: lines,
	}

	// Try to parse based on first character (document type)
	firstLine := lines[0]
	if len(firstLine) < 2 {
		return nil
	}

	mrz.Type = string(firstLine[0])

	switch mrz.Type {
	case "P": // Passport TD3
		if len(lines) >= 2 && len(firstLine) >= 44 && len(lines[1]) >= 44 {
			mrz.Country = strings.ReplaceAll(firstLine[2:5], "<", "")

			// Parse names
			namePart := firstLine[5:44]
			names := strings.SplitN(namePart, "<<", 2)
			if len(names) >= 1 {
				mrz.Surname = strings.ReplaceAll(names[0], "<", " ")
				mrz.Surname = strings.TrimSpace(mrz.Surname)
			}
			if len(names) >= 2 {
				mrz.GivenNames = strings.ReplaceAll(names[1], "<", " ")
				mrz.GivenNames = strings.TrimSpace(mrz.GivenNames)
			}

			// Parse second line
			line2 := lines[1]
			mrz.DocumentNumber = strings.ReplaceAll(line2[0:9], "<", "")
			mrz.Nationality = strings.ReplaceAll(line2[10:13], "<", "")
			mrz.DateOfBirth = line2[13:19]
			mrz.Sex = string(line2[20])
			mrz.ExpiryDate = line2[21:27]

			// Validate checksum (simplified)
			mrz.IsValid = ia.validateMRZChecksum(line2)
		}

	case "I", "A", "C": // ID cards TD1/TD2
		if len(lines) >= 2 {
			mrz.Country = strings.ReplaceAll(firstLine[2:5], "<", "")
			mrz.IsValid = true
		}
	}

	return mrz
}

// validateMRZChecksum validates MRZ check digits
func (ia *ImageAnalyzer) validateMRZChecksum(line string) bool {
	// Simplified validation - check if check digits are present
	if len(line) < 44 {
		return false
	}

	// Check digit positions in TD3 line 2: 9, 13, 19, 27, 43
	checkPositions := []int{9, 13, 19, 27, 43}
	validDigits := 0

	for _, pos := range checkPositions {
		if pos < len(line) {
			c := line[pos]
			if (c >= '0' && c <= '9') || c == '<' {
				validDigits++
			}
		}
	}

	return validDigits >= 3
}

// detectKeywords detects document-related keywords
func (ia *ImageAnalyzer) detectKeywords(result *ImageAnalysisResult, textLower string) {
	totalScore := 0
	foundKeywords := []string{}

	for keyword, score := range ia.keywordScores {
		if strings.Contains(textLower, strings.ToLower(keyword)) {
			totalScore += score
			foundKeywords = append(foundKeywords, keyword)
		}
	}

	result.Keywords = foundKeywords
	result.Signals.KeywordsFound = len(foundKeywords)

	// Cap at 30 points
	if totalScore > 30 {
		totalScore = 30
	}
	result.Signals.KeywordScore = float64(totalScore)

	// Try to determine document type from keywords
	if result.DocumentType == "" {
		if strings.Contains(textLower, "passport") || strings.Contains(textLower, "паспорт") {
			result.DocumentType = "passport"
		} else if strings.Contains(textLower, "driver") || strings.Contains(textLower, "водительское") {
			result.DocumentType = "driver_license"
		} else if strings.Contains(textLower, "снилс") {
			result.DocumentType = "snils"
		} else if strings.Contains(textLower, "инн") {
			result.DocumentType = "inn"
		} else if strings.Contains(textLower, "id") || strings.Contains(textLower, "identity") {
			result.DocumentType = "id_card"
		}
	}
}

// detectDatePatterns detects date patterns in text
func (ia *ImageAnalyzer) detectDatePatterns(result *ImageAnalysisResult, text string) {
	datePatterns := []string{
		`\d{2}[./\-]\d{2}[./\-]\d{4}`, // DD.MM.YYYY, DD/MM/YYYY
		`\d{4}[./\-]\d{2}[./\-]\d{2}`, // YYYY-MM-DD
		`\d{2}\s+\w+\s+\d{4}`,         // DD Month YYYY
		`\d{6}`,                       // YYMMDD (MRZ format)
	}

	for _, pattern := range datePatterns {
		if r, err := regexp.Compile(pattern); err == nil {
			if matches := r.FindAllString(text, -1); len(matches) >= 2 {
				result.Signals.HasDatePattern = true
				result.Signals.StructureScore += 10
				return
			}
		}
	}
}

// detectNamePatterns detects name patterns in text
func (ia *ImageAnalyzer) detectNamePatterns(result *ImageAnalysisResult, text string) {
	// Look for patterns like "SURNAME<<GIVEN<NAME"
	mrzNamePattern := regexp.MustCompile(`[A-Z]+<<[A-Z<]+`)
	if mrzNamePattern.MatchString(text) {
		result.Signals.HasNamePattern = true
		result.Signals.StructureScore += 10
		return
	}

	// Look for "Фамилия: XXXX" or "Surname: XXXX" patterns
	labeledNamePatterns := []string{
		`(?i)(surname|фамилия|nom|nachname)\s*[:\-]?\s*[A-ZА-Яa-zа-я]+`,
		`(?i)(given name|имя|prénom|vorname)\s*[:\-]?\s*[A-ZА-Яa-zа-я]+`,
	}

	for _, pattern := range labeledNamePatterns {
		if r, err := regexp.Compile(pattern); err == nil {
			if r.MatchString(text) {
				result.Signals.HasNamePattern = true
				result.Signals.StructureScore += 5
			}
		}
	}
}

// detectCodePatterns detects barcode/QR patterns in text
func (ia *ImageAnalyzer) detectCodePatterns(result *ImageAnalysisResult, text string) {
	// PDF417 often contains structured data
	if strings.Contains(text, "ANSI ") || strings.Contains(text, "AAMVA") {
		result.Signals.BarcodeScore = 20
		result.Signals.BarcodeType = "PDF417"
		return
	}

	// Look for long alphanumeric sequences (potential barcode data)
	longAlphaNum := regexp.MustCompile(`[A-Z0-9]{20,}`)
	if matches := longAlphaNum.FindAllString(strings.ToUpper(text), -1); len(matches) > 0 {
		result.Signals.BarcodeScore = 10
		result.Signals.BarcodeType = "possible_barcode"
	}
}

// calculateFinalScore calculates the weighted final score
func (ia *ImageAnalyzer) calculateFinalScore(result *ImageAnalysisResult) {
	signals := result.Signals

	// If this is just a passport photo (face only), not a document
	if signals.IsPassportPhoto {
		result.FinalScore = 0
		result.Confidence = "Нет"
		result.IsDocument = false
		result.DocumentType = "passport_photo"
		return
	}

	// Normalize each signal to 0-100 scale
	mrzNorm := (signals.MRZScore / 70) * 100
	keywordNorm := (signals.KeywordScore / 30) * 100
	barcodeNorm := (signals.BarcodeScore / 20) * 100
	faceNorm := (signals.FaceScore / 15) * 100
	geometryNorm := (signals.GeometryScore / 15) * 100
	structureNorm := (signals.StructureScore / 20) * 100
	qualityNorm := (signals.QualityScore / 10) * 100

	// If MRZ not found, redistribute weights to other signals
	weights := make(map[string]float64)
	for k, v := range signalWeights {
		weights[k] = v
	}

	// Adjust weights when MRZ is absent but other strong signals present
	if signals.MRZScore == 0 {
		// Redistribute MRZ weight to keywords, geometry, and structure
		weights["keywords"] += 0.15  // More weight on keywords
		weights["geometry"] += 0.10  // More weight on document shape
		weights["structure"] += 0.10 // More weight on text structure
		weights["mrz"] = 0
	}

	// Calculate weighted score
	result.FinalScore = mrzNorm*weights["mrz"] +
		keywordNorm*weights["keywords"] +
		barcodeNorm*weights["barcode"] +
		faceNorm*weights["face"] +
		geometryNorm*weights["geometry"] +
		structureNorm*weights["structure"] +
		qualityNorm*weights["quality"]

	// Require multiple signals for document detection (not just geometry)
	// Must have keywords or MRZ or structure to be considered a document
	hasTextSignals := signals.KeywordScore > 10 || signals.MRZScore > 0 || signals.StructureScore > 10

	// Determine confidence level
	if result.FinalScore >= 65 && hasTextSignals {
		result.Confidence = "Высокая"
		result.IsDocument = true
	} else if result.FinalScore >= 40 && hasTextSignals {
		result.Confidence = "Средняя"
		result.IsDocument = true
	} else if result.FinalScore >= 25 {
		result.Confidence = "Низкая"
		result.IsDocument = false
	} else {
		result.Confidence = "Нет"
		result.IsDocument = false
	}

	// Determine document type description
	if result.DocumentType == "" && result.IsDocument {
		result.DocumentType = "unknown_document"
	}
}

// SetTessClient sets the Tesseract client
func (ia *ImageAnalyzer) SetTessClient(client TessClient) {
	ia.tessClient = client
}

// GetDocumentTypeDescription returns Russian description of document type
func (ia *ImageAnalyzer) GetDocumentTypeDescription(docType string) string {
	descriptions := map[string]string{
		"passport":         "Паспорт",
		"passport_page":    "Паспорт",
		"passport_closed":  "Паспорт",
		"passport_card":    "Паспорт",
		"passport_photo":   "Фото на документы", // Not a document!
		"id_card":          "Удостоверение личности",
		"driver_license":   "Водительское удостоверение",
		"visa":             "Виза",
		"residence":        "Вид на жительство",
		"work_permit":      "Разрешение на работу",
		"snils":            "СНИЛС",
		"inn":              "ИНН",
		"a4_portrait":      "Документ",
		"unknown_document": "Документ",
	}

	if desc, ok := descriptions[docType]; ok {
		return desc
	}
	return "Документ"
}

// ContainsUppercaseWords checks if text has significant uppercase words
func ContainsUppercaseWords(text string) bool {
	words := strings.Fields(text)
	uppercaseCount := 0

	for _, word := range words {
		if len(word) > 2 {
			allUpper := true
			for _, r := range word {
				if !unicode.IsUpper(r) && unicode.IsLetter(r) {
					allUpper = false
					break
				}
			}
			if allUpper {
				uppercaseCount++
			}
		}
	}

	return uppercaseCount >= 3
}
