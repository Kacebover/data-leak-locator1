package searcher

import (
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"regexp"
	"strings"
)

// DocumentDetector detects identity documents in images and text
type DocumentDetector struct {
	patterns map[string]*regexp.Regexp
}

// DocumentType represents the type of detected document
type DocumentType string

const (
	DocTypePassport      DocumentType = "passport"
	DocTypeDriverLicense DocumentType = "driver_license"
	DocTypeIDCard        DocumentType = "id_card"
	DocTypeCreditCard    DocumentType = "credit_card"
	DocTypeBankStatement DocumentType = "bank_statement"
	DocTypeTaxDocument   DocumentType = "tax_document"
	DocTypeMedicalRecord DocumentType = "medical_record"
	DocTypeUnknown       DocumentType = "unknown"
)

// DetectedDocument represents a detected identity document
type DetectedDocument struct {
	Type        DocumentType `json:"type"`
	TypeRu      string       `json:"type_ru"`
	Confidence  float64      `json:"confidence"`
	FilePath    string       `json:"file_path"`
	Indicators  []string     `json:"indicators"`
	RiskLevel   string       `json:"risk_level"`
	Description string       `json:"description"`
}

// NewDocumentDetector creates a new document detector
func NewDocumentDetector() *DocumentDetector {
	dd := &DocumentDetector{
		patterns: make(map[string]*regexp.Regexp),
	}
	dd.initPatterns()
	return dd
}

// initPatterns initializes detection patterns
func (dd *DocumentDetector) initPatterns() {
	// Russian passport patterns
	dd.patterns["ru_passport_series"] = regexp.MustCompile(`\b\d{2}\s?\d{2}\s?\d{6}\b`)
	dd.patterns["ru_passport_text"] = regexp.MustCompile(`(?i)(паспорт|passport|серия|номер паспорта|выдан|код подразделения|место рождения|дата рождения)`)

	// International passport
	dd.patterns["int_passport"] = regexp.MustCompile(`(?i)(passport|passeport|reisepass|pasaporte)`)
	dd.patterns["mrz"] = regexp.MustCompile(`[A-Z<]{2}[A-Z<]{3}[A-Z<]{39}`)

	// Driver's license
	dd.patterns["driver_license_ru"] = regexp.MustCompile(`(?i)(водительское удостоверение|права|driver.?s?.?licen[sc]e|führerschein|permis de conduire)`)
	dd.patterns["driver_license_num"] = regexp.MustCompile(`\b\d{2}\s?\d{2}\s?\d{6}\b`)

	// ID card patterns
	dd.patterns["id_card"] = regexp.MustCompile(`(?i)(удостоверение личности|identity card|id card|personalausweis|carte d'identité|снилс|инн)`)
	dd.patterns["snils"] = regexp.MustCompile(`\b\d{3}-\d{3}-\d{3}\s?\d{2}\b`)
	dd.patterns["inn_personal"] = regexp.MustCompile(`\b\d{12}\b`)
	dd.patterns["inn_company"] = regexp.MustCompile(`\b\d{10}\b`)

	// Credit card patterns
	dd.patterns["credit_card_visual"] = regexp.MustCompile(`(?i)(visa|mastercard|american express|amex|mir|мир|maestro|valid thru|cvv|cvc|exp|срок действия)`)

	// Bank documents
	dd.patterns["bank_doc"] = regexp.MustCompile(`(?i)(bank statement|выписка|счёт|account|баланс|balance|transaction|операция|перевод|transfer)`)
	dd.patterns["iban"] = regexp.MustCompile(`[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}`)
	dd.patterns["bic"] = regexp.MustCompile(`[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?`)

	// Tax documents
	dd.patterns["tax_doc"] = regexp.MustCompile(`(?i)(налоговая|tax|ндфл|2-ндфл|3-ндфл|декларация|w-2|1099|tax return|справка о доходах)`)

	// Medical records
	dd.patterns["medical"] = regexp.MustCompile(`(?i)(медицинская карта|medical record|health|диагноз|diagnosis|prescription|рецепт|анализ|полис омс|страховой полис)`)
	dd.patterns["oms"] = regexp.MustCompile(`\b\d{16}\b`)
}

// DetectInText analyzes text for identity document indicators
func (dd *DocumentDetector) DetectInText(text, filePath string) []*DetectedDocument {
	var documents []*DetectedDocument
	textLower := strings.ToLower(text)

	// Check for passport
	if doc := dd.detectPassport(text, textLower, filePath); doc != nil {
		documents = append(documents, doc)
	}

	// Check for driver's license
	if doc := dd.detectDriverLicense(text, textLower, filePath); doc != nil {
		documents = append(documents, doc)
	}

	// Check for ID card
	if doc := dd.detectIDCard(text, textLower, filePath); doc != nil {
		documents = append(documents, doc)
	}

	// Check for credit card
	if doc := dd.detectCreditCard(text, textLower, filePath); doc != nil {
		documents = append(documents, doc)
	}

	// Check for bank documents
	if doc := dd.detectBankDocument(text, textLower, filePath); doc != nil {
		documents = append(documents, doc)
	}

	// Check for tax documents
	if doc := dd.detectTaxDocument(text, textLower, filePath); doc != nil {
		documents = append(documents, doc)
	}

	// Check for medical records
	if doc := dd.detectMedicalRecord(text, textLower, filePath); doc != nil {
		documents = append(documents, doc)
	}

	return documents
}

// detectPassport checks for passport indicators
func (dd *DocumentDetector) detectPassport(text, textLower, filePath string) *DetectedDocument {
	var indicators []string
	confidence := 0.0

	// Check for passport keywords
	if dd.patterns["ru_passport_text"].MatchString(textLower) {
		indicators = append(indicators, "Найдены ключевые слова паспорта")
		confidence += 0.3
	}

	// Check for passport series/number
	if dd.patterns["ru_passport_series"].MatchString(text) {
		indicators = append(indicators, "Найден номер паспорта (формат XX XX XXXXXX)")
		confidence += 0.4
	}

	// Check for MRZ (machine readable zone)
	if dd.patterns["mrz"].MatchString(text) {
		indicators = append(indicators, "Найдена машиночитаемая зона (MRZ)")
		confidence += 0.5
	}

	// Check for international passport keywords
	if dd.patterns["int_passport"].MatchString(textLower) {
		indicators = append(indicators, "Найдены международные ключевые слова паспорта")
		confidence += 0.2
	}

	if confidence >= 0.3 {
		return &DetectedDocument{
			Type:        DocTypePassport,
			TypeRu:      "Паспорт",
			Confidence:  min(confidence, 1.0),
			FilePath:    filePath,
			Indicators:  indicators,
			RiskLevel:   "🔴 КРИТИЧЕСКИЙ",
			Description: "Обнаружены данные паспорта. Это критически важный документ!",
		}
	}
	return nil
}

// detectDriverLicense checks for driver's license indicators
func (dd *DocumentDetector) detectDriverLicense(text, textLower, filePath string) *DetectedDocument {
	var indicators []string
	confidence := 0.0

	if dd.patterns["driver_license_ru"].MatchString(textLower) {
		indicators = append(indicators, "Найдены ключевые слова водительского удостоверения")
		confidence += 0.4
	}

	if dd.patterns["driver_license_num"].MatchString(text) {
		indicators = append(indicators, "Найден номер водительского удостоверения")
		confidence += 0.3
	}

	if confidence >= 0.3 {
		return &DetectedDocument{
			Type:        DocTypeDriverLicense,
			TypeRu:      "Водительское удостоверение",
			Confidence:  min(confidence, 1.0),
			FilePath:    filePath,
			Indicators:  indicators,
			RiskLevel:   "🔴 КРИТИЧЕСКИЙ",
			Description: "Обнаружены данные водительского удостоверения.",
		}
	}
	return nil
}

// detectIDCard checks for ID card indicators
func (dd *DocumentDetector) detectIDCard(text, textLower, filePath string) *DetectedDocument {
	var indicators []string
	confidence := 0.0

	if dd.patterns["id_card"].MatchString(textLower) {
		indicators = append(indicators, "Найдены ключевые слова удостоверения личности")
		confidence += 0.3
	}

	if dd.patterns["snils"].MatchString(text) {
		indicators = append(indicators, "Найден СНИЛС (XXX-XXX-XXX XX)")
		confidence += 0.5
	}

	if dd.patterns["inn_personal"].MatchString(text) {
		indicators = append(indicators, "Найден ИНН физического лица (12 цифр)")
		confidence += 0.4
	}

	if confidence >= 0.3 {
		return &DetectedDocument{
			Type:        DocTypeIDCard,
			TypeRu:      "Удостоверение личности / СНИЛС / ИНН",
			Confidence:  min(confidence, 1.0),
			FilePath:    filePath,
			Indicators:  indicators,
			RiskLevel:   "🔴 КРИТИЧЕСКИЙ",
			Description: "Обнаружены персональные идентификаторы.",
		}
	}
	return nil
}

// detectCreditCard checks for credit card indicators
func (dd *DocumentDetector) detectCreditCard(text, textLower, filePath string) *DetectedDocument {
	var indicators []string
	confidence := 0.0

	if dd.patterns["credit_card_visual"].MatchString(textLower) {
		indicators = append(indicators, "Найдены ключевые слова банковской карты")
		confidence += 0.4
	}

	// Check for card number pattern (already in main patterns)
	cardPattern := regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`)
	if cardPattern.MatchString(text) {
		indicators = append(indicators, "Найден номер банковской карты")
		confidence += 0.5
	}

	if confidence >= 0.3 {
		return &DetectedDocument{
			Type:        DocTypeCreditCard,
			TypeRu:      "Банковская карта",
			Confidence:  min(confidence, 1.0),
			FilePath:    filePath,
			Indicators:  indicators,
			RiskLevel:   "🔴 КРИТИЧЕСКИЙ",
			Description: "Обнаружены данные банковской карты. Нарушение PCI DSS!",
		}
	}
	return nil
}

// detectBankDocument checks for bank document indicators
func (dd *DocumentDetector) detectBankDocument(text, textLower, filePath string) *DetectedDocument {
	var indicators []string
	confidence := 0.0

	if dd.patterns["bank_doc"].MatchString(textLower) {
		indicators = append(indicators, "Найдены ключевые слова банковского документа")
		confidence += 0.3
	}

	if dd.patterns["iban"].MatchString(text) {
		indicators = append(indicators, "Найден IBAN")
		confidence += 0.4
	}

	if dd.patterns["bic"].MatchString(text) {
		indicators = append(indicators, "Найден BIC/SWIFT код")
		confidence += 0.3
	}

	if confidence >= 0.4 {
		return &DetectedDocument{
			Type:        DocTypeBankStatement,
			TypeRu:      "Банковский документ",
			Confidence:  min(confidence, 1.0),
			FilePath:    filePath,
			Indicators:  indicators,
			RiskLevel:   "🟠 ВЫСОКИЙ",
			Description: "Обнаружены банковские реквизиты.",
		}
	}
	return nil
}

// detectTaxDocument checks for tax document indicators
func (dd *DocumentDetector) detectTaxDocument(text, textLower, filePath string) *DetectedDocument {
	var indicators []string
	confidence := 0.0

	if dd.patterns["tax_doc"].MatchString(textLower) {
		indicators = append(indicators, "Найдены ключевые слова налогового документа")
		confidence += 0.5
	}

	if confidence >= 0.4 {
		return &DetectedDocument{
			Type:        DocTypeTaxDocument,
			TypeRu:      "Налоговый документ",
			Confidence:  min(confidence, 1.0),
			FilePath:    filePath,
			Indicators:  indicators,
			RiskLevel:   "🟠 ВЫСОКИЙ",
			Description: "Обнаружен налоговый документ с персональными данными.",
		}
	}
	return nil
}

// detectMedicalRecord checks for medical record indicators
func (dd *DocumentDetector) detectMedicalRecord(text, textLower, filePath string) *DetectedDocument {
	var indicators []string
	confidence := 0.0

	if dd.patterns["medical"].MatchString(textLower) {
		indicators = append(indicators, "Найдены ключевые слова медицинского документа")
		confidence += 0.4
	}

	if dd.patterns["oms"].MatchString(text) {
		indicators = append(indicators, "Найден номер полиса ОМС")
		confidence += 0.4
	}

	if confidence >= 0.4 {
		return &DetectedDocument{
			Type:        DocTypeMedicalRecord,
			TypeRu:      "Медицинский документ",
			Confidence:  min(confidence, 1.0),
			FilePath:    filePath,
			Indicators:  indicators,
			RiskLevel:   "🔴 КРИТИЧЕСКИЙ",
			Description: "Обнаружены медицинские данные. Защищены законом о персональных данных!",
		}
	}
	return nil
}

// AnalyzeImage analyzes an image for document-like characteristics
func (dd *DocumentDetector) AnalyzeImage(filePath string) (*DetectedDocument, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Decode image to get dimensions
	img, format, err := image.DecodeConfig(file)
	if err != nil {
		return nil, err
	}

	// Analyze aspect ratio for common document sizes
	aspectRatio := float64(img.Width) / float64(img.Height)
	if aspectRatio < 1 {
		aspectRatio = 1 / aspectRatio
	}

	var docType DocumentType
	var typeRu string
	var confidence float64
	var indicators []string

	// ID-1 format (credit cards, driver's licenses): 85.6mm × 53.98mm = 1.586
	if aspectRatio >= 1.5 && aspectRatio <= 1.7 {
		docType = DocTypeIDCard
		typeRu = "Возможно ID-документ"
		confidence = 0.3
		indicators = append(indicators, "Соотношение сторон соответствует формату ID-1 (карта)")
	}

	// ID-3 format (passport): 125mm × 88mm = 1.42
	if aspectRatio >= 1.35 && aspectRatio <= 1.5 {
		docType = DocTypePassport
		typeRu = "Возможно паспорт"
		confidence = 0.25
		indicators = append(indicators, "Соотношение сторон соответствует формату паспорта")
	}

	// A4 format (documents): 297mm × 210mm = 1.414
	if aspectRatio >= 1.4 && aspectRatio <= 1.45 {
		docType = DocTypeBankStatement
		typeRu = "Возможно документ A4"
		confidence = 0.2
		indicators = append(indicators, "Соотношение сторон соответствует формату A4")
	}

	if confidence > 0 {
		indicators = append(indicators, "Формат: "+format)
		indicators = append(indicators, fmt.Sprintf("Размер: %dx%d", img.Width, img.Height))

		return &DetectedDocument{
			Type:        docType,
			TypeRu:      typeRu,
			Confidence:  confidence,
			FilePath:    filePath,
			Indicators:  indicators,
			RiskLevel:   "🟡 ТРЕБУЕТ ПРОВЕРКИ",
			Description: "Изображение может содержать документ. Рекомендуется проверка с OCR.",
		}, nil
	}

	return nil, nil
}

// GetDocumentTypeDescription returns Russian description for document type
func GetDocumentTypeDescription(dt DocumentType) string {
	descriptions := map[DocumentType]string{
		DocTypePassport:      "Паспорт (внутренний или заграничный)",
		DocTypeDriverLicense: "Водительское удостоверение",
		DocTypeIDCard:        "Удостоверение личности / ID-карта",
		DocTypeCreditCard:    "Банковская карта",
		DocTypeBankStatement: "Банковская выписка / документ",
		DocTypeTaxDocument:   "Налоговый документ (2-НДФЛ, декларация)",
		DocTypeMedicalRecord: "Медицинская документация",
		DocTypeUnknown:       "Неизвестный тип документа",
	}

	if desc, ok := descriptions[dt]; ok {
		return desc
	}
	return string(dt)
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
