package searcher

import (
	"encoding/csv"
	"encoding/json"
	"os"
	"strconv"
	"time"
)

// ReportGenerator generates findings reports in various formats
type ReportGenerator struct {
	result *ScanResult
}

// NewReportGenerator creates a new ReportGenerator
func NewReportGenerator(result *ScanResult) *ReportGenerator {
	return &ReportGenerator{
		result: result,
	}
}

// JSONReport represents the structure for JSON export
type JSONReport struct {
	Metadata    ReportMetadata `json:"metadata"`
	Summary     ReportSummary  `json:"summary"`
	Findings    []*Finding     `json:"findings"`
	GeneratedAt string         `json:"generated_at"`
}

// ReportMetadata contains scan metadata
type ReportMetadata struct {
	ScanStartTime    int64  `json:"scan_start_time"`
	ScanEndTime      int64  `json:"scan_end_time"`
	ScanDuration     int64  `json:"scan_duration_seconds"`
	FilesScanned     int    `json:"files_scanned"`
	FilesSkipped     int    `json:"files_skipped"`
	TotalDataScanned string `json:"total_data_scanned_bytes"`
	ErrorCount       int    `json:"error_count"`
}

// ReportSummary contains summary statistics
type ReportSummary struct {
	TotalFindings    int            `json:"total_findings"`
	CriticalFindings int            `json:"critical_findings"`
	HighFindings     int            `json:"high_findings"`
	MediumFindings   int            `json:"medium_findings"`
	LowFindings      int            `json:"low_findings"`
	AverageRiskScore float64        `json:"average_risk_score"`
	HighestRiskScore float64        `json:"highest_risk_score"`
	PatternCounts    map[string]int `json:"pattern_counts"`
}

// ExportJSON exports findings to a JSON file
func (rg *ReportGenerator) ExportJSON(filePath string) error {
	summary := rg.generateSummary()
	metadata := rg.generateMetadata()

	report := JSONReport{
		Metadata:    metadata,
		Summary:     summary,
		Findings:    rg.result.Findings,
		GeneratedAt: time.Now().Format(time.RFC3339),
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filePath, data, 0644)
}

// ExportCSV exports findings to a CSV file
func (rg *ReportGenerator) ExportCSV(filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Write UTF-8 BOM for Excel compatibility
	file.Write([]byte{0xEF, 0xBB, 0xBF})

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header (Russian)
	header := []string{
		"Путь к файлу",
		"Строка",
		"Начало колонки",
		"Конец колонки",
		"Тип паттерна",
		"Уровень серьёзности",
		"Оценка риска",
		"Энтропия",
		"Описание",
		"Найденный текст",
		"Контекст",
	}
	if err := writer.Write(header); err != nil {
		return err
	}

	// Write findings
	for _, finding := range rg.result.Findings {
		record := []string{
			finding.FilePath,
			strconv.Itoa(finding.LineNumber),
			strconv.Itoa(finding.ColumnStart),
			strconv.Itoa(finding.ColumnEnd),
			patternTypeToRussian(finding.PatternType),
			severityToRussian(finding.Severity),
			strconv.FormatFloat(finding.RiskScore, 'f', 2, 64),
			strconv.FormatFloat(finding.EntropyScore, 'f', 4, 64),
			descriptionToRussian(finding.Description),
			maskSensitiveText(finding.MatchedText),
			maskSensitiveText(finding.Context),
		}
		if err := writer.Write(record); err != nil {
			return err
		}
	}

	return nil
}

// ExportPlainText exports findings to a plain text file
func (rg *ReportGenerator) ExportPlainText(filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	summary := rg.generateSummary()

	// Write header
	file.WriteString("ОТЧЁТ ОБ ОБНАРУЖЕНИИ УТЕЧЕК ДАННЫХ\n")
	file.WriteString("==================================\n\n")

	file.WriteString("Дата создания: " + time.Now().Format("02.01.2006 15:04:05") + "\n")
	file.WriteString("Длительность сканирования: " + strconv.FormatInt(rg.result.EndTime-rg.result.StartTime, 10) + " сек.\n\n")

	// Write summary
	file.WriteString("СВОДКА\n")
	file.WriteString("------\n")
	file.WriteString("Всего находок:     " + strconv.Itoa(summary.TotalFindings) + "\n")
	file.WriteString("🔴 Критических:    " + strconv.Itoa(summary.CriticalFindings) + "\n")
	file.WriteString("🟠 Высоких:        " + strconv.Itoa(summary.HighFindings) + "\n")
	file.WriteString("🟡 Средних:        " + strconv.Itoa(summary.MediumFindings) + "\n")
	file.WriteString("🟢 Низких:         " + strconv.Itoa(summary.LowFindings) + "\n")
	file.WriteString("Средняя оценка риска: " + strconv.FormatFloat(summary.AverageRiskScore, 'f', 2, 64) + "\n\n")

	// Pattern statistics
	if len(summary.PatternCounts) > 0 {
		file.WriteString("СТАТИСТИКА ПО ТИПАМ\n")
		file.WriteString("-------------------\n")
		for pattern, count := range summary.PatternCounts {
			file.WriteString("  " + patternTypeToRussian(PatternType(pattern)) + ": " + strconv.Itoa(count) + "\n")
		}
		file.WriteString("\n")
	}

	// Write findings
	file.WriteString("ДЕТАЛИ НАХОДОК\n")
	file.WriteString("--------------\n\n")

	for i, finding := range rg.result.Findings {
		file.WriteString(strconv.Itoa(i+1) + ". " + finding.FilePath + ":" + strconv.Itoa(finding.LineNumber) + "\n")
		file.WriteString("   Тип:         " + patternTypeToRussian(finding.PatternType) + "\n")
		file.WriteString("   Серьёзность: " + severityToRussian(finding.Severity) + "\n")
		file.WriteString("   Оценка риска: " + strconv.FormatFloat(finding.RiskScore, 'f', 2, 64) + "\n")
		file.WriteString("   Описание:    " + descriptionToRussian(finding.Description) + "\n")
		file.WriteString("   Контекст:    " + maskSensitiveText(finding.Context) + "\n\n")
	}

	file.WriteString("==================================\n")
	file.WriteString("Конец отчёта\n")

	return nil
}

// generateSummary creates a summary of findings
func (rg *ReportGenerator) generateSummary() ReportSummary {
	summary := ReportSummary{
		TotalFindings:    len(rg.result.Findings),
		PatternCounts:    make(map[string]int),
		HighestRiskScore: 0,
		AverageRiskScore: 0,
	}

	summary.CriticalFindings = rg.result.SeveritySummary[Critical]
	summary.HighFindings = rg.result.SeveritySummary[High]
	summary.MediumFindings = rg.result.SeveritySummary[Medium]
	summary.LowFindings = rg.result.SeveritySummary[Low]

	totalRiskScore := 0.0

	for _, finding := range rg.result.Findings {
		// Count patterns
		summary.PatternCounts[string(finding.PatternType)]++

		// Track risk scores
		totalRiskScore += finding.RiskScore
		if finding.RiskScore > summary.HighestRiskScore {
			summary.HighestRiskScore = finding.RiskScore
		}
	}

	if len(rg.result.Findings) > 0 {
		summary.AverageRiskScore = totalRiskScore / float64(len(rg.result.Findings))
	}

	return summary
}

// generateMetadata creates scan metadata
func (rg *ReportGenerator) generateMetadata() ReportMetadata {
	return ReportMetadata{
		ScanStartTime:    rg.result.StartTime,
		ScanEndTime:      rg.result.EndTime,
		ScanDuration:     rg.result.EndTime - rg.result.StartTime,
		FilesScanned:     rg.result.FilesScanned,
		FilesSkipped:     rg.result.FilesSkipped,
		TotalDataScanned: strconv.FormatInt(rg.result.TotalSize, 10) + " bytes",
		ErrorCount:       rg.result.ErrorCount,
	}
}

// maskSensitiveText masks sensitive parts of text for display
func maskSensitiveText(text string) string {
	// If text is very long, truncate it
	if len(text) > 100 {
		return text[:97] + "..."
	}
	return text
}

// GenerateReport generates a complete report in multiple formats
func (rg *ReportGenerator) GenerateReport(outputDir string) error {
	timestamp := time.Now().Format("20060102_150405")

	// JSON report
	jsonPath := outputDir + "/отчёт-утечки_" + timestamp + ".json"
	if err := rg.ExportJSON(jsonPath); err != nil {
		return err
	}

	// CSV report
	csvPath := outputDir + "/отчёт-утечки_" + timestamp + ".csv"
	if err := rg.ExportCSV(csvPath); err != nil {
		return err
	}

	// Text report
	txtPath := outputDir + "/отчёт-утечки_" + timestamp + ".txt"
	if err := rg.ExportPlainText(txtPath); err != nil {
		return err
	}

	return nil
}

// severityToRussian converts severity to Russian
func severityToRussian(s Severity) string {
	switch s {
	case Critical:
		return "Критический"
	case High:
		return "Высокий"
	case Medium:
		return "Средний"
	case Low:
		return "Низкий"
	default:
		return string(s)
	}
}

// patternTypeToRussian converts pattern type to Russian
func patternTypeToRussian(p PatternType) string {
	translations := map[PatternType]string{
		PatternPassword:      "Пароль",
		PatternAPIKey:        "API-ключ",
		PatternToken:         "Токен",
		PatternPrivateKey:    "Приватный ключ",
		PatternAWSKey:        "AWS ключ",
		PatternGitHubToken:   "GitHub токен",
		PatternEmail:         "Email",
		PatternPhoneNumber:   "Телефон",
		PatternSSN:           "SSN",
		PatternCreditCard:    "Банковская карта",
		PatternJSONSecret:    "JSON секрет",
		PatternEnvVar:        "Переменная окружения",
		PatternConnectionStr: "Строка подключения",
		// Additional patterns
		"bic":              "BIC код",
		"iban":             "IBAN",
		"yaml_secret":      "YAML секрет",
		"hardcoded_secret": "Захардкоженный секрет",
		"passport":         "Паспорт",
	}

	if ru, ok := translations[p]; ok {
		return ru
	}
	return string(p)
}

// descriptionToRussian converts description to Russian
func descriptionToRussian(desc string) string {
	translations := map[string]string{
		"Password assignment detected":             "Обнаружено присвоение пароля",
		"API Key detected":                         "Обнаружен API-ключ",
		"Authentication token detected":            "Обнаружен токен аутентификации",
		"Private key detected":                     "Обнаружен приватный ключ",
		"AWS Access Key detected":                  "Обнаружен AWS ключ доступа",
		"GitHub token detected":                    "Обнаружен GitHub токен",
		"Email address detected":                   "Обнаружен email адрес",
		"Phone number detected":                    "Обнаружен номер телефона",
		"Social Security Number detected":          "Обнаружен SSN",
		"Credit card number detected":              "Обнаружен номер банковской карты",
		"JSON secret detected":                     "Обнаружен секрет в JSON",
		"YAML secret detected":                     "Обнаружен секрет в YAML",
		"Environment variable assignment detected": "Обнаружена переменная окружения",
		"Connection string detected":               "Обнаружена строка подключения",
		"Hardcoded secret detected":                "Обнаружен захардкоженный секрет",
		"IBAN detected":                            "Обнаружен IBAN",
		"BIC code detected":                        "Обнаружен BIC код",
		"Passport number detected":                 "Обнаружен номер паспорта",
	}
	if ru, ok := translations[desc]; ok {
		return ru
	}
	return desc
}
