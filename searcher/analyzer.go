package searcher

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"
)

// LocalAnalyzer provides AI-powered analysis using local LLM (Ollama)
type LocalAnalyzer struct {
	ollamaURL  string
	model      string
	timeout    time.Duration
	enabled    bool
	httpClient *http.Client
}

// AnalysisResult holds the result of AI analysis
type AnalysisResult struct {
	Summary          string             `json:"summary"`
	RiskAssessment   string             `json:"risk_assessment"`
	Recommendations  []string           `json:"recommendations"`
	CriticalFindings []CriticalFinding  `json:"critical_findings"`
	Statistics       AnalysisStatistics `json:"statistics"`
	AIInsights       string             `json:"ai_insights,omitempty"`
	ImageAnalyses    []ImageAIAnalysis  `json:"image_analyses,omitempty"`
	AnalyzedAt       string             `json:"analyzed_at"`
	UsedOllama       bool               `json:"used_ollama"`
}

// ImageAIAnalysis holds AI analysis result for a specific image
type ImageAIAnalysis struct {
	FilePath      string   `json:"file_path"`
	DocumentType  string   `json:"document_type"`
	Confidence    float64  `json:"confidence"`
	AIDescription string   `json:"ai_description"`
	RiskLevel     string   `json:"risk_level"`
	Warnings      []string `json:"warnings,omitempty"`
	DataFound     []string `json:"data_found,omitempty"`
}

// CriticalFinding represents a critical issue found
type CriticalFinding struct {
	FilePath    string  `json:"file_path"`
	Description string  `json:"description"`
	Severity    string  `json:"severity"`
	RiskScore   float64 `json:"risk_score"`
	Suggestion  string  `json:"suggestion"`
}

// AnalysisStatistics holds statistical analysis
type AnalysisStatistics struct {
	TotalFindings        int               `json:"total_findings"`
	UniqueFiles          int               `json:"unique_files"`
	AverageRiskScore     float64           `json:"average_risk_score"`
	MaxRiskScore         float64           `json:"max_risk_score"`
	SeverityDistribution map[string]int    `json:"severity_distribution"`
	PatternDistribution  map[string]int    `json:"pattern_distribution"`
	MostAffectedFiles    []FileRiskSummary `json:"most_affected_files"`
}

// FileRiskSummary summarizes risk for a single file
type FileRiskSummary struct {
	FilePath     string  `json:"file_path"`
	FindingCount int     `json:"finding_count"`
	MaxSeverity  string  `json:"max_severity"`
	AvgRiskScore float64 `json:"avg_risk_score"`
}

// NewLocalAnalyzer creates a new local analyzer
func NewLocalAnalyzer() *LocalAnalyzer {
	return &LocalAnalyzer{
		ollamaURL:  "http://localhost:11434",
		model:      "llama3.2", // Default model, can be changed
		timeout:    60 * time.Second,
		enabled:    false,
		httpClient: &http.Client{Timeout: 60 * time.Second},
	}
}

// SetModel sets the Ollama model to use
func (la *LocalAnalyzer) SetModel(model string) {
	la.model = model
}

// SetOllamaURL sets the Ollama API URL
func (la *LocalAnalyzer) SetOllamaURL(url string) {
	la.ollamaURL = url
}

// EnableAI enables AI analysis
func (la *LocalAnalyzer) EnableAI(enabled bool) {
	la.enabled = enabled
}

// IsOllamaAvailable checks if Ollama is running
func (la *LocalAnalyzer) IsOllamaAvailable() bool {
	resp, err := la.httpClient.Get(la.ollamaURL + "/api/tags")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}

// GetAvailableModels returns list of available Ollama models
func (la *LocalAnalyzer) GetAvailableModels() ([]string, error) {
	resp, err := la.httpClient.Get(la.ollamaURL + "/api/tags")
	if err != nil {
		return nil, fmt.Errorf("ollama недоступен: %v", err)
	}
	defer resp.Body.Close()

	var result struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var models []string
	for _, m := range result.Models {
		models = append(models, m.Name)
	}
	return models, nil
}

// Analyze performs comprehensive analysis of scan results
func (la *LocalAnalyzer) Analyze(result *ScanResult) (*AnalysisResult, error) {
	analysis := &AnalysisResult{
		AnalyzedAt: time.Now().Format("02.01.2006 15:04:05"),
		UsedOllama: false,
	}

	// Calculate statistics
	analysis.Statistics = la.calculateStatistics(result)

	// Generate rule-based analysis
	analysis.Summary = la.generateSummary(result, &analysis.Statistics)
	analysis.RiskAssessment = la.assessRisk(result, &analysis.Statistics)
	analysis.Recommendations = la.generateRecommendations(result, &analysis.Statistics)
	analysis.CriticalFindings = la.identifyCriticalFindings(result)

	// If AI is enabled and Ollama is available, get AI insights
	if la.enabled && la.IsOllamaAvailable() {
		analysis.UsedOllama = true

		// Get text-based AI insights
		insights, err := la.getAIInsights(result, &analysis.Statistics)
		if err == nil {
			analysis.AIInsights = insights
		}

		// Analyze document images with AI
		analysis.ImageAnalyses = la.analyzeDocumentImages(result)
	}

	return analysis, nil
}

// analyzeDocumentImages analyzes detected document images with AI
func (la *LocalAnalyzer) analyzeDocumentImages(result *ScanResult) []ImageAIAnalysis {
	var analyses []ImageAIAnalysis

	for _, f := range result.Findings {
		// Only analyze image-based document findings
		if f.PatternType != PatternPassport {
			continue
		}

		// Check if it's an image file
		filePath := f.FilePath
		isImage := strings.HasSuffix(strings.ToLower(filePath), ".jpg") ||
			strings.HasSuffix(strings.ToLower(filePath), ".jpeg") ||
			strings.HasSuffix(strings.ToLower(filePath), ".png")

		if !isImage {
			// For PDF findings, create analysis based on existing data
			if strings.HasSuffix(strings.ToLower(filePath), ".pdf") {
				analysis := ImageAIAnalysis{
					FilePath:      filePath,
					DocumentType:  f.MatchedText,
					Confidence:    f.RiskScore,
					RiskLevel:     la.getRiskLevelFromScore(f.RiskScore),
					AIDescription: la.generateDocumentDescription(f),
					Warnings:      la.generateWarnings(f),
					DataFound:     la.extractFoundData(f),
				}
				analyses = append(analyses, analysis)
			}
			continue
		}

		// Try to analyze with vision model (llava)
		aiDesc := la.analyzeImageWithVision(filePath)

		analysis := ImageAIAnalysis{
			FilePath:      filePath,
			DocumentType:  f.MatchedText,
			Confidence:    f.RiskScore,
			RiskLevel:     la.getRiskLevelFromScore(f.RiskScore),
			AIDescription: aiDesc,
			Warnings:      la.generateWarnings(f),
			DataFound:     la.extractFoundData(f),
		}
		analyses = append(analyses, analysis)
	}

	return analyses
}

// analyzeImageWithVision uses Ollama vision model to analyze image
func (la *LocalAnalyzer) analyzeImageWithVision(imagePath string) string {
	// Check if we have a vision model (llava, bakllava, etc.)
	models, err := la.GetAvailableModels()
	if err != nil {
		return la.getDefaultImageDescription()
	}

	// Look for vision model
	visionModel := ""
	for _, m := range models {
		if strings.Contains(strings.ToLower(m), "llava") ||
			strings.Contains(strings.ToLower(m), "bakllava") ||
			strings.Contains(strings.ToLower(m), "moondream") {
			visionModel = m
			break
		}
	}

	if visionModel == "" {
		// No vision model available, use text description
		return la.getDefaultImageDescription()
	}

	// Read and encode image
	imageData, err := la.encodeImageBase64(imagePath)
	if err != nil {
		return la.getDefaultImageDescription()
	}

	// Call Ollama with vision model
	prompt := `Проанализируй это изображение документа. На русском языке опиши:
1. Что это за документ (паспорт, удостоверение, права и т.д.)
2. Какая информация видна (без указания конкретных персональных данных)
3. Уровень риска утечки данных
Будь кратким, 2-3 предложения.`

	reqBody := map[string]interface{}{
		"model":  visionModel,
		"prompt": prompt,
		"images": []string{imageData},
		"stream": false,
		"options": map[string]interface{}{
			"temperature": 0.3,
			"num_predict": 200,
		},
	}

	jsonBody, _ := json.Marshal(reqBody)

	resp, err := la.httpClient.Post(
		la.ollamaURL+"/api/generate",
		"application/json",
		bytes.NewReader(jsonBody),
	)
	if err != nil {
		return la.getDefaultImageDescription()
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var ollamaResp struct {
		Response string `json:"response"`
	}

	if err := json.Unmarshal(body, &ollamaResp); err != nil {
		return la.getDefaultImageDescription()
	}

	if ollamaResp.Response == "" {
		return la.getDefaultImageDescription()
	}

	return ollamaResp.Response
}

// encodeImageBase64 reads and encodes image to base64
func (la *LocalAnalyzer) encodeImageBase64(imagePath string) (string, error) {
	// Read actual file and encode to base64
	return readImageFile(imagePath)
}

// readImageFile reads image file and returns base64
func readImageFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

// getDefaultImageDescription returns default description when AI unavailable
func (la *LocalAnalyzer) getDefaultImageDescription() string {
	return "Обнаружен документ, удостоверяющий личность. Рекомендуется проверить и удалить из общего доступа."
}

// getRiskLevelFromScore converts risk score to text level
func (la *LocalAnalyzer) getRiskLevelFromScore(score float64) string {
	if score >= 80 {
		return "🔴 КРИТИЧЕСКИЙ"
	} else if score >= 60 {
		return "🟠 ВЫСОКИЙ"
	} else if score >= 40 {
		return "🟡 СРЕДНИЙ"
	}
	return "🟢 НИЗКИЙ"
}

// generateDocumentDescription generates description based on finding
func (la *LocalAnalyzer) generateDocumentDescription(f *Finding) string {
	docType := f.MatchedText

	descriptions := map[string]string{
		"passport_page":   "Обнаружена страница паспорта с персональными данными владельца.",
		"passport_closed": "Обнаружен паспорт (разворот). Виден документ целиком.",
		"passport_card":   "Обнаружена карточка паспорта с фото и данными.",
		"id_card":         "Обнаружено удостоверение личности с персональной информацией.",
		"driver_license":  "Обнаружено водительское удостоверение.",
		"passport":        "Обнаружен паспорт с персональными данными.",
	}

	if desc, ok := descriptions[docType]; ok {
		return desc
	}
	return "Обнаружен документ, содержащий персональные данные."
}

// generateWarnings generates warnings based on finding
func (la *LocalAnalyzer) generateWarnings(f *Finding) []string {
	var warnings []string

	if f.RiskScore >= 80 {
		warnings = append(warnings, "⚠️ Высокий риск утечки персональных данных")
	}
	if f.RiskScore >= 60 {
		warnings = append(warnings, "⚠️ Документ содержит идентифицирующую информацию")
	}

	// Document-specific warnings
	docType := f.MatchedText
	if strings.Contains(docType, "passport") {
		warnings = append(warnings, "⚠️ Паспортные данные могут быть использованы для мошенничества")
	}

	return warnings
}

// extractFoundData extracts what data was found
func (la *LocalAnalyzer) extractFoundData(f *Finding) []string {
	var data []string

	docType := f.MatchedText

	if strings.Contains(docType, "passport") {
		data = append(data, "📋 ФИО владельца")
		data = append(data, "📅 Дата рождения")
		data = append(data, "🔢 Номер документа")
		data = append(data, "📸 Фотография")
	}

	if strings.Contains(docType, "id_card") || strings.Contains(docType, "driver") {
		data = append(data, "📋 Персональные данные")
		data = append(data, "📸 Фотография")
		data = append(data, "🔢 Номер документа")
	}

	if len(data) == 0 {
		data = append(data, "📋 Персональные данные")
	}

	return data
}

// calculateStatistics calculates detailed statistics
func (la *LocalAnalyzer) calculateStatistics(result *ScanResult) AnalysisStatistics {
	stats := AnalysisStatistics{
		TotalFindings:        len(result.Findings),
		SeverityDistribution: make(map[string]int),
		PatternDistribution:  make(map[string]int),
	}

	fileFindings := make(map[string][]Finding)
	var totalRisk float64
	stats.MaxRiskScore = 0

	for _, f := range result.Findings {
		// Severity distribution
		stats.SeverityDistribution[string(f.Severity)]++

		// Pattern distribution
		stats.PatternDistribution[string(f.PatternType)]++

		// Risk scores
		totalRisk += f.RiskScore
		if f.RiskScore > stats.MaxRiskScore {
			stats.MaxRiskScore = f.RiskScore
		}

		// Group by file
		fileFindings[f.FilePath] = append(fileFindings[f.FilePath], *f)
	}

	stats.UniqueFiles = len(fileFindings)

	if len(result.Findings) > 0 {
		stats.AverageRiskScore = totalRisk / float64(len(result.Findings))
	}

	// Calculate most affected files
	for filePath, findings := range fileFindings {
		var maxSeverity Severity = Low
		var totalFileRisk float64

		for _, f := range findings {
			totalFileRisk += f.RiskScore
			if f.Severity.Score() > maxSeverity.Score() {
				maxSeverity = f.Severity
			}
		}

		stats.MostAffectedFiles = append(stats.MostAffectedFiles, FileRiskSummary{
			FilePath:     filePath,
			FindingCount: len(findings),
			MaxSeverity:  string(maxSeverity),
			AvgRiskScore: totalFileRisk / float64(len(findings)),
		})
	}

	// Sort by finding count
	sort.Slice(stats.MostAffectedFiles, func(i, j int) bool {
		return stats.MostAffectedFiles[i].FindingCount > stats.MostAffectedFiles[j].FindingCount
	})

	// Keep only top 10
	if len(stats.MostAffectedFiles) > 10 {
		stats.MostAffectedFiles = stats.MostAffectedFiles[:10]
	}

	return stats
}

// generateSummary generates a human-readable summary
func (la *LocalAnalyzer) generateSummary(result *ScanResult, stats *AnalysisStatistics) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("Анализ выявил %d потенциальных утечек данных в %d файлах.\n\n",
		stats.TotalFindings, stats.UniqueFiles))

	critCount := stats.SeverityDistribution[string(Critical)]
	highCount := stats.SeverityDistribution[string(High)]

	if critCount > 0 || highCount > 0 {
		sb.WriteString(fmt.Sprintf("⚠️ ВНИМАНИЕ: Обнаружено %d критических и %d серьёзных проблем, требующих немедленного внимания.\n\n",
			critCount, highCount))
	}

	// Top patterns
	type patternCount struct {
		pattern string
		count   int
	}
	var patterns []patternCount
	for p, c := range stats.PatternDistribution {
		patterns = append(patterns, patternCount{p, c})
	}
	sort.Slice(patterns, func(i, j int) bool {
		return patterns[i].count > patterns[j].count
	})

	sb.WriteString("Наиболее частые типы утечек:\n")
	for i, p := range patterns {
		if i >= 5 {
			break
		}
		sb.WriteString(fmt.Sprintf("  • %s: %d\n", patternTypeToRussian(PatternType(p.pattern)), p.count))
	}

	return sb.String()
}

// assessRisk provides risk assessment
func (la *LocalAnalyzer) assessRisk(result *ScanResult, stats *AnalysisStatistics) string {
	var level string
	var description string

	critCount := stats.SeverityDistribution[string(Critical)]
	highCount := stats.SeverityDistribution[string(High)]

	switch {
	case critCount >= 10 || (critCount >= 5 && highCount >= 10):
		level = "🔴 КРИТИЧЕСКИЙ"
		description = "Обнаружено множество критических утечек. Требуется немедленное вмешательство. " +
			"Рекомендуется приостановить деплой до устранения проблем."

	case critCount >= 3 || highCount >= 10:
		level = "🟠 ВЫСОКИЙ"
		description = "Обнаружены серьёзные проблемы безопасности. Необходимо устранить критические " +
			"уязвимости перед выпуском в продакшн."

	case critCount >= 1 || highCount >= 5:
		level = "🟡 СРЕДНИЙ"
		description = "Присутствуют потенциальные риски. Рекомендуется провести ревью найденных " +
			"проблем и устранить их в ближайшее время."

	case highCount >= 1 || stats.TotalFindings >= 10:
		level = "🟡 УМЕРЕННЫЙ"
		description = "Обнаружены незначительные проблемы. Рекомендуется запланировать их устранение."

	default:
		level = "🟢 НИЗКИЙ"
		description = "Критических проблем не обнаружено. Рекомендуется периодический мониторинг."
	}

	return fmt.Sprintf("Уровень риска: %s\n\n%s\n\nСредний балл риска: %.1f / 100\nМаксимальный балл: %.1f / 100",
		level, description, stats.AverageRiskScore, stats.MaxRiskScore)
}

// generateRecommendations provides actionable recommendations
func (la *LocalAnalyzer) generateRecommendations(result *ScanResult, stats *AnalysisStatistics) []string {
	var recs []string

	critCount := stats.SeverityDistribution[string(Critical)]
	highCount := stats.SeverityDistribution[string(High)]

	// Critical recommendations
	if critCount > 0 {
		recs = append(recs, "🔴 Немедленно удалите или замаскируйте все критические секреты из кода")
	}

	// Pattern-specific recommendations
	if stats.PatternDistribution[string(PatternPrivateKey)] > 0 {
		recs = append(recs, "🔑 Переместите приватные ключи в защищённое хранилище (HashiCorp Vault, AWS Secrets Manager)")
	}

	if stats.PatternDistribution[string(PatternPassword)] > 0 {
		recs = append(recs, "🔐 Используйте переменные окружения или менеджер секретов вместо хардкода паролей")
	}

	if stats.PatternDistribution[string(PatternAPIKey)] > 0 || stats.PatternDistribution[string(PatternAWSKey)] > 0 {
		recs = append(recs, "🗝️ Ротируйте все обнаруженные API-ключи и настройте их безопасное хранение")
	}

	if stats.PatternDistribution[string(PatternCreditCard)] > 0 {
		recs = append(recs, "💳 СРОЧНО: Удалите данные банковских карт из кодовой базы. Это нарушение PCI DSS!")
	}

	if stats.PatternDistribution[string(PatternConnectionStr)] > 0 {
		recs = append(recs, "🔗 Вынесите строки подключения к БД в конфигурацию окружения")
	}

	// General recommendations
	if len(result.Findings) > 0 {
		recs = append(recs, "📋 Добавьте pre-commit хук для автоматической проверки секретов")
		recs = append(recs, "🛡️ Настройте .gitignore для исключения файлов с секретами")
		recs = append(recs, "📝 Обновите .env.example с примерами переменных (без реальных значений)")
	}

	if critCount > 0 || highCount > 0 {
		recs = append(recs, "🔄 После исправлений выполните повторное сканирование для проверки")
	}

	return recs
}

// identifyCriticalFindings identifies most critical issues
func (la *LocalAnalyzer) identifyCriticalFindings(result *ScanResult) []CriticalFinding {
	var critical []CriticalFinding

	for _, f := range result.Findings {
		if f.Severity == Critical || (f.Severity == High && f.RiskScore >= 70) {
			suggestion := la.getSuggestionForPattern(f.PatternType)

			critical = append(critical, CriticalFinding{
				FilePath:    f.FilePath,
				Description: descriptionToRussian(f.Description),
				Severity:    severityToRussian(f.Severity),
				RiskScore:   f.RiskScore,
				Suggestion:  suggestion,
			})
		}
	}

	// Sort by risk score
	sort.Slice(critical, func(i, j int) bool {
		return critical[i].RiskScore > critical[j].RiskScore
	})

	// Limit to top 20
	if len(critical) > 20 {
		critical = critical[:20]
	}

	return critical
}

// getSuggestionForPattern returns a suggestion for fixing a specific pattern
func (la *LocalAnalyzer) getSuggestionForPattern(pattern PatternType) string {
	suggestions := map[PatternType]string{
		PatternPassword:      "Используйте переменные окружения: os.Getenv(\"DB_PASSWORD\")",
		PatternAPIKey:        "Храните в .env файле: API_KEY=xxx, загружайте через godotenv",
		PatternPrivateKey:    "Переместите в ~/.ssh/ или используйте Vault для хранения",
		PatternAWSKey:        "Настройте AWS credentials через aws configure или IAM роли",
		PatternGitHubToken:   "Используйте GitHub App или Personal Access Token в секретах CI/CD",
		PatternCreditCard:    "НЕМЕДЛЕННО удалите! Данные карт не должны храниться в коде",
		PatternConnectionStr: "Используйте DATABASE_URL из переменных окружения",
		PatternToken:         "Храните токены в защищённом хранилище секретов",
	}

	if suggestion, ok := suggestions[pattern]; ok {
		return suggestion
	}
	return "Удалите чувствительные данные и используйте безопасное хранение"
}

// getAIInsights gets AI-powered insights from Ollama
func (la *LocalAnalyzer) getAIInsights(result *ScanResult, stats *AnalysisStatistics) (string, error) {
	// Build prompt
	prompt := la.buildAnalysisPrompt(result, stats)

	// Call Ollama
	reqBody := map[string]interface{}{
		"model":  la.model,
		"prompt": prompt,
		"stream": false,
		"options": map[string]interface{}{
			"temperature": 0.3,
			"num_predict": 500,
		},
	}

	jsonBody, _ := json.Marshal(reqBody)

	resp, err := la.httpClient.Post(
		la.ollamaURL+"/api/generate",
		"application/json",
		bytes.NewReader(jsonBody),
	)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var ollamaResp struct {
		Response string `json:"response"`
	}

	if err := json.Unmarshal(body, &ollamaResp); err != nil {
		return "", err
	}

	return ollamaResp.Response, nil
}

// buildAnalysisPrompt builds the prompt for AI analysis
func (la *LocalAnalyzer) buildAnalysisPrompt(result *ScanResult, stats *AnalysisStatistics) string {
	var sb strings.Builder

	sb.WriteString("Ты эксперт по безопасности. Проанализируй результаты сканирования на утечки данных и дай краткие рекомендации на русском языке.\n\n")

	sb.WriteString("Статистика:\n")
	sb.WriteString(fmt.Sprintf("- Всего находок: %d\n", stats.TotalFindings))
	sb.WriteString(fmt.Sprintf("- Критических: %d\n", stats.SeverityDistribution[string(Critical)]))
	sb.WriteString(fmt.Sprintf("- Высоких: %d\n", stats.SeverityDistribution[string(High)]))
	sb.WriteString(fmt.Sprintf("- Средних: %d\n", stats.SeverityDistribution[string(Medium)]))
	sb.WriteString(fmt.Sprintf("- Затронуто файлов: %d\n", stats.UniqueFiles))
	sb.WriteString(fmt.Sprintf("- Средний риск: %.1f\n\n", stats.AverageRiskScore))

	sb.WriteString("Типы утечек:\n")
	for pattern, count := range stats.PatternDistribution {
		sb.WriteString(fmt.Sprintf("- %s: %d\n", pattern, count))
	}

	sb.WriteString("\nПримеры критических находок (первые 5):\n")
	shown := 0
	for _, f := range result.Findings {
		if f.Severity == Critical && shown < 5 {
			sb.WriteString(fmt.Sprintf("- %s:%d - %s\n", f.FilePath, f.LineNumber, f.Description))
			shown++
		}
	}

	sb.WriteString("\nДай 3-5 конкретных рекомендаций по устранению, учитывая специфику найденных проблем.")

	return sb.String()
}

// FormatAnalysisReport formats analysis result as a readable report
func (la *LocalAnalyzer) FormatAnalysisReport(analysis *AnalysisResult) string {
	var sb strings.Builder

	sb.WriteString("╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("║             ОТЧЁТ АНАЛИЗА БЕЗОПАСНОСТИ                       ║\n")
	sb.WriteString("╚══════════════════════════════════════════════════════════════╝\n\n")

	sb.WriteString(fmt.Sprintf("Дата анализа: %s\n\n", analysis.AnalyzedAt))

	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	sb.WriteString("СВОДКА\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	sb.WriteString(analysis.Summary)
	sb.WriteString("\n")

	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	sb.WriteString("ОЦЕНКА РИСКА\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	sb.WriteString(analysis.RiskAssessment)
	sb.WriteString("\n\n")

	if len(analysis.CriticalFindings) > 0 {
		sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		sb.WriteString("КРИТИЧЕСКИЕ НАХОДКИ\n")
		sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		for i, cf := range analysis.CriticalFindings {
			sb.WriteString(fmt.Sprintf("\n%d. %s\n", i+1, cf.FilePath))
			sb.WriteString(fmt.Sprintf("   Описание: %s\n", cf.Description))
			sb.WriteString(fmt.Sprintf("   Серьёзность: %s | Риск: %.0f%%\n", cf.Severity, cf.RiskScore))
			sb.WriteString(fmt.Sprintf("   💡 %s\n", cf.Suggestion))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	sb.WriteString("РЕКОМЕНДАЦИИ\n")
	sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
	for i, rec := range analysis.Recommendations {
		sb.WriteString(fmt.Sprintf("%d. %s\n", i+1, rec))
	}

	if analysis.AIInsights != "" {
		sb.WriteString("\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		sb.WriteString("🤖 AI-АНАЛИЗ (Ollama)\n")
		sb.WriteString("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
		sb.WriteString(analysis.AIInsights)
		sb.WriteString("\n")
	}

	sb.WriteString("\n═══════════════════════════════════════════════════════════════\n")

	return sb.String()
}
