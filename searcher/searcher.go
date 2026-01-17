package searcher

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// MaxFileSize is the maximum file size to scan (100MB)
	MaxFileSize = 100 * 1024 * 1024

	// MaxConcurrentFiles limits goroutines for file scanning
	MaxConcurrentFiles = 16
)

// Scanner performs recursive filesystem scanning for sensitive data
type Scanner struct {
	patterns          *Patterns
	ignoreList        *IgnoreList
	riskScorer        *RiskScorer
	maxFileSize       int64
	semaphore         chan struct{}
	result            *ScanResult
	startTime         int64
	docExtractor      *DocumentExtractor
	scanDocuments     bool
	scanArchives      bool
	onlyExtensions    map[string]bool // If set, only scan files with these extensions
}

// NewScanner creates a new Scanner instance
func NewScanner() *Scanner {
	return &Scanner{
		patterns:      NewPatterns(),
		ignoreList:   NewIgnoreList(),
		riskScorer:   NewRiskScorer(),
		maxFileSize:  MaxFileSize,
		semaphore:    make(chan struct{}, MaxConcurrentFiles),
		result:       NewScanResult(),
		scanDocuments: false,
		scanArchives:  false,
	}
}

// SetDocumentExtractor sets the document extractor
func (s *Scanner) SetDocumentExtractor(de *DocumentExtractor) {
	s.docExtractor = de
}

// SetScanDocuments enables/disables document scanning
func (s *Scanner) SetScanDocuments(enabled bool) {
	s.scanDocuments = enabled
}

// SetScanArchives enables/disables archive scanning
func (s *Scanner) SetScanArchives(enabled bool) {
	s.scanArchives = enabled
}

// Scan recursively scans a directory for sensitive data
func (s *Scanner) Scan(rootDir string) (*ScanResult, error) {
	s.startTime = time.Now().Unix()
	s.result = NewScanResult()
	s.result.StartTime = s.startTime

	// Initialize ignore list with defaults
	s.ignoreList.AddDefaultIgnores()
	
	// Enable document/image/archive scanning if configured
	if s.scanDocuments {
		s.ignoreList.EnableDocumentScanning()
	}
	if s.docExtractor != nil && s.docExtractor.enableOCR {
		s.ignoreList.EnableImageScanning()
	}
	if s.scanArchives {
		s.ignoreList.EnableArchiveScanning()
	}

	// Try to load .dataLeak-ignore file
	ignoreFilePath := filepath.Join(rootDir, ".dataLeak-ignore")
	_ = s.ignoreList.LoadFromFile(ignoreFilePath)

	// Start recursive scan
	var wg sync.WaitGroup
	wg.Add(1)
	go s.scanDirectory(rootDir, &wg)
	wg.Wait()

	s.result.EndTime = time.Now().Unix()
	return s.result, nil
}

// scanDirectory recursively scans a directory
func (s *Scanner) scanDirectory(dir string, wg *sync.WaitGroup) {
	defer wg.Done()

	entries, err := os.ReadDir(dir)
	if err != nil {
		s.result.ErrorCount++
		return
	}

	for _, entry := range entries {
		fullPath := filepath.Join(dir, entry.Name())

		if s.ignoreList.ShouldIgnorePath(fullPath) {
			continue
		}

		if entry.IsDir() {
			if !s.ignoreList.ShouldIgnoreDirectory(fullPath) {
				wg.Add(1)
				go s.scanDirectory(fullPath, wg)
			}
		} else {
			wg.Add(1)
			go s.scanFile(fullPath, wg)
		}
	}
}

// scanFile scans a single file for sensitive patterns
func (s *Scanner) scanFile(filePath string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Acquire semaphore slot
	s.semaphore <- struct{}{}
	defer func() { <-s.semaphore }()

	fileInfo, err := os.Stat(filePath)
	if err != nil {
		s.result.IncrementErrorCount()
		return
	}

	ext := strings.ToLower(filepath.Ext(filePath))

	// Check if only specific extensions should be scanned
	if len(s.onlyExtensions) > 0 {
		if !s.onlyExtensions[ext] {
			s.result.IncrementFilesSkipped()
			return
		}
	}

	// Skip files that are too large
	if fileInfo.Size() > s.maxFileSize {
		s.result.IncrementFilesSkipped()
		return
	}

	// Check if it's a document or archive that needs special handling
	if s.docExtractor != nil {
		isDocument := ext == ".pdf" || ext == ".docx" || ext == ".doc" || ext == ".xlsx" || ext == ".xls"
		isArchive := ext == ".zip" || ext == ".tar" || ext == ".gz" || ext == ".tgz"
		isImage := ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".gif" || ext == ".bmp" || ext == ".tiff"

		// Handle documents
		if isDocument && s.scanDocuments {
			s.scanDocumentFile(filePath, fileInfo.Size())
			return
		}

		// Handle archives
		if isArchive && s.scanArchives {
			s.scanArchiveFile(filePath, fileInfo.Size())
			return
		}

		// Handle images (OCR)
		if isImage && s.docExtractor.enableOCR {
			s.scanImageFile(filePath, fileInfo.Size())
			return
		}
		
		// If it's a document/image but scanning is not enabled for that type
		if isDocument && !s.scanDocuments {
			s.result.IncrementFilesSkipped()
			s.result.AddSkipReason(filePath, "сканирование документов отключено")
			return
		}
		if isImage && !s.docExtractor.enableOCR {
			s.result.IncrementFilesSkipped()
			s.result.AddSkipReason(filePath, "OCR отключён (установите Tesseract)")
			return
		}
	} else {
		// No document extractor - skip documents/images
		isDocument := ext == ".pdf" || ext == ".docx" || ext == ".doc" || ext == ".xlsx" || ext == ".xls"
		isImage := ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".gif" || ext == ".bmp" || ext == ".tiff"
		if isDocument || isImage {
			s.result.IncrementFilesSkipped()
			s.result.AddSkipReason(filePath, "нет экстрактора (включите -docs или -ocr)")
			return
		}
	}

	// Try to detect if file is binary
	if s.isBinaryFile(filePath) {
		s.result.IncrementFilesSkipped()
		return
	}

	findings, err := s.scanFileContent(filePath)
	if err != nil {
		s.result.IncrementErrorCount()
		return
	}

	for _, finding := range findings {
		s.result.AddFinding(finding)
	}

	s.result.IncrementFilesScanned()
	s.result.AddTotalSize(fileInfo.Size())
}

// scanDocumentFile scans a document file (PDF, DOCX, etc.)
func (s *Scanner) scanDocumentFile(filePath string, fileSize int64) {
	if s.docExtractor == nil {
		s.result.IncrementFilesSkipped()
		s.result.AddSkipReason(filePath, "нет экстрактора документов")
		return
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	hasFindings := false

	content, err := s.docExtractor.ExtractText(filePath)
	if err != nil {
		s.result.IncrementErrorCount()
		s.result.AddSkipReason(filePath, "ошибка извлечения: "+err.Error())
		return
	}

	// Scan extracted text for patterns if we have text
	if content.Text != "" {
		findings := s.scanTextContent(filePath, content.Text)
		for _, finding := range findings {
			s.result.AddFinding(finding)
			hasFindings = true
		}
	}

	// For PDFs, also run image analysis on pages if OCR is enabled
	if ext == ".pdf" && s.docExtractor.enableOCR {
		pdfFindings := s.analyzePDFAsDocument(filePath)
		for _, finding := range pdfFindings {
			s.result.AddFinding(finding)
			hasFindings = true
		}
	}

	if !hasFindings && content.Text == "" {
		s.result.IncrementFilesSkipped()
		if content.Error != nil {
			s.result.AddSkipReason(filePath, "OCR ошибка: "+content.Error.Error())
		} else {
			s.result.AddSkipReason(filePath, "пустой текст (возможно сканированный PDF, нужен OCR)")
		}
		return
	}

	s.result.IncrementFilesScanned()
	s.result.AddTotalSize(fileSize)
}

// analyzePDFAsDocument converts PDF pages to images and runs document detection
func (s *Scanner) analyzePDFAsDocument(filePath string) []*Finding {
	var findings []*Finding

	// Check if pdftoppm is available
	pdftoppm, err := exec.LookPath("pdftoppm")
	if err != nil {
		return findings // Can't convert PDF without pdftoppm
	}

	// Create temp directory for images
	tmpDir, err := os.MkdirTemp("", "pdf_analyze_")
	if err != nil {
		return findings
	}
	defer os.RemoveAll(tmpDir)

	// Convert PDF to images
	outputPrefix := filepath.Join(tmpDir, "page")
	cmd := exec.Command(pdftoppm, "-png", "-r", "150", filePath, outputPrefix)
	if err := cmd.Run(); err != nil {
		return findings
	}

	// Analyze each page as an image
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return findings
	}

	imageAnalyzer := NewImageAnalyzer(true)
	
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".png") {
			continue
		}

		imgPath := filepath.Join(tmpDir, entry.Name())
		analysisResult, err := imageAnalyzer.AnalyzeImage(imgPath)
		
		if err == nil && analysisResult != nil && analysisResult.IsDocument {
			// Document detected - add as critical finding
			pageNum := extractPageNumber(entry.Name())
			finding := &Finding{
				FilePath:     filePath,
				LineNumber:   pageNum,
				PatternType:  PatternPassport,
				Severity:     Critical,
				Description:  imageAnalyzer.GetDocumentTypeDescription(analysisResult.DocumentType) + " обнаружен в PDF",
				MatchedText:  analysisResult.DocumentType,
				Context:      fmt.Sprintf("PDF страница %d (confidence: %s)", pageNum, analysisResult.Confidence),
				RiskScore:    analysisResult.FinalScore,
			}
			
			if analysisResult.MRZData != nil && analysisResult.MRZData.IsValid {
				finding.Description = "Паспорт с MRZ обнаружен в PDF"
			}
			
			findings = append(findings, finding)
		}
	}

	return findings
}

// extractPageNumber extracts page number from filename like "page-1.png"
func extractPageNumber(filename string) int {
	// Pattern: page-N.png
	parts := strings.Split(strings.TrimSuffix(filename, ".png"), "-")
	if len(parts) >= 2 {
		if num, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
			return num
		}
	}
	return 1
}

// scanArchiveFile scans contents of an archive
func (s *Scanner) scanArchiveFile(filePath string, fileSize int64) {
	if s.docExtractor == nil {
		s.result.IncrementFilesSkipped()
		return
	}

	content, err := s.docExtractor.ExtractText(filePath)
	if err != nil {
		s.result.IncrementErrorCount()
		return
	}

	if content.Text == "" {
		s.result.IncrementFilesSkipped()
		return
	}

	// Scan extracted text for patterns
	findings := s.scanTextContent(filePath+" (архив)", content.Text)
	for _, finding := range findings {
		s.result.AddFinding(finding)
	}

	s.result.IncrementFilesScanned()
	s.result.AddTotalSize(fileSize)
}

// scanImageFile scans an image using OCR
func (s *Scanner) scanImageFile(filePath string, fileSize int64) {
	if s.docExtractor == nil || !s.docExtractor.enableOCR {
		s.result.IncrementFilesSkipped()
		s.result.AddSkipReason(filePath, "OCR отключён")
		return
	}

	// Use multi-signal image analyzer
	imageAnalyzer := NewImageAnalyzer(true)
	analysisResult, err := imageAnalyzer.AnalyzeImage(filePath)
	
	if err == nil && analysisResult != nil && analysisResult.IsDocument {
		// Document detected with high confidence - add as critical finding
		finding := &Finding{
			FilePath:     filePath,
			LineNumber:   1,
			PatternType:  PatternPassport, // Generic document type
			Severity:     Critical,
			Description:  imageAnalyzer.GetDocumentTypeDescription(analysisResult.DocumentType) + " обнаружен",
			MatchedText:  analysisResult.DocumentType,
			Context:      "Изображение документа (confidence: " + analysisResult.Confidence + ")",
			RiskScore:    analysisResult.FinalScore,
		}
		
		// Add MRZ data if found
		if analysisResult.MRZData != nil && analysisResult.MRZData.IsValid {
			finding.Description = "Паспорт с MRZ обнаружен"
			finding.Context = "MRZ: " + analysisResult.MRZData.Surname + " " + analysisResult.MRZData.GivenNames
		}
		
		s.result.AddFinding(finding)
	}

	// Also try OCR text extraction
	content, err := s.docExtractor.ExtractText(filePath)
	if err != nil {
		s.result.IncrementFilesScanned()
		s.result.AddTotalSize(fileSize)
		return
	}

	if content.Text == "" {
		s.result.IncrementFilesScanned()
		s.result.AddTotalSize(fileSize)
		return
	}

	// Scan extracted text for patterns
	findings := s.scanTextContent(filePath+" (OCR)", content.Text)
	for _, finding := range findings {
		s.result.AddFinding(finding)
	}

	s.result.IncrementFilesScanned()
	s.result.AddTotalSize(fileSize)
}

// scanTextContent scans text content for patterns
func (s *Scanner) scanTextContent(sourcePath, text string) []*Finding {
	var findings []*Finding
	lines := strings.Split(text, "\n")

	for lineNum, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}

		patterns := s.patterns.FindAll(line)
		for _, pattern := range patterns {
			pattern.LineNumber = lineNum + 1
			pattern.FilePath = sourcePath
			pattern.Context = line
			pattern.EntropyScore = s.riskScorer.entropyCalculator.CalculateEntropy(pattern.MatchText)

			riskScore := s.riskScorer.CalculateRiskScore(pattern)

			finding := &Finding{
				FilePath:     sourcePath,
				LineNumber:   lineNum + 1,
				ColumnStart:  pattern.StartIndex,
				ColumnEnd:    pattern.EndIndex,
				PatternType:  pattern.Type,
				Severity:     pattern.Severity,
				Description:  pattern.Description,
				MatchedText:  pattern.MatchText,
				Context:      line,
				EntropyScore: pattern.EntropyScore,
				RiskScore:    riskScore,
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// scanFileContent scans the content of a single file
func (s *Scanner) scanFileContent(filePath string) ([]*Finding, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var findings []*Finding
	scanner := bufio.NewScanner(file)
	lineNum := 1

	for scanner.Scan() {
		line := scanner.Text()

		// Skip empty lines
		if strings.TrimSpace(line) == "" {
			lineNum++
			continue
		}

		// Find patterns in line
		patterns := s.patterns.FindAll(line)
		for _, pattern := range patterns {
			// Calculate risk score
			pattern.LineNumber = lineNum
			pattern.FilePath = filePath
			pattern.Context = line
			pattern.EntropyScore = s.riskScorer.entropyCalculator.CalculateEntropy(pattern.MatchText)

			riskScore := s.riskScorer.CalculateRiskScore(pattern)

			// Create finding
			finding := &Finding{
				FilePath:     filePath,
				LineNumber:   lineNum,
				ColumnStart:  pattern.StartIndex,
				ColumnEnd:    pattern.EndIndex,
				PatternType:  pattern.Type,
				Severity:     pattern.Severity,
				Description:  pattern.Description,
				MatchedText:  pattern.MatchText,
				Context:      line,
				EntropyScore: pattern.EntropyScore,
				RiskScore:    riskScore,
			}

			findings = append(findings, finding)
		}

		lineNum++
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return findings, nil
}

// isBinaryFile checks if a file is likely binary
func (s *Scanner) isBinaryFile(filePath string) bool {
	file, err := os.Open(filePath)
	if err != nil {
		return true
	}
	defer file.Close()

	// Read first 512 bytes
	buf := make([]byte, 512)
	n, _ := file.Read(buf)

	if n == 0 {
		return false
	}

	// Check for null bytes (typical of binary files)
	for i := 0; i < n; i++ {
		if buf[i] == 0 {
			return true
		}
	}

	return false
}

// SetMaxFileSize sets the maximum file size to scan
func (s *Scanner) SetMaxFileSize(size int64) {
	s.maxFileSize = size
}

// SetMaxConcurrentFiles sets the maximum number of concurrent file scans
func (s *Scanner) SetMaxConcurrentFiles(max int) {
	s.semaphore = make(chan struct{}, max)
}

// GetIgnoreList returns the ignore list for configuration
func (s *Scanner) GetIgnoreList() *IgnoreList {
	return s.ignoreList
}

// GetPatterns returns the patterns for configuration
func (s *Scanner) GetPatterns() *Patterns {
	return s.patterns
}

// SetOnlyExtensions sets which file extensions to scan (nil = all)
func (s *Scanner) SetOnlyExtensions(extensions []string) {
	if len(extensions) == 0 {
		s.onlyExtensions = nil
		return
	}
	s.onlyExtensions = make(map[string]bool)
	for _, ext := range extensions {
		ext = strings.ToLower(ext)
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		s.onlyExtensions[ext] = true
	}
}

// ClearOnlyExtensions removes the extension filter (scan all files)
func (s *Scanner) ClearOnlyExtensions() {
	s.onlyExtensions = nil
}

// SearchInFile searches for the keyword in a single file (legacy function)
func SearchInFile(filePath string, keyword string) ([]int, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lineNumbers []int
	scanner := bufio.NewScanner(file)
	lineNum := 1

	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(strings.ToLower(line), strings.ToLower(keyword)) {
			lineNumbers = append(lineNumbers, lineNum)
		}
		lineNum++
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return lineNumbers, nil
}
