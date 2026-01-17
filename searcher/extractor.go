package searcher

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// DocumentExtractor extracts text from various document formats
type DocumentExtractor struct {
	enableOCR    bool
	tesseractCmd string
	maxFileSize  int64
	tempDir      string
}

// NewDocumentExtractor creates a new document extractor
func NewDocumentExtractor(enableOCR bool) *DocumentExtractor {
	return &DocumentExtractor{
		enableOCR:    enableOCR,
		tesseractCmd: "tesseract",
		maxFileSize:  100 * 1024 * 1024, // 100MB
		tempDir:      os.TempDir(),
	}
}

// SetOCREnabled enables or disables OCR
func (de *DocumentExtractor) SetOCREnabled(enabled bool) {
	de.enableOCR = enabled
}

// ExtractedContent holds extracted text and metadata
type ExtractedContent struct {
	Text       string
	SourceFile string
	Format     string
	PageCount  int
	Error      error
}

// ExtractText extracts text from a file based on its type
func (de *DocumentExtractor) ExtractText(filePath string) (*ExtractedContent, error) {
	ext := strings.ToLower(filepath.Ext(filePath))

	switch ext {
	case ".pdf":
		return de.extractPDF(filePath)
	case ".docx":
		return de.extractDOCX(filePath)
	case ".doc":
		return de.extractDOC(filePath)
	case ".xlsx", ".xls":
		return de.extractExcel(filePath)
	case ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif":
		return de.extractImage(filePath)
	case ".zip":
		return de.extractZIP(filePath)
	case ".tar":
		return de.extractTAR(filePath)
	case ".gz", ".tgz":
		return de.extractGzip(filePath)
	case ".txt", ".md", ".rst", ".csv", ".json", ".xml", ".yaml", ".yml":
		return de.extractPlainText(filePath)
	default:
		return nil, fmt.Errorf("неподдерживаемый формат: %s", ext)
	}
}

// extractPDF extracts text from PDF files
func (de *DocumentExtractor) extractPDF(filePath string) (*ExtractedContent, error) {
	content := &ExtractedContent{
		SourceFile: filePath,
		Format:     "PDF",
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Simple PDF text extraction (basic implementation)
	text := de.extractPDFText(data)

	if text == "" {
		// Try pdftotext first if available
		if pdfText := de.tryPdfToText(filePath); pdfText != "" {
			text = pdfText
		} else if de.enableOCR {
			// Try OCR on PDF (convert pages to images)
			ocrText, ocrErr := de.ocrPDF(filePath)
			if ocrErr == nil && ocrText != "" {
				text = ocrText
			} else if ocrErr != nil {
				// Return error info for debugging
				content.Error = ocrErr
			}
		}
	}

	content.Text = text
	return content, nil
}

// tryPdfToText tries to extract text using pdftotext command
func (de *DocumentExtractor) tryPdfToText(filePath string) string {
	// Check if pdftotext is available
	pdftotext, err := exec.LookPath("pdftotext")
	if err != nil {
		return ""
	}

	cmd := exec.Command(pdftotext, "-layout", filePath, "-")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	return strings.TrimSpace(string(output))
}

// ocrPDF performs OCR on a PDF by converting pages to images
func (de *DocumentExtractor) ocrPDF(filePath string) (string, error) {
	if !de.isTesseractAvailable() {
		return "", fmt.Errorf("tesseract не установлен")
	}

	// Check if pdftoppm is available (for converting PDF to images)
	pdftoppm, err := exec.LookPath("pdftoppm")
	if err != nil {
		// Fallback: try direct OCR on PDF (some Tesseract builds support it)
		return de.performOCR(filePath)
	}

	// Create temp directory for images
	tmpDir, err := os.MkdirTemp("", "pdf_ocr_")
	if err != nil {
		return "", fmt.Errorf("ошибка создания temp директории: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Convert PDF to images
	outputPrefix := filepath.Join(tmpDir, "page")
	cmd := exec.Command(pdftoppm, "-png", "-r", "150", filePath, outputPrefix)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("ошибка конвертации PDF: %v - %s", err, string(output))
	}

	// OCR each image
	var allText []string
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return "", fmt.Errorf("ошибка чтения temp директории: %v", err)
	}

	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".png") {
			imgPath := filepath.Join(tmpDir, entry.Name())
			text, err := de.performOCR(imgPath)
			if err == nil && text != "" {
				allText = append(allText, text)
			}
		}
	}

	if len(allText) == 0 {
		return "", fmt.Errorf("OCR не извлёк текст из %d страниц (установите языковой пакет: brew install tesseract-lang)", len(entries))
	}

	return strings.Join(allText, "\n\n"), nil
}

// extractPDFText performs basic PDF text extraction
func (de *DocumentExtractor) extractPDFText(data []byte) string {
	var texts []string

	// Find text streams in PDF
	// Look for BT...ET blocks (Begin Text...End Text)
	btPattern := regexp.MustCompile(`BT[\s\S]*?ET`)
	matches := btPattern.FindAll(data, -1)

	for _, match := range matches {
		// Extract text from Tj and TJ operators
		tjPattern := regexp.MustCompile(`\((.*?)\)\s*Tj`)
		tjMatches := tjPattern.FindAllSubmatch(match, -1)
		for _, m := range tjMatches {
			if len(m) > 1 {
				texts = append(texts, string(m[1]))
			}
		}

		// Extract text from TJ arrays
		tjArrayPattern := regexp.MustCompile(`\[(.*?)\]\s*TJ`)
		tjArrayMatches := tjArrayPattern.FindAllSubmatch(match, -1)
		for _, m := range tjArrayMatches {
			if len(m) > 1 {
				// Extract strings from array
				strPattern := regexp.MustCompile(`\((.*?)\)`)
				strMatches := strPattern.FindAllSubmatch(m[1], -1)
				for _, s := range strMatches {
					if len(s) > 1 {
						texts = append(texts, string(s[1]))
					}
				}
			}
		}
	}

	// Also look for plain text streams
	streamPattern := regexp.MustCompile(`stream\s*([\s\S]*?)\s*endstream`)
	streamMatches := streamPattern.FindAllSubmatch(data, -1)
	for _, m := range streamMatches {
		if len(m) > 1 {
			// Check if stream contains readable text
			streamText := string(m[1])
			if isPrintableText(streamText) {
				texts = append(texts, streamText)
			}
		}
	}

	return strings.Join(texts, " ")
}

// extractDOCX extracts text from DOCX files
func (de *DocumentExtractor) extractDOCX(filePath string) (*ExtractedContent, error) {
	content := &ExtractedContent{
		SourceFile: filePath,
		Format:     "DOCX",
	}

	r, err := zip.OpenReader(filePath)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	var texts []string

	for _, f := range r.File {
		// Main document content
		if f.Name == "word/document.xml" {
			text, err := de.extractXMLText(f)
			if err == nil {
				texts = append(texts, text)
			}
		}
		// Headers
		if strings.HasPrefix(f.Name, "word/header") && strings.HasSuffix(f.Name, ".xml") {
			text, err := de.extractXMLText(f)
			if err == nil {
				texts = append(texts, text)
			}
		}
		// Footers
		if strings.HasPrefix(f.Name, "word/footer") && strings.HasSuffix(f.Name, ".xml") {
			text, err := de.extractXMLText(f)
			if err == nil {
				texts = append(texts, text)
			}
		}
	}

	content.Text = strings.Join(texts, "\n")
	return content, nil
}

// extractXMLText extracts text content from an XML file in a ZIP
func (de *DocumentExtractor) extractXMLText(f *zip.File) (string, error) {
	rc, err := f.Open()
	if err != nil {
		return "", err
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return "", err
	}

	// Parse XML and extract text nodes
	return extractTextFromXML(data), nil
}

// XMLNode represents an XML element for text extraction
type XMLNode struct {
	XMLName xml.Name
	Content string   `xml:",chardata"`
	Nodes   []XMLNode `xml:",any"`
}

// extractTextFromXML extracts all text content from XML
func extractTextFromXML(data []byte) string {
	var texts []string

	// Simple regex-based extraction for Word XML
	// Matches <w:t>...</w:t> tags
	textPattern := regexp.MustCompile(`<w:t[^>]*>([^<]*)</w:t>`)
	matches := textPattern.FindAllSubmatch(data, -1)

	for _, m := range matches {
		if len(m) > 1 {
			text := string(m[1])
			if strings.TrimSpace(text) != "" {
				texts = append(texts, text)
			}
		}
	}

	return strings.Join(texts, "")
}

// extractDOC extracts text from old DOC files (basic)
func (de *DocumentExtractor) extractDOC(filePath string) (*ExtractedContent, error) {
	content := &ExtractedContent{
		SourceFile: filePath,
		Format:     "DOC",
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	// Basic text extraction from DOC (compound document)
	// Look for text between specific markers
	var texts []string
	
	// DOC files often have readable text mixed with binary
	// Extract printable sequences
	var currentText strings.Builder
	for _, b := range data {
		if b >= 32 && b < 127 || b == '\n' || b == '\r' || b == '\t' {
			currentText.WriteByte(b)
		} else {
			if currentText.Len() > 10 { // Only keep sequences longer than 10 chars
				texts = append(texts, currentText.String())
			}
			currentText.Reset()
		}
	}
	if currentText.Len() > 10 {
		texts = append(texts, currentText.String())
	}

	content.Text = strings.Join(texts, " ")
	return content, nil
}

// extractExcel extracts text from Excel files
func (de *DocumentExtractor) extractExcel(filePath string) (*ExtractedContent, error) {
	content := &ExtractedContent{
		SourceFile: filePath,
		Format:     "Excel",
	}

	ext := strings.ToLower(filepath.Ext(filePath))
	if ext == ".xlsx" {
		return de.extractXLSX(filePath)
	}

	// Old XLS format - basic extraction
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	content.Text = extractPrintableText(data)
	return content, nil
}

// extractXLSX extracts text from XLSX files
func (de *DocumentExtractor) extractXLSX(filePath string) (*ExtractedContent, error) {
	content := &ExtractedContent{
		SourceFile: filePath,
		Format:     "XLSX",
	}

	r, err := zip.OpenReader(filePath)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	var texts []string
	var sharedStrings []string

	// First, read shared strings
	for _, f := range r.File {
		if f.Name == "xl/sharedStrings.xml" {
			rc, err := f.Open()
			if err == nil {
				data, _ := io.ReadAll(rc)
				rc.Close()
				// Extract strings from shared strings XML
				strPattern := regexp.MustCompile(`<t[^>]*>([^<]*)</t>`)
				matches := strPattern.FindAllSubmatch(data, -1)
				for _, m := range matches {
					if len(m) > 1 {
						sharedStrings = append(sharedStrings, string(m[1]))
					}
				}
			}
		}
	}

	texts = append(texts, sharedStrings...)

	// Read sheet data
	for _, f := range r.File {
		if strings.HasPrefix(f.Name, "xl/worksheets/") && strings.HasSuffix(f.Name, ".xml") {
			rc, err := f.Open()
			if err == nil {
				data, _ := io.ReadAll(rc)
				rc.Close()
				// Extract inline strings
				strPattern := regexp.MustCompile(`<v>([^<]*)</v>`)
				matches := strPattern.FindAllSubmatch(data, -1)
				for _, m := range matches {
					if len(m) > 1 {
						texts = append(texts, string(m[1]))
					}
				}
			}
		}
	}

	content.Text = strings.Join(texts, " ")
	return content, nil
}

// extractImage extracts text from images using OCR
func (de *DocumentExtractor) extractImage(filePath string) (*ExtractedContent, error) {
	content := &ExtractedContent{
		SourceFile: filePath,
		Format:     "Image",
	}

	if !de.enableOCR {
		return nil, fmt.Errorf("OCR отключён, пропуск изображения: %s", filePath)
	}

	text, err := de.performOCR(filePath)
	if err != nil {
		return nil, err
	}

	content.Text = text
	return content, nil
}

// performOCR runs Tesseract OCR on an image
func (de *DocumentExtractor) performOCR(filePath string) (string, error) {
	// Check if Tesseract is available
	if !de.isTesseractAvailable() {
		return "", fmt.Errorf("tesseract не установлен или недоступен")
	}

	// Use gosseract if available, otherwise fall back to command line
	return de.runTesseractCLI(filePath)
}

// IsTesseractAvailable checks if Tesseract is installed (exported)
func (de *DocumentExtractor) IsTesseractAvailable() bool {
	return de.isTesseractAvailable()
}

// isTesseractAvailable checks if Tesseract is installed
func (de *DocumentExtractor) isTesseractAvailable() bool {
	// Check common locations
	paths := []string{
		"/usr/local/bin/tesseract",
		"/usr/bin/tesseract",
		"/opt/homebrew/bin/tesseract",
		"tesseract", // Check PATH
	}

	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			de.tesseractCmd = p
			return true
		}
	}
	
	// Also check using which/where command
	if path, err := exec.LookPath("tesseract"); err == nil {
		de.tesseractCmd = path
		return true
	}

	return false
}

// runTesseractCLI runs Tesseract via command line
func (de *DocumentExtractor) runTesseractCLI(imagePath string) (string, error) {
	// Create temp file for output
	tmpFile := filepath.Join(de.tempDir, "ocr_output")

	// Detect available languages
	lang := de.getAvailableTesseractLangs()
	
	cmd := exec.Command(de.tesseractCmd, imagePath, tmpFile, "-l", lang)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// If rus+eng fails, try just eng
		if strings.Contains(string(output), "rus") {
			cmd = exec.Command(de.tesseractCmd, imagePath, tmpFile, "-l", "eng")
			if err := cmd.Run(); err != nil {
				return "", fmt.Errorf("ошибка Tesseract: %v", err)
			}
		} else {
			return "", fmt.Errorf("ошибка Tesseract: %v - %s", err, string(output))
		}
	}

	// Read output
	outputPath := tmpFile + ".txt"
	defer os.Remove(outputPath)

	data, err := os.ReadFile(outputPath)
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// getAvailableTesseractLangs returns available language string for Tesseract
func (de *DocumentExtractor) getAvailableTesseractLangs() string {
	// Check if Russian is available
	cmd := exec.Command(de.tesseractCmd, "--list-langs")
	output, err := cmd.Output()
	if err != nil {
		return "eng"
	}

	langs := string(output)
	hasRus := strings.Contains(langs, "rus")
	hasEng := strings.Contains(langs, "eng")

	if hasRus && hasEng {
		return "rus+eng"
	} else if hasRus {
		return "rus"
	} else if hasEng {
		return "eng"
	}

	return "eng" // Default
}

// extractZIP extracts and scans contents of ZIP archives
func (de *DocumentExtractor) extractZIP(filePath string) (*ExtractedContent, error) {
	content := &ExtractedContent{
		SourceFile: filePath,
		Format:     "ZIP",
	}

	r, err := zip.OpenReader(filePath)
	if err != nil {
		return nil, err
	}
	defer r.Close()

	var texts []string

	for _, f := range r.File {
		// Skip directories
		if f.FileInfo().IsDir() {
			continue
		}

		// Check if encrypted (bit 0 of Flags indicates encryption)
		if f.Flags&0x1 != 0 {
			texts = append(texts, fmt.Sprintf("[Зашифрованный файл: %s]", f.Name))
			continue
		}

		// Skip large files
		if f.UncompressedSize64 > uint64(de.maxFileSize) {
			continue
		}

		// Extract and process file
		rc, err := f.Open()
		if err != nil {
			continue
		}

		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			continue
		}

		// Process based on file extension
		ext := strings.ToLower(filepath.Ext(f.Name))
		switch ext {
		case ".txt", ".md", ".json", ".xml", ".yaml", ".yml", ".env", ".cfg", ".conf", ".ini":
			texts = append(texts, fmt.Sprintf("=== %s ===\n%s", f.Name, string(data)))
		case ".docx":
			// Create temp file and extract
			tmpPath := filepath.Join(de.tempDir, "temp_"+filepath.Base(f.Name))
			if err := os.WriteFile(tmpPath, data, 0644); err == nil {
				if extracted, err := de.extractDOCX(tmpPath); err == nil {
					texts = append(texts, fmt.Sprintf("=== %s ===\n%s", f.Name, extracted.Text))
				}
				os.Remove(tmpPath)
			}
		}
	}

	content.Text = strings.Join(texts, "\n\n")
	return content, nil
}

// extractTAR extracts and scans contents of TAR archives
func (de *DocumentExtractor) extractTAR(filePath string) (*ExtractedContent, error) {
	content := &ExtractedContent{
		SourceFile: filePath,
		Format:     "TAR",
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	tr := tar.NewReader(f)
	var texts []string

	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}

		// Skip directories
		if header.Typeflag == tar.TypeDir {
			continue
		}

		// Skip large files
		if header.Size > de.maxFileSize {
			continue
		}

		// Read file content
		data, err := io.ReadAll(tr)
		if err != nil {
			continue
		}

		// Process text files
		ext := strings.ToLower(filepath.Ext(header.Name))
		if isTextExtension(ext) {
			texts = append(texts, fmt.Sprintf("=== %s ===\n%s", header.Name, string(data)))
		}
	}

	content.Text = strings.Join(texts, "\n\n")
	return content, nil
}

// extractGzip extracts and scans contents of gzipped files
func (de *DocumentExtractor) extractGzip(filePath string) (*ExtractedContent, error) {
	content := &ExtractedContent{
		SourceFile: filePath,
		Format:     "GZIP",
	}

	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	gr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer gr.Close()

	data, err := io.ReadAll(gr)
	if err != nil {
		return nil, err
	}

	// Check if it's a tar.gz
	if strings.HasSuffix(filePath, ".tar.gz") || strings.HasSuffix(filePath, ".tgz") {
		tr := tar.NewReader(bytes.NewReader(data))
		var texts []string

		for {
			header, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}

			if header.Typeflag == tar.TypeDir {
				continue
			}

			fileData, err := io.ReadAll(tr)
			if err != nil {
				continue
			}

			ext := strings.ToLower(filepath.Ext(header.Name))
			if isTextExtension(ext) {
				texts = append(texts, fmt.Sprintf("=== %s ===\n%s", header.Name, string(fileData)))
			}
		}

		content.Text = strings.Join(texts, "\n\n")
	} else {
		content.Text = string(data)
	}

	return content, nil
}

// extractPlainText reads plain text files
func (de *DocumentExtractor) extractPlainText(filePath string) (*ExtractedContent, error) {
	content := &ExtractedContent{
		SourceFile: filePath,
		Format:     "Text",
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	content.Text = string(data)
	return content, nil
}

// Helper functions

func isPrintableText(s string) bool {
	printable := 0
	for _, r := range s {
		if r >= 32 && r < 127 || r == '\n' || r == '\r' || r == '\t' {
			printable++
		}
	}
	return float64(printable)/float64(len(s)) > 0.7
}

func extractPrintableText(data []byte) string {
	var result strings.Builder
	for _, b := range data {
		if b >= 32 && b < 127 || b == '\n' || b == '\r' || b == '\t' {
			result.WriteByte(b)
		} else {
			result.WriteByte(' ')
		}
	}
	return result.String()
}

func isTextExtension(ext string) bool {
	textExts := map[string]bool{
		".txt": true, ".md": true, ".rst": true,
		".json": true, ".xml": true, ".yaml": true, ".yml": true,
		".csv": true, ".env": true, ".cfg": true, ".conf": true,
		".ini": true, ".log": true, ".sql": true,
		".py": true, ".js": true, ".ts": true, ".go": true,
		".java": true, ".c": true, ".cpp": true, ".h": true,
		".sh": true, ".bash": true, ".zsh": true,
		".html": true, ".htm": true, ".css": true,
	}
	return textExts[ext]
}

// SupportedFormats returns list of supported document formats
func (de *DocumentExtractor) SupportedFormats() []string {
	formats := []string{
		"PDF (текст и OCR)",
		"DOCX (Word)",
		"DOC (Word старый)",
		"XLSX (Excel)",
		"XLS (Excel старый)",
		"ZIP архивы",
		"TAR архивы",
		"GZIP/TGZ архивы",
		"Текстовые файлы",
	}

	if de.enableOCR {
		formats = append(formats, "PNG/JPG/GIF/BMP/TIFF (OCR)")
	}

	return formats
}

