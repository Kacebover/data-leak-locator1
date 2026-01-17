package searcher

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// DependencyStatus represents the status of a single dependency
type DependencyStatus struct {
	Name        string `json:"name"`
	Available   bool   `json:"available"`
	Version     string `json:"version,omitempty"`
	Path        string `json:"path,omitempty"`
	Required    bool   `json:"required"`
	Description string `json:"description"`
	InstallHint string `json:"install_hint"`
}

// DependencyChecker checks for required external dependencies
type DependencyChecker struct {
	results map[string]*DependencyStatus
}

// NewDependencyChecker creates a new dependency checker
func NewDependencyChecker() *DependencyChecker {
	return &DependencyChecker{
		results: make(map[string]*DependencyStatus),
	}
}

// CheckAll checks all dependencies and returns their statuses
func (dc *DependencyChecker) CheckAll() map[string]*DependencyStatus {
	dc.checkTesseract()
	dc.checkPoppler()
	dc.checkOllama()
	return dc.results
}

// checkTesseract checks if Tesseract OCR is available
func (dc *DependencyChecker) checkTesseract() {
	status := &DependencyStatus{
		Name:        "Tesseract OCR",
		Required:    false,
		Description: "Распознавание текста на изображениях (OCR)",
		InstallHint: dc.getTesseractInstallHint(),
	}

	path, err := exec.LookPath("tesseract")
	if err == nil {
		status.Available = true
		status.Path = path
		// Try to get version
		cmd := exec.Command(path, "--version")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			if len(lines) > 0 {
				status.Version = strings.TrimSpace(lines[0])
			}
		}
	}

	dc.results["tesseract"] = status
}

// checkPoppler checks if Poppler (pdftotext, pdftoppm) is available
func (dc *DependencyChecker) checkPoppler() {
	status := &DependencyStatus{
		Name:        "Poppler (PDF utils)",
		Required:    false,
		Description: "Извлечение текста и OCR из PDF файлов",
		InstallHint: dc.getPopplerInstallHint(),
	}

	// Check for pdftotext
	pdftotext, err := exec.LookPath("pdftotext")
	if err == nil {
		status.Available = true
		status.Path = pdftotext
		// Try to get version
		cmd := exec.Command(pdftotext, "-v")
		output, _ := cmd.CombinedOutput()
		lines := strings.Split(string(output), "\n")
		if len(lines) > 0 {
			status.Version = strings.TrimSpace(lines[0])
		}
	}

	// Also check pdftoppm
	pdftoppm, err := exec.LookPath("pdftoppm")
	if err == nil && !status.Available {
		status.Available = true
		status.Path = pdftoppm
	}

	dc.results["poppler"] = status
}

// checkOllama checks if Ollama is available and running
func (dc *DependencyChecker) checkOllama() {
	status := &DependencyStatus{
		Name:        "Ollama (AI)",
		Required:    false,
		Description: "Локальный AI-анализ результатов сканирования",
		InstallHint: dc.getOllamaInstallHint(),
	}

	// Check if ollama binary exists
	path, err := exec.LookPath("ollama")
	if err == nil {
		status.Path = path
		// Try to get version
		cmd := exec.Command(path, "--version")
		output, err := cmd.Output()
		if err == nil {
			status.Version = strings.TrimSpace(string(output))
		}
	}

	// Check if Ollama server is running
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get("http://localhost:11434/api/tags")
	if err == nil {
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			status.Available = true
			// Try to get installed models
			var result struct {
				Models []struct {
					Name string `json:"name"`
				} `json:"models"`
			}
			if json.NewDecoder(resp.Body).Decode(&result) == nil && len(result.Models) > 0 {
				var modelNames []string
				for _, m := range result.Models {
					modelNames = append(modelNames, m.Name)
				}
				status.Version = fmt.Sprintf("Модели: %s", strings.Join(modelNames, ", "))
			}
		}
	}

	dc.results["ollama"] = status
}

// getTesseractInstallHint returns platform-specific install instructions
func (dc *DependencyChecker) getTesseractInstallHint() string {
	switch runtime.GOOS {
	case "darwin":
		return "brew install tesseract tesseract-lang"
	case "linux":
		return "sudo apt install tesseract-ocr tesseract-ocr-rus"
	case "windows":
		return "Скачать: https://github.com/UB-Mannheim/tesseract/wiki"
	default:
		return "Установите Tesseract OCR для вашей системы"
	}
}

// getPopplerInstallHint returns platform-specific install instructions
func (dc *DependencyChecker) getPopplerInstallHint() string {
	switch runtime.GOOS {
	case "darwin":
		return "brew install poppler"
	case "linux":
		return "sudo apt install poppler-utils"
	case "windows":
		return "Скачать: https://github.com/oschwartz10612/poppler-windows/releases"
	default:
		return "Установите Poppler utils для вашей системы"
	}
}

// getOllamaInstallHint returns platform-specific install instructions
func (dc *DependencyChecker) getOllamaInstallHint() string {
	switch runtime.GOOS {
	case "darwin":
		return "brew install ollama && ollama pull llama3.2"
	case "linux":
		return "curl -fsSL https://ollama.com/install.sh | sh && ollama pull llama3.2"
	case "windows":
		return "Скачать: https://ollama.com/download"
	default:
		return "Установите Ollama для вашей системы"
	}
}

// IsTesseractAvailable returns true if Tesseract is available
func (dc *DependencyChecker) IsTesseractAvailable() bool {
	if dc.results["tesseract"] == nil {
		dc.checkTesseract()
	}
	return dc.results["tesseract"].Available
}

// IsPopplerAvailable returns true if Poppler is available
func (dc *DependencyChecker) IsPopplerAvailable() bool {
	if dc.results["poppler"] == nil {
		dc.checkPoppler()
	}
	return dc.results["poppler"].Available
}

// IsOllamaAvailable returns true if Ollama is available and running
func (dc *DependencyChecker) IsOllamaAvailable() bool {
	if dc.results["ollama"] == nil {
		dc.checkOllama()
	}
	return dc.results["ollama"].Available
}

// GetMissingDependencies returns a list of dependencies that are not available
func (dc *DependencyChecker) GetMissingDependencies() []*DependencyStatus {
	var missing []*DependencyStatus
	for _, status := range dc.results {
		if !status.Available {
			missing = append(missing, status)
		}
	}
	return missing
}

// GetAvailableDependencies returns a list of available dependencies
func (dc *DependencyChecker) GetAvailableDependencies() []*DependencyStatus {
	var available []*DependencyStatus
	for _, status := range dc.results {
		if status.Available {
			available = append(available, status)
		}
	}
	return available
}

// FormatStatusReport returns a formatted string with dependency statuses
func (dc *DependencyChecker) FormatStatusReport() string {
	var sb strings.Builder
	sb.WriteString("📋 Статус зависимостей:\n\n")

	for _, status := range dc.results {
		if status.Available {
			sb.WriteString(fmt.Sprintf("✅ %s", status.Name))
			if status.Version != "" {
				sb.WriteString(fmt.Sprintf(" (%s)", status.Version))
			}
			sb.WriteString("\n")
		} else {
			sb.WriteString(fmt.Sprintf("❌ %s - не установлен\n", status.Name))
			sb.WriteString(fmt.Sprintf("   💡 %s\n", status.InstallHint))
		}
	}

	return sb.String()
}

// FormatMissingWarning returns a warning message about missing dependencies
func (dc *DependencyChecker) FormatMissingWarning() string {
	missing := dc.GetMissingDependencies()
	if len(missing) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("⚠️ Отсутствующие зависимости:\n")
	for _, status := range missing {
		sb.WriteString(fmt.Sprintf("   • %s: %s\n", status.Name, status.Description))
		sb.WriteString(fmt.Sprintf("     📝 %s\n", status.InstallHint))
	}
	return sb.String()
}

