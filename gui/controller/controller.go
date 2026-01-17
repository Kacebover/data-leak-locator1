// Package controller provides the bridge between UI and scanning logic
package controller

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/kacebover/password-finder/encryptor"
	"github.com/kacebover/password-finder/searcher"
)

// ScanController manages scanning operations and provides callbacks for UI updates
type ScanController struct {
	scanner    *searcher.StreamingScanner
	config     *AppConfig
	cancelFunc context.CancelFunc
	
	// Callbacks
	onFinding     func(*searcher.Finding)
	onProgress    func(searcher.ScanProgress)
	onLogMessage  func(LogLevel, string)
	onStateChange func(searcher.ScanState)
	onComplete    func(*searcher.ScanResult, error)
	
	// State
	mu            sync.RWMutex
	currentResult *searcher.ScanResult
	isScanning    bool
	isPaused      bool
	
	// Ignore list (persistent)
	ignoredFindings map[string]bool // key: filepath:line:pattern
	ignoredFiles    map[string]bool
}

// LogLevel represents log message severity
type LogLevel int

const (
	LogInfo LogLevel = iota
	LogWarning
	LogError
	LogDebug
)

// NewScanController creates a new scan controller
func NewScanController() *ScanController {
	ctrl := &ScanController{
		config:          LoadConfig(),
		ignoredFindings: make(map[string]bool),
		ignoredFiles:    make(map[string]bool),
	}
	
	// Load persisted ignore list
	ctrl.loadIgnoreList()
	
	return ctrl
}

// SetOnFinding sets the callback for new findings
func (sc *ScanController) SetOnFinding(callback func(*searcher.Finding)) {
	sc.onFinding = callback
}

// SetOnProgress sets the callback for progress updates
func (sc *ScanController) SetOnProgress(callback func(searcher.ScanProgress)) {
	sc.onProgress = callback
}

// SetOnLogMessage sets the callback for log messages
func (sc *ScanController) SetOnLogMessage(callback func(LogLevel, string)) {
	sc.onLogMessage = callback
}

// SetOnStateChange sets the callback for state changes
func (sc *ScanController) SetOnStateChange(callback func(searcher.ScanState)) {
	sc.onStateChange = callback
}

// SetOnComplete sets the callback for scan completion
func (sc *ScanController) SetOnComplete(callback func(*searcher.ScanResult, error)) {
	sc.onComplete = callback
}

// GetConfig returns the current configuration
func (sc *ScanController) GetConfig() *AppConfig {
	return sc.config
}

// UpdateConfig updates and saves configuration
func (sc *ScanController) UpdateConfig(config *AppConfig) error {
	sc.config = config
	return SaveConfig(config)
}

// StartScan starts a new scan
func (sc *ScanController) StartScan(targetDir string) error {
	sc.mu.Lock()
	if sc.isScanning {
		sc.mu.Unlock()
		return nil
	}
	sc.isScanning = true
	sc.isPaused = false
	sc.mu.Unlock()
	
	// Create scanner with current config
	scannerConfig := searcher.StreamingScannerConfig{
		MaxFileSize:    sc.config.MaxFileSize,
		MaxConcurrent:  sc.config.Concurrency,
		FollowSymlinks: sc.config.FollowSymlinks,
		ScanBinaries:   sc.config.ScanBinaries,
		IncludeExts:    sc.config.IncludeExtensions,
		ExcludeExts:    sc.config.ExcludeExtensions,
		IncludeDirs:    sc.config.IncludeDirs,
		ExcludeDirs:    sc.config.ExcludeDirs,
	}
	
	sc.scanner = searcher.NewStreamingScanner(scannerConfig)
	
	ctx, cancel := context.WithCancel(context.Background())
	sc.cancelFunc = cancel
	
	sc.log(LogInfo, "Starting scan: "+targetDir)
	
	if sc.onStateChange != nil {
		sc.onStateChange(searcher.StateRunning)
	}
	
	// Start event processing goroutine
	go sc.processEvents()
	
	// Start scan in background
	go func() {
		result, err := sc.scanner.Scan(ctx, targetDir)
		
		sc.mu.Lock()
		sc.currentResult = result
		sc.isScanning = false
		sc.isPaused = false
		sc.mu.Unlock()
		
		if err != nil {
			if err == context.Canceled {
				sc.log(LogInfo, "Scan cancelled by user")
			} else {
				sc.log(LogError, "Scan error: "+err.Error())
			}
		} else {
			sc.log(LogInfo, "Scan completed successfully")
		}
		
		if sc.onComplete != nil {
			sc.onComplete(result, err)
		}
	}()
	
	return nil
}

// processEvents handles events from the scanner
func (sc *ScanController) processEvents() {
	for event := range sc.scanner.Events() {
		switch event.Type {
		case searcher.EventFinding:
			if sc.onFinding != nil && !sc.isIgnored(event.Finding) {
				sc.onFinding(event.Finding)
			}
			
		case searcher.EventProgress:
			if sc.onProgress != nil {
				sc.onProgress(event.Progress)
			}
			
		case searcher.EventLogInfo:
			sc.log(LogInfo, event.Message)
			
		case searcher.EventLogWarning:
			sc.log(LogWarning, event.Message)
			
		case searcher.EventLogError, searcher.EventError:
			if event.Error != nil {
				sc.log(LogError, event.Message)
			}
			
		case searcher.EventScanPaused:
			if sc.onStateChange != nil {
				sc.onStateChange(searcher.StatePaused)
			}
			
		case searcher.EventScanResumed:
			if sc.onStateChange != nil {
				sc.onStateChange(searcher.StateRunning)
			}
			
		case searcher.EventScanCompleted:
			if sc.onStateChange != nil {
				sc.onStateChange(searcher.StateCompleted)
			}
			if sc.onProgress != nil {
				sc.onProgress(event.Progress)
			}
			
		case searcher.EventScanCancelled:
			if sc.onStateChange != nil {
				sc.onStateChange(searcher.StateCancelled)
			}
		}
	}
}

// PauseScan pauses the current scan
func (sc *ScanController) PauseScan() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	
	if sc.scanner != nil && sc.isScanning && !sc.isPaused {
		sc.scanner.Pause()
		sc.isPaused = true
		sc.log(LogInfo, "Scan paused")
	}
}

// ResumeScan resumes a paused scan
func (sc *ScanController) ResumeScan() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	
	if sc.scanner != nil && sc.isPaused {
		sc.scanner.Resume()
		sc.isPaused = false
		sc.log(LogInfo, "Scan resumed")
	}
}

// CancelScan cancels the current scan
func (sc *ScanController) CancelScan() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	
	if sc.cancelFunc != nil {
		sc.cancelFunc()
		sc.isScanning = false
		sc.isPaused = false
		sc.log(LogInfo, "Scan cancelled")
	}
}

// IsScanning returns whether a scan is currently running
func (sc *ScanController) IsScanning() bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.isScanning
}

// IsPaused returns whether the scan is paused
func (sc *ScanController) IsPaused() bool {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.isPaused
}

// GetProgress returns current scan progress
func (sc *ScanController) GetProgress() searcher.ScanProgress {
	if sc.scanner != nil {
		return sc.scanner.GetProgress()
	}
	return searcher.ScanProgress{}
}

// GetResult returns the current scan result
func (sc *ScanController) GetResult() *searcher.ScanResult {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.currentResult
}

// ExportJSON exports results to JSON
func (sc *ScanController) ExportJSON(filePath string) error {
	sc.mu.RLock()
	result := sc.currentResult
	sc.mu.RUnlock()
	
	if result == nil {
		return nil
	}
	
	reporter := searcher.NewReportGenerator(result)
	return reporter.ExportJSON(filePath)
}

// ExportCSV exports results to CSV
func (sc *ScanController) ExportCSV(filePath string) error {
	sc.mu.RLock()
	result := sc.currentResult
	sc.mu.RUnlock()
	
	if result == nil {
		return nil
	}
	
	reporter := searcher.NewReportGenerator(result)
	return reporter.ExportCSV(filePath)
}

// ExportAll exports results to all formats
func (sc *ScanController) ExportAll(outputDir string) error {
	sc.mu.RLock()
	result := sc.currentResult
	sc.mu.RUnlock()
	
	if result == nil {
		return nil
	}
	
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return err
	}
	
	reporter := searcher.NewReportGenerator(result)
	return reporter.GenerateReport(outputDir)
}

// IgnoreFinding marks a finding as ignored (false positive)
func (sc *ScanController) IgnoreFinding(finding *searcher.Finding) {
	key := sc.findingKey(finding)
	sc.ignoredFindings[key] = true
	sc.saveIgnoreList()
}

// IgnoreFile marks all findings in a file as ignored
func (sc *ScanController) IgnoreFile(filePath string) {
	sc.ignoredFiles[filePath] = true
	sc.saveIgnoreList()
}

// UnignoreFinding removes a finding from the ignore list
func (sc *ScanController) UnignoreFinding(finding *searcher.Finding) {
	key := sc.findingKey(finding)
	delete(sc.ignoredFindings, key)
	sc.saveIgnoreList()
}

// IsIgnored checks if a finding is ignored
func (sc *ScanController) isIgnored(finding *searcher.Finding) bool {
	if sc.ignoredFiles[finding.FilePath] {
		return true
	}
	key := sc.findingKey(finding)
	return sc.ignoredFindings[key]
}

// findingKey generates a unique key for a finding
func (sc *ScanController) findingKey(finding *searcher.Finding) string {
	return finding.FilePath + ":" + string(rune(finding.LineNumber)) + ":" + string(finding.PatternType)
}

// log emits a log message
func (sc *ScanController) log(level LogLevel, message string) {
	if sc.onLogMessage != nil {
		sc.onLogMessage(level, message)
	}
}

// IgnoreListData represents persisted ignore list
type IgnoreListData struct {
	IgnoredFindings []string `json:"ignored_findings"`
	IgnoredFiles    []string `json:"ignored_files"`
	UpdatedAt       string   `json:"updated_at"`
}

// saveIgnoreList persists the ignore list to disk
func (sc *ScanController) saveIgnoreList() {
	data := IgnoreListData{
		IgnoredFindings: make([]string, 0, len(sc.ignoredFindings)),
		IgnoredFiles:    make([]string, 0, len(sc.ignoredFiles)),
		UpdatedAt:       time.Now().Format(time.RFC3339),
	}
	
	for key := range sc.ignoredFindings {
		data.IgnoredFindings = append(data.IgnoredFindings, key)
	}
	for file := range sc.ignoredFiles {
		data.IgnoredFiles = append(data.IgnoredFiles, file)
	}
	
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return
	}
	
	ignoreFile := filepath.Join(getConfigDir(), "ignore_list.json")
	_ = os.WriteFile(ignoreFile, jsonData, 0644)
}

// loadIgnoreList loads the ignore list from disk
func (sc *ScanController) loadIgnoreList() {
	ignoreFile := filepath.Join(getConfigDir(), "ignore_list.json")
	
	jsonData, err := os.ReadFile(ignoreFile)
	if err != nil {
		return
	}
	
	var data IgnoreListData
	if err := json.Unmarshal(jsonData, &data); err != nil {
		return
	}
	
	for _, key := range data.IgnoredFindings {
		sc.ignoredFindings[key] = true
	}
	for _, file := range data.IgnoredFiles {
		sc.ignoredFiles[file] = true
	}
}

// GetIgnoredCount returns the count of ignored items
func (sc *ScanController) GetIgnoredCount() (int, int) {
	return len(sc.ignoredFindings), len(sc.ignoredFiles)
}

// ClearIgnoreList clears all ignored items
func (sc *ScanController) ClearIgnoreList() {
	sc.ignoredFindings = make(map[string]bool)
	sc.ignoredFiles = make(map[string]bool)
	sc.saveIgnoreList()
}

// EncryptionConfig holds configuration for file encryption
type EncryptionConfig struct {
	Password          string
	OutputPath        string
	DeleteOriginals   bool
	DeletePasses      int  // Number of secure deletion passes (default: 3)
	CompressionLevel  int  // 0-9, default 6
	UseAES256         bool // default true
}

// EncryptionProgress represents encryption progress
type EncryptionProgress struct {
	BytesProcessed int64
	TotalBytes     int64
	CurrentFile    string
	Percentage     float64
}

// EncryptionResult represents the result of an encryption operation
type EncryptionResult struct {
	OutputPath       string
	FilesEncrypted   int
	TotalSize        int64
	ArchiveSize      int64
	CompressionRatio float64
	FilesDeleted     int
}

// EncryptFiles encrypts the specified files into a password-protected ZIP archive
func (sc *ScanController) EncryptFiles(
	filePaths []string,
	config EncryptionConfig,
	onProgress func(EncryptionProgress),
) (*EncryptionResult, error) {
	sc.log(LogInfo, "Starting encryption of "+string(rune('0'+len(filePaths)))+" files")

	// Validate password
	if err := encryptor.ValidatePassword(config.Password); err != nil {
		return nil, err
	}

	// Build file entries
	var entries []encryptor.FileEntry
	for _, path := range filePaths {
		entries = append(entries, encryptor.FileEntry{SourcePath: path})
	}

	// Configure encryptor
	encConfig := encryptor.DefaultConfig()
	encConfig.Password = config.Password
	encConfig.OutputPath = config.OutputPath
	encConfig.CompressionLevel = config.CompressionLevel
	if encConfig.CompressionLevel == 0 {
		encConfig.CompressionLevel = 6
	}

	if config.UseAES256 {
		encConfig.Method = encryptor.AES256
	}

	// Set up progress callback
	if onProgress != nil {
		encConfig.OnProgress = func(bytesProcessed, totalBytes int64, currentFile string) {
			var pct float64
			if totalBytes > 0 {
				pct = float64(bytesProcessed) / float64(totalBytes) * 100
			}
			onProgress(EncryptionProgress{
				BytesProcessed: bytesProcessed,
				TotalBytes:     totalBytes,
				CurrentFile:    currentFile,
				Percentage:     pct,
			})
		}
	}

	// Create encryptor
	enc, err := encryptor.NewEncryptor(encConfig)
	if err != nil {
		sc.log(LogError, "Failed to create encryptor: "+err.Error())
		return nil, err
	}

	// Run encryption
	result, err := enc.EncryptFilesWithResult(entries)
	if err != nil {
		sc.log(LogError, "Encryption failed: "+err.Error())
		return nil, err
	}

	sc.log(LogInfo, "Encryption completed: "+result.OutputPath)

	encResult := &EncryptionResult{
		OutputPath:       result.OutputPath,
		FilesEncrypted:   result.FilesEncrypted,
		TotalSize:        result.TotalSize,
		ArchiveSize:      result.ArchiveSize,
		CompressionRatio: result.CompressionRatio,
	}

	// Delete originals if requested
	if config.DeleteOriginals {
		passes := config.DeletePasses
		if passes <= 0 {
			passes = 3
		}

		sc.log(LogInfo, "Securely deleting original files...")

		err := encryptor.SecureDeleteMultiple(filePaths, passes, func(current, total int, path string) {
			sc.log(LogInfo, "Deleting: "+filepath.Base(path))
		})

		if err != nil {
			sc.log(LogWarning, "Some files could not be deleted: "+err.Error())
		} else {
			encResult.FilesDeleted = len(filePaths)
			sc.log(LogInfo, "Original files securely deleted")
		}
	}

	return encResult, nil
}

// GenerateSecurePassword generates a cryptographically secure password
func (sc *ScanController) GenerateSecurePassword(length int, alphanumericOnly bool) (string, error) {
	if alphanumericOnly {
		return encryptor.GenerateAlphanumericPassword(length)
	}
	return encryptor.GeneratePassword(length)
}

// ValidateEncryptionPassword validates a password for encryption
func (sc *ScanController) ValidateEncryptionPassword(password string) error {
	return encryptor.ValidatePassword(password)
}

// GetUniqueFilePaths extracts unique file paths from findings
func (sc *ScanController) GetUniqueFilePaths(findings []*searcher.Finding) []string {
	seen := make(map[string]bool)
	var paths []string

	for _, f := range findings {
		if !seen[f.FilePath] {
			seen[f.FilePath] = true
			paths = append(paths, f.FilePath)
		}
	}

	return paths
}

