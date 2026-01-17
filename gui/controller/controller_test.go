package controller

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/kacebover/password-finder/searcher"
)

// MockScanner provides a mock implementation for testing
type MockScanner struct {
	findings      []*searcher.Finding
	eventChan     chan searcher.ScanEvent
	pauseCalled   bool
	resumeCalled  bool
	cancelCalled  bool
	scanDuration  time.Duration
}

func NewMockScanner() *MockScanner {
	return &MockScanner{
		findings:     make([]*searcher.Finding, 0),
		eventChan:    make(chan searcher.ScanEvent, 100),
		scanDuration: 100 * time.Millisecond,
	}
}

func (m *MockScanner) AddMockFinding(finding *searcher.Finding) {
	m.findings = append(m.findings, finding)
}

// TestScanController_NewController tests controller creation
func TestScanController_NewController(t *testing.T) {
	ctrl := NewScanController()
	
	if ctrl == nil {
		t.Fatal("NewScanController returned nil")
	}
	
	if ctrl.config == nil {
		t.Error("Controller config is nil")
	}
	
	if ctrl.ignoredFindings == nil {
		t.Error("Controller ignoredFindings map is nil")
	}
	
	if ctrl.ignoredFiles == nil {
		t.Error("Controller ignoredFiles map is nil")
	}
}

// TestScanController_Config tests configuration management
func TestScanController_Config(t *testing.T) {
	ctrl := NewScanController()
	
	config := ctrl.GetConfig()
	if config == nil {
		t.Fatal("GetConfig returned nil")
	}
	
	// Modify config
	config.Concurrency = 4
	config.MaxFileSize = 50 * 1024 * 1024
	
	err := ctrl.UpdateConfig(config)
	if err != nil {
		t.Errorf("UpdateConfig failed: %v", err)
	}
	
	// Verify config was updated
	newConfig := ctrl.GetConfig()
	if newConfig.Concurrency != 4 {
		t.Errorf("Concurrency not updated: got %d", newConfig.Concurrency)
	}
}

// TestScanController_Callbacks tests callback registration
func TestScanController_Callbacks(t *testing.T) {
	ctrl := NewScanController()
	
	ctrl.SetOnFinding(func(f *searcher.Finding) {
		// callback registered
	})
	
	ctrl.SetOnProgress(func(p searcher.ScanProgress) {
		// callback registered
	})
	
	ctrl.SetOnLogMessage(func(level LogLevel, msg string) {
		// callback registered
	})
	
	ctrl.SetOnStateChange(func(state searcher.ScanState) {
		// callback registered
	})
	
	ctrl.SetOnComplete(func(result *searcher.ScanResult, err error) {
		// callback registered
	})
	
	// Verify callbacks are set (by checking they're not nil internally)
	if ctrl.onFinding == nil {
		t.Error("onFinding callback not set")
	}
	if ctrl.onProgress == nil {
		t.Error("onProgress callback not set")
	}
	if ctrl.onLogMessage == nil {
		t.Error("onLogMessage callback not set")
	}
	if ctrl.onStateChange == nil {
		t.Error("onStateChange callback not set")
	}
	if ctrl.onComplete == nil {
		t.Error("onComplete callback not set")
	}
}

// TestScanController_StartScan tests starting a scan
func TestScanController_StartScan(t *testing.T) {
	ctrl := NewScanController()
	
	// Create temp dir with test file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	os.WriteFile(testFile, []byte("password=secret123"), 0644)
	
	var wg sync.WaitGroup
	var completed bool
	
	ctrl.SetOnComplete(func(result *searcher.ScanResult, err error) {
		completed = true
		wg.Done()
	})
	
	wg.Add(1)
	err := ctrl.StartScan(tempDir)
	if err != nil {
		t.Errorf("StartScan failed: %v", err)
	}
	
	// Wait for completion with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		// Good
	case <-time.After(10 * time.Second):
		t.Error("Scan timed out")
	}
	
	if !completed {
		t.Error("Scan did not complete")
	}
}

// TestScanController_IgnoreList tests ignore list functionality
func TestScanController_IgnoreList(t *testing.T) {
	ctrl := NewScanController()
	
	// Create a mock finding
	finding := &searcher.Finding{
		FilePath:    "/test/path/file.txt",
		LineNumber:  10,
		PatternType: "password",
	}
	
	// Initially not ignored
	ignoredFindings, ignoredFiles := ctrl.GetIgnoredCount()
	if ignoredFindings != 0 || ignoredFiles != 0 {
		t.Errorf("Expected 0 ignored items, got %d findings, %d files", ignoredFindings, ignoredFiles)
	}
	
	// Ignore the finding
	ctrl.IgnoreFinding(finding)
	
	ignoredFindings, _ = ctrl.GetIgnoredCount()
	if ignoredFindings == 0 {
		t.Error("Expected finding to be ignored")
	}
	
	// Ignore a file
	ctrl.IgnoreFile("/test/path/other.txt")
	
	_, ignoredFiles = ctrl.GetIgnoredCount()
	if ignoredFiles == 0 {
		t.Error("Expected file to be ignored")
	}
	
	// Clear ignore list
	ctrl.ClearIgnoreList()
	
	ignoredFindings, ignoredFiles = ctrl.GetIgnoredCount()
	if ignoredFindings != 0 || ignoredFiles != 0 {
		t.Error("Expected ignore list to be cleared")
	}
}

// TestScanController_ExportResults tests result export
func TestScanController_ExportResults(t *testing.T) {
	ctrl := NewScanController()
	
	// Create temp dir with test file
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "test.txt")
	os.WriteFile(testFile, []byte("password=secret123"), 0644)
	
	// Run a scan first
	var wg sync.WaitGroup
	wg.Add(1)
	ctrl.SetOnComplete(func(result *searcher.ScanResult, err error) {
		wg.Done()
	})
	
	ctrl.StartScan(tempDir)
	wg.Wait()
	
	// Export results
	exportDir := t.TempDir()
	err := ctrl.ExportAll(exportDir)
	if err != nil {
		t.Errorf("ExportAll failed: %v", err)
	}
	
	// Check for exported files
	files, _ := filepath.Glob(filepath.Join(exportDir, "*.json"))
	if len(files) == 0 {
		t.Log("Warning: No JSON export file found")
	}
	
	csvFiles, _ := filepath.Glob(filepath.Join(exportDir, "*.csv"))
	if len(csvFiles) == 0 {
		t.Log("Warning: No CSV export file found")
	}
}

// TestScanController_StateTracking tests state management
func TestScanController_StateTracking(t *testing.T) {
	ctrl := NewScanController()
	
	// Initially not scanning
	if ctrl.IsScanning() {
		t.Error("Should not be scanning initially")
	}
	if ctrl.IsPaused() {
		t.Error("Should not be paused initially")
	}
	
	// Create temp dir
	tempDir := t.TempDir()
	for i := 0; i < 10; i++ {
		testFile := filepath.Join(tempDir, "test"+string(rune('0'+i))+".txt")
		os.WriteFile(testFile, []byte("password=secret"), 0644)
	}
	
	var scanStarted bool
	ctrl.SetOnStateChange(func(state searcher.ScanState) {
		if state == searcher.StateRunning {
			scanStarted = true
		}
	})
	
	var wg sync.WaitGroup
	wg.Add(1)
	ctrl.SetOnComplete(func(result *searcher.ScanResult, err error) {
		wg.Done()
	})
	
	ctrl.StartScan(tempDir)
	
	// Should be scanning
	time.Sleep(10 * time.Millisecond)
	if scanStarted {
		t.Log("Scan started successfully")
	}
	
	wg.Wait()
	
	// Should not be scanning after completion
	if ctrl.IsScanning() {
		t.Error("Should not be scanning after completion")
	}
}

// TestScanController_CancelScan tests scan cancellation
func TestScanController_CancelScan(t *testing.T) {
	ctrl := NewScanController()
	
	// Create temp dir with many files
	tempDir := t.TempDir()
	for i := 0; i < 100; i++ {
		testFile := filepath.Join(tempDir, "test"+string(rune('a'+i%26))+string(rune('0'+i/26))+".txt")
		os.WriteFile(testFile, []byte("password=secret"+string(rune('0'+i%10))), 0644)
	}
	
	var completed bool
	var wg sync.WaitGroup
	wg.Add(1)
	ctrl.SetOnComplete(func(result *searcher.ScanResult, err error) {
		completed = true
		wg.Done()
	})
	
	// Start scan
	ctrl.StartScan(tempDir)
	
	// Cancel after short delay
	time.Sleep(10 * time.Millisecond)
	ctrl.CancelScan()
	
	// Wait for completion
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		// Good
	case <-time.After(5 * time.Second):
		t.Error("Cancel did not complete in time")
	}
	
	if !completed {
		t.Error("OnComplete callback not called after cancel")
	}
}

// TestScanController_Progress tests progress tracking
func TestScanController_Progress(t *testing.T) {
	ctrl := NewScanController()
	
	// Create temp dir with test files
	tempDir := t.TempDir()
	for i := 0; i < 5; i++ {
		testFile := filepath.Join(tempDir, "test"+string(rune('0'+i))+".txt")
		os.WriteFile(testFile, []byte("password=secret"), 0644)
	}
	
	var lastProgress searcher.ScanProgress
	var progressUpdates int
	var mu sync.Mutex
	
	ctrl.SetOnProgress(func(p searcher.ScanProgress) {
		mu.Lock()
		lastProgress = p
		progressUpdates++
		mu.Unlock()
	})
	
	var wg sync.WaitGroup
	wg.Add(1)
	ctrl.SetOnComplete(func(result *searcher.ScanResult, err error) {
		wg.Done()
	})
	
	ctrl.StartScan(tempDir)
	wg.Wait()
	
	mu.Lock()
	updates := progressUpdates
	progress := lastProgress
	mu.Unlock()
	
	t.Logf("Received %d progress updates", updates)
	t.Logf("Final progress: %+v", progress)
}

// TestAppConfig_DefaultConfig tests default configuration
func TestAppConfig_DefaultConfig(t *testing.T) {
	config := DefaultConfig()
	
	if config.MaxFileSize <= 0 {
		t.Error("MaxFileSize should be positive")
	}
	
	if config.Concurrency <= 0 {
		t.Error("Concurrency should be positive")
	}
	
	if config.WindowWidth <= 0 || config.WindowHeight <= 0 {
		t.Error("Window dimensions should be positive")
	}
}

// TestAppConfig_Validate tests configuration validation
func TestAppConfig_Validate(t *testing.T) {
	config := &AppConfig{
		MaxFileSize: 0,
		Concurrency: 0,
		WindowWidth: 100,
		WindowHeight: 100,
	}
	
	config.ValidateConfig()
	
	if config.MaxFileSize < 1024 {
		t.Error("MaxFileSize should be at least 1KB after validation")
	}
	
	if config.Concurrency < 1 {
		t.Error("Concurrency should be at least 1 after validation")
	}
	
	if config.WindowWidth < 800 {
		t.Error("WindowWidth should be at least 800 after validation")
	}
}

// TestAppConfig_Clone tests configuration cloning
func TestAppConfig_Clone(t *testing.T) {
	config := DefaultConfig()
	config.ExcludeExtensions = []string{".exe", ".dll"}
	config.ExcludeDirs = []string{"node_modules"}
	
	clone := config.Clone()
	
	// Modify original
	config.ExcludeExtensions[0] = ".so"
	config.Concurrency = 100
	
	// Clone should be unchanged
	if clone.ExcludeExtensions[0] != ".exe" {
		t.Error("Clone should have independent slice")
	}
	
	if clone.Concurrency == 100 {
		t.Error("Clone should have independent values")
	}
}

// TestAppConfig_RecentDirs tests recent directories management
func TestAppConfig_RecentDirs(t *testing.T) {
	config := DefaultConfig()
	
	// Add directories
	config.AddRecentDir("/path/one")
	config.AddRecentDir("/path/two")
	config.AddRecentDir("/path/three")
	
	if len(config.RecentDirs) != 3 {
		t.Errorf("Expected 3 recent dirs, got %d", len(config.RecentDirs))
	}
	
	// Most recent should be first
	if config.RecentDirs[0] != "/path/three" {
		t.Error("Most recent dir should be first")
	}
	
	// Adding duplicate should move to front
	config.AddRecentDir("/path/one")
	if config.RecentDirs[0] != "/path/one" {
		t.Error("Duplicate should move to front")
	}
	if len(config.RecentDirs) != 3 {
		t.Error("Duplicate should not increase count")
	}
	
	// Add more than 10 to test limit
	for i := 0; i < 15; i++ {
		config.AddRecentDir("/path/dir" + string(rune('0'+i)))
	}
	
	if len(config.RecentDirs) > 10 {
		t.Error("Recent dirs should be limited to 10")
	}
}

// TestFormatFileSize tests file size formatting
func TestFormatFileSize(t *testing.T) {
	tests := []struct {
		bytes    int64
		expected string
	}{
		{0, "0 B"},
		{100, "100 B"},
		{1024, "1 KB"},
		{1536, "1.50 KB"},
		{1048576, "1 MB"},
		{1073741824, "1 GB"},
	}
	
	for _, tt := range tests {
		result := FormatFileSize(tt.bytes)
		if result != tt.expected {
			t.Errorf("FormatFileSize(%d) = %q, expected %q", tt.bytes, result, tt.expected)
		}
	}
}

// TestParseFileSize tests file size parsing
func TestParseFileSize(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
	}{
		{"100", 100},
		{"100KB", 100 * 1024},
		{"100MB", 100 * 1024 * 1024},
		{"1GB", 1024 * 1024 * 1024},
	}
	
	for _, tt := range tests {
		result := ParseFileSize(tt.input)
		if result != tt.expected {
			t.Errorf("ParseFileSize(%q) = %d, expected %d", tt.input, result, tt.expected)
		}
	}
}

// BenchmarkScanController_StartScan benchmarks scan startup
func BenchmarkScanController_StartScan(b *testing.B) {
	tempDir := b.TempDir()
	for i := 0; i < 10; i++ {
		testFile := filepath.Join(tempDir, "test"+string(rune('0'+i))+".txt")
		os.WriteFile(testFile, []byte("password=secret"), 0644)
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		ctrl := NewScanController()
		var wg sync.WaitGroup
		wg.Add(1)
		ctrl.SetOnComplete(func(result *searcher.ScanResult, err error) {
			wg.Done()
		})
		ctrl.StartScan(tempDir)
		wg.Wait()
	}
}

// ═══════════════════════════════════════════════════════════════════════════
// ENCRYPTION TESTS
// ═══════════════════════════════════════════════════════════════════════════

// TestScanController_GenerateSecurePassword tests password generation
func TestScanController_GenerateSecurePassword(t *testing.T) {
	ctrl := NewScanController()

	tests := []struct {
		name            string
		length          int
		alphanumericOnly bool
	}{
		{"Standard 16 chars", 16, false},
		{"Long 32 chars", 32, false},
		{"Short 8 chars (minimum)", 4, false}, // Should be at least 8
		{"Alphanumeric 16", 16, true},
		{"Alphanumeric 24", 24, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pwd, err := ctrl.GenerateSecurePassword(tt.length, tt.alphanumericOnly)
			if err != nil {
				t.Fatalf("GenerateSecurePassword failed: %v", err)
			}

			expectedLen := tt.length
			if expectedLen < 8 {
				expectedLen = 8 // Minimum enforced
			}
			if len(pwd) != expectedLen {
				t.Errorf("Password length = %d, want %d", len(pwd), expectedLen)
			}

			if tt.alphanumericOnly {
				for _, c := range pwd {
					isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
					isNum := c >= '0' && c <= '9'
					if !isAlpha && !isNum {
						t.Errorf("Alphanumeric password contains invalid char: %c", c)
					}
				}
			}
		})
	}
}

// TestScanController_GenerateSecurePassword_Uniqueness tests password randomness
func TestScanController_GenerateSecurePassword_Uniqueness(t *testing.T) {
	ctrl := NewScanController()
	
	passwords := make(map[string]bool)
	for i := 0; i < 100; i++ {
		pwd, err := ctrl.GenerateSecurePassword(16, false)
		if err != nil {
			t.Fatalf("GenerateSecurePassword failed: %v", err)
		}
		if passwords[pwd] {
			t.Error("Generated duplicate password")
		}
		passwords[pwd] = true
	}
}

// TestScanController_ValidateEncryptionPassword tests password validation
func TestScanController_ValidateEncryptionPassword(t *testing.T) {
	ctrl := NewScanController()

	tests := []struct {
		password string
		wantErr  bool
	}{
		{"", true},
		{"abc", true},
		{"abcd", false},
		{"password123", false},
		{"P@ssw0rd!#$%", false},
		{"a very long password with spaces and 特殊字符", false},
	}

	for _, tt := range tests {
		err := ctrl.ValidateEncryptionPassword(tt.password)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidateEncryptionPassword(%q) error = %v, wantErr %v",
				tt.password, err, tt.wantErr)
		}
	}
}

// TestScanController_EncryptFiles tests the encryption functionality
func TestScanController_EncryptFiles(t *testing.T) {
	ctrl := NewScanController()
	tmpDir := t.TempDir()

	// Create test files
	testFiles := []string{
		filepath.Join(tmpDir, "secret1.txt"),
		filepath.Join(tmpDir, "secret2.txt"),
	}

	for i, f := range testFiles {
		content := []byte("sensitive content #" + string(rune('1'+i)))
		if err := os.WriteFile(f, content, 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	config := EncryptionConfig{
		Password:         "TestPassword123!",
		OutputPath:       filepath.Join(tmpDir, "encrypted.zip"),
		DeleteOriginals:  false,
		CompressionLevel: 6,
		UseAES256:        true,
	}

	result, err := ctrl.EncryptFiles(testFiles, config, nil)
	if err != nil {
		t.Fatalf("EncryptFiles failed: %v", err)
	}

	// Verify result
	if result.FilesEncrypted != 2 {
		t.Errorf("FilesEncrypted = %d, want 2", result.FilesEncrypted)
	}

	if result.OutputPath != config.OutputPath {
		t.Errorf("OutputPath = %s, want %s", result.OutputPath, config.OutputPath)
	}

	// Verify archive exists
	if _, err := os.Stat(result.OutputPath); os.IsNotExist(err) {
		t.Error("Archive was not created")
	}

	// Verify archive is not empty
	info, _ := os.Stat(result.OutputPath)
	if info.Size() == 0 {
		t.Error("Archive is empty")
	}
}

// TestScanController_EncryptFiles_WithProgress tests progress reporting
func TestScanController_EncryptFiles_WithProgress(t *testing.T) {
	ctrl := NewScanController()
	tmpDir := t.TempDir()

	// Create larger test file
	testFile := filepath.Join(tmpDir, "large.txt")
	content := make([]byte, 50000) // 50KB
	for i := range content {
		content[i] = byte(i % 256)
	}
	if err := os.WriteFile(testFile, content, 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	config := EncryptionConfig{
		Password:   "TestPassword123!",
		OutputPath: filepath.Join(tmpDir, "progress.zip"),
		UseAES256:  true,
	}

	var progressCalls int
	var lastPercentage float64
	var mu sync.Mutex

	_, err := ctrl.EncryptFiles([]string{testFile}, config, func(progress EncryptionProgress) {
		mu.Lock()
		defer mu.Unlock()
		progressCalls++
		if progress.Percentage < lastPercentage {
			t.Errorf("Progress decreased: %f -> %f", lastPercentage, progress.Percentage)
		}
		lastPercentage = progress.Percentage
	})

	if err != nil {
		t.Fatalf("EncryptFiles failed: %v", err)
	}

	mu.Lock()
	calls := progressCalls
	mu.Unlock()

	if calls == 0 {
		t.Error("Progress callback was never called")
	}
}

// TestScanController_EncryptFiles_WithDeletion tests secure deletion
func TestScanController_EncryptFiles_WithDeletion(t *testing.T) {
	ctrl := NewScanController()
	tmpDir := t.TempDir()

	testFile := filepath.Join(tmpDir, "to_delete.txt")
	if err := os.WriteFile(testFile, []byte("delete me"), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	config := EncryptionConfig{
		Password:        "TestPassword123!",
		OutputPath:      filepath.Join(tmpDir, "encrypted.zip"),
		DeleteOriginals: true,
		DeletePasses:    1, // 1 pass for faster test
		UseAES256:       true,
	}

	result, err := ctrl.EncryptFiles([]string{testFile}, config, nil)
	if err != nil {
		t.Fatalf("EncryptFiles failed: %v", err)
	}

	// Verify file was deleted
	if _, err := os.Stat(testFile); !os.IsNotExist(err) {
		t.Error("Original file should be deleted")
	}

	if result.FilesDeleted != 1 {
		t.Errorf("FilesDeleted = %d, want 1", result.FilesDeleted)
	}
}

// TestScanController_EncryptFiles_InvalidPassword tests error handling
func TestScanController_EncryptFiles_InvalidPassword(t *testing.T) {
	ctrl := NewScanController()
	tmpDir := t.TempDir()

	testFile := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(testFile, []byte("content"), 0644)

	config := EncryptionConfig{
		Password:   "", // Empty password
		OutputPath: filepath.Join(tmpDir, "encrypted.zip"),
	}

	_, err := ctrl.EncryptFiles([]string{testFile}, config, nil)
	if err == nil {
		t.Error("Expected error for empty password")
	}
}

// TestScanController_EncryptFiles_MissingFiles tests error handling
func TestScanController_EncryptFiles_MissingFiles(t *testing.T) {
	ctrl := NewScanController()
	tmpDir := t.TempDir()

	config := EncryptionConfig{
		Password:   "TestPassword123!",
		OutputPath: filepath.Join(tmpDir, "encrypted.zip"),
	}

	_, err := ctrl.EncryptFiles([]string{"/nonexistent/file.txt"}, config, nil)
	if err == nil {
		t.Error("Expected error for missing file")
	}
}

// TestScanController_GetUniqueFilePaths tests unique path extraction
func TestScanController_GetUniqueFilePaths(t *testing.T) {
	ctrl := NewScanController()

	findings := []*searcher.Finding{
		{FilePath: "/path/a.txt"},
		{FilePath: "/path/b.txt"},
		{FilePath: "/path/a.txt"}, // Duplicate
		{FilePath: "/path/c.txt"},
		{FilePath: "/path/b.txt"}, // Duplicate
	}

	paths := ctrl.GetUniqueFilePaths(findings)

	if len(paths) != 3 {
		t.Errorf("Expected 3 unique paths, got %d", len(paths))
	}

	// Verify no duplicates
	seen := make(map[string]bool)
	for _, p := range paths {
		if seen[p] {
			t.Errorf("Duplicate path in result: %s", p)
		}
		seen[p] = true
	}
}

// TestScanController_GetUniqueFilePaths_Empty tests empty input
func TestScanController_GetUniqueFilePaths_Empty(t *testing.T) {
	ctrl := NewScanController()

	paths := ctrl.GetUniqueFilePaths([]*searcher.Finding{})
	if len(paths) != 0 {
		t.Errorf("Expected 0 paths for empty input, got %d", len(paths))
	}

	paths = ctrl.GetUniqueFilePaths(nil)
	if len(paths) != 0 {
		t.Errorf("Expected 0 paths for nil input, got %d", len(paths))
	}
}

// TestEncryptionConfig tests encryption config structure
func TestEncryptionConfig(t *testing.T) {
	config := EncryptionConfig{
		Password:         "test",
		OutputPath:       "/tmp/test.zip",
		DeleteOriginals:  true,
		DeletePasses:     5,
		CompressionLevel: 9,
		UseAES256:        true,
	}

	if config.DeletePasses != 5 {
		t.Errorf("DeletePasses = %d, want 5", config.DeletePasses)
	}
	if config.CompressionLevel != 9 {
		t.Errorf("CompressionLevel = %d, want 9", config.CompressionLevel)
	}
}

// TestEncryptionResult tests encryption result structure
func TestEncryptionResult(t *testing.T) {
	result := EncryptionResult{
		OutputPath:       "/tmp/test.zip",
		FilesEncrypted:   5,
		TotalSize:        10000,
		ArchiveSize:      8000,
		CompressionRatio: 0.8,
		FilesDeleted:     3,
	}

	if result.FilesEncrypted != 5 {
		t.Errorf("FilesEncrypted = %d, want 5", result.FilesEncrypted)
	}
	if result.CompressionRatio != 0.8 {
		t.Errorf("CompressionRatio = %f, want 0.8", result.CompressionRatio)
	}
}

// BenchmarkGeneratePassword benchmarks password generation
func BenchmarkGeneratePassword(b *testing.B) {
	ctrl := NewScanController()
	for i := 0; i < b.N; i++ {
		_, _ = ctrl.GenerateSecurePassword(16, false)
	}
}

// BenchmarkEncryptFiles benchmarks file encryption
func BenchmarkEncryptFiles(b *testing.B) {
	ctrl := NewScanController()
	tmpDir := b.TempDir()

	// Create test file
	testFile := filepath.Join(tmpDir, "bench.txt")
	content := make([]byte, 100000) // 100KB
	os.WriteFile(testFile, content, 0644)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		outputPath := filepath.Join(tmpDir, "bench_"+string(rune('0'+i%10))+".zip")
		config := EncryptionConfig{
			Password:   "BenchPassword123!",
			OutputPath: outputPath,
			UseAES256:  true,
		}
		ctrl.EncryptFiles([]string{testFile}, config, nil)
		os.Remove(outputPath)
	}
}

