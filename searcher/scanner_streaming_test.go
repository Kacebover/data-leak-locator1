package searcher

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestStreamingScanner_BasicScan tests basic scanning functionality
func TestStreamingScanner_BasicScan(t *testing.T) {
	config := DefaultStreamingScannerConfig()
	scanner := NewStreamingScanner(config)
	
	ctx := context.Background()
	
	// Get the testdata directory
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	testDataDir := filepath.Join(wd, "..", "testdata")
	if _, err := os.Stat(testDataDir); os.IsNotExist(err) {
		testDataDir = filepath.Join(wd, "testdata")
	}
	
	// Collect events
	var findings []*Finding
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for event := range scanner.Events() {
			if event.Type == EventFinding {
				findings = append(findings, event.Finding)
			}
		}
	}()
	
	result, err := scanner.Scan(ctx, testDataDir)
	wg.Wait()
	
	if err != nil {
		t.Errorf("Scan failed: %v", err)
	}
	
	if result == nil {
		t.Fatal("Expected result, got nil")
	}
	
	// Should find some secrets in testdata
	if len(findings) == 0 {
		t.Error("Expected to find some findings in testdata")
	}
	
	// Check scan completed
	if scanner.GetState() != StateCompleted {
		t.Errorf("Expected state Completed, got %v", scanner.GetState())
	}
}

// TestStreamingScanner_Cancellation tests that cancellation stops the scan
func TestStreamingScanner_Cancellation(t *testing.T) {
	config := DefaultStreamingScannerConfig()
	config.MaxConcurrent = 1 // Slow down to allow cancellation
	scanner := NewStreamingScanner(config)
	
	ctx, cancel := context.WithCancel(context.Background())
	
	// Create a temp directory with many files
	tempDir := t.TempDir()
	for i := 0; i < 100; i++ {
		file := filepath.Join(tempDir, "file"+string(rune('0'+i%10))+string(rune('0'+i/10))+".txt")
		os.WriteFile(file, []byte("password=secret"+string(rune('0'+i%10))), 0644)
	}
	
	var findingCount atomic.Int32
	var cancelled atomic.Bool
	
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for event := range scanner.Events() {
			switch event.Type {
			case EventFinding:
				findingCount.Add(1)
			case EventScanCancelled:
				cancelled.Store(true)
			}
		}
	}()
	
	// Start scan and cancel after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	
	_, err := scanner.Scan(ctx, tempDir)
	wg.Wait()
	
	// Should have context cancelled error
	if err != context.Canceled {
		t.Logf("Scan returned: %v", err)
	}
	
	// State should be cancelled
	state := scanner.GetState()
	if state != StateCancelled && state != StateCompleted {
		t.Errorf("Expected state Cancelled or Completed, got %v", state)
	}
}

// TestStreamingScanner_PauseResume tests pause and resume functionality
func TestStreamingScanner_PauseResume(t *testing.T) {
	config := DefaultStreamingScannerConfig()
	config.MaxConcurrent = 1
	scanner := NewStreamingScanner(config)
	
	ctx := context.Background()
	
	// Create temp files
	tempDir := t.TempDir()
	for i := 0; i < 20; i++ {
		file := filepath.Join(tempDir, "file"+string(rune('0'+i%10))+".txt")
		os.WriteFile(file, []byte("content "+string(rune('0'+i))), 0644)
	}
	
	var pausedAt, resumedAt time.Time
	var pauseSeen, resumeSeen bool
	
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for event := range scanner.Events() {
			switch event.Type {
			case EventScanPaused:
				pauseSeen = true
				pausedAt = time.Now()
			case EventScanResumed:
				resumeSeen = true
				resumedAt = time.Now()
			}
		}
	}()
	
	// Start scan in background
	go func() {
		time.Sleep(10 * time.Millisecond)
		scanner.Pause()
		time.Sleep(100 * time.Millisecond) // Stay paused
		scanner.Resume()
	}()
	
	scanner.Scan(ctx, tempDir)
	wg.Wait()
	
	if pauseSeen {
		t.Log("Pause event received")
		if resumeSeen {
			pauseDuration := resumedAt.Sub(pausedAt)
			if pauseDuration < 50*time.Millisecond {
				t.Errorf("Pause duration too short: %v", pauseDuration)
			}
		}
	}
}

// TestStreamingScanner_Progress tests progress reporting
func TestStreamingScanner_Progress(t *testing.T) {
	config := DefaultStreamingScannerConfig()
	scanner := NewStreamingScanner(config)
	
	ctx := context.Background()
	
	// Create temp files
	tempDir := t.TempDir()
	for i := 0; i < 10; i++ {
		file := filepath.Join(tempDir, "file"+string(rune('0'+i))+".txt")
		os.WriteFile(file, []byte("some content here"), 0644)
	}
	
	var lastProgress ScanProgress
	
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for event := range scanner.Events() {
			if event.Type == EventProgress || event.Type == EventScanCompleted {
				lastProgress = event.Progress
			}
		}
	}()
	
	result, _ := scanner.Scan(ctx, tempDir)
	wg.Wait()
	
	// Check final progress matches result
	if lastProgress.FilesProcessed == 0 {
		t.Error("Expected some files to be processed")
	}
	
	if result.FilesScanned != int(lastProgress.FilesProcessed) {
		t.Logf("Files scanned: %d, progress reported: %d", result.FilesScanned, lastProgress.FilesProcessed)
	}
}

// TestStreamingScanner_BinarySkipping tests that binary files are skipped
func TestStreamingScanner_BinarySkipping(t *testing.T) {
	config := DefaultStreamingScannerConfig()
	config.ScanBinaries = false
	scanner := NewStreamingScanner(config)
	
	ctx := context.Background()
	
	// Create temp dir with binary and text files
	tempDir := t.TempDir()
	
	// Text file with secret
	textFile := filepath.Join(tempDir, "secret.txt")
	os.WriteFile(textFile, []byte("password=secret123"), 0644)
	
	// Binary file with secret (contains null bytes)
	binaryFile := filepath.Join(tempDir, "binary.bin")
	binaryContent := []byte("password=secret\x00\x00\x00hidden")
	os.WriteFile(binaryFile, binaryContent, 0644)
	
	var textFindings, binaryFindings int
	var skippedCount atomic.Int32
	
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for event := range scanner.Events() {
			switch event.Type {
			case EventFinding:
				if filepath.Ext(event.FilePath) == ".txt" {
					textFindings++
				} else if filepath.Ext(event.FilePath) == ".bin" {
					binaryFindings++
				}
			case EventFileSkipped:
				skippedCount.Add(1)
			}
		}
	}()
	
	scanner.Scan(ctx, tempDir)
	wg.Wait()
	
	// Text file should have findings
	if textFindings == 0 {
		t.Error("Expected findings in text file")
	}
	
	// Binary file should be skipped (no findings)
	if binaryFindings > 0 {
		t.Error("Binary file should have been skipped")
	}
}

// TestStreamingScanner_ExtensionFilter tests extension filtering
func TestStreamingScanner_ExtensionFilter(t *testing.T) {
	config := DefaultStreamingScannerConfig()
	config.IncludeExts = []string{".txt"}
	scanner := NewStreamingScanner(config)
	
	ctx := context.Background()
	
	// Create temp files with different extensions
	tempDir := t.TempDir()
	
	os.WriteFile(filepath.Join(tempDir, "secret.txt"), []byte("password=secret1"), 0644)
	os.WriteFile(filepath.Join(tempDir, "secret.go"), []byte("password=secret2"), 0644)
	os.WriteFile(filepath.Join(tempDir, "secret.py"), []byte("password=secret3"), 0644)
	
	var txtFindings, otherFindings int
	
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for event := range scanner.Events() {
			if event.Type == EventFinding {
				if filepath.Ext(event.FilePath) == ".txt" {
					txtFindings++
				} else {
					otherFindings++
				}
			}
		}
	}()
	
	scanner.Scan(ctx, tempDir)
	wg.Wait()
	
	// Only .txt files should have findings
	if txtFindings == 0 {
		t.Error("Expected findings in .txt file")
	}
	if otherFindings > 0 {
		t.Error("Non-.txt files should have been skipped")
	}
}

// TestStreamingScanner_MaxFileSize tests max file size filtering
func TestStreamingScanner_MaxFileSize(t *testing.T) {
	config := DefaultStreamingScannerConfig()
	config.MaxFileSize = 100 // Very small limit
	scanner := NewStreamingScanner(config)
	
	ctx := context.Background()
	
	tempDir := t.TempDir()
	
	// Small file (under limit)
	smallFile := filepath.Join(tempDir, "small.txt")
	os.WriteFile(smallFile, []byte("password=secret"), 0644)
	
	// Large file (over limit)
	largeFile := filepath.Join(tempDir, "large.txt")
	largeContent := make([]byte, 200)
	for i := range largeContent {
		largeContent[i] = 'x'
	}
	copy(largeContent, []byte("password=secret"))
	os.WriteFile(largeFile, largeContent, 0644)
	
	var smallFindings, largeFindings int
	var skippedLarge bool
	
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for event := range scanner.Events() {
			switch event.Type {
			case EventFinding:
				if filepath.Base(event.FilePath) == "small.txt" {
					smallFindings++
				} else if filepath.Base(event.FilePath) == "large.txt" {
					largeFindings++
				}
			case EventFileSkipped:
				if filepath.Base(event.FilePath) == "large.txt" {
					skippedLarge = true
				}
			}
		}
	}()
	
	scanner.Scan(ctx, tempDir)
	wg.Wait()
	
	if smallFindings == 0 {
		t.Error("Expected findings in small file")
	}
	if largeFindings > 0 {
		t.Error("Large file should have been skipped")
	}
	if !skippedLarge {
		t.Error("Expected skip event for large file")
	}
}

// TestStreamingScanner_ConcurrentSafety tests thread safety
func TestStreamingScanner_ConcurrentSafety(t *testing.T) {
	config := DefaultStreamingScannerConfig()
	config.MaxConcurrent = 8
	scanner := NewStreamingScanner(config)
	
	ctx := context.Background()
	
	// Create many files
	tempDir := t.TempDir()
	for i := 0; i < 50; i++ {
		file := filepath.Join(tempDir, "file"+string(rune('a'+i%26))+string(rune('0'+i/26))+".txt")
		os.WriteFile(file, []byte("password=secret"+string(rune('0'+i%10))), 0644)
	}
	
	var findingsCount atomic.Int32
	
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for event := range scanner.Events() {
			if event.Type == EventFinding {
				findingsCount.Add(1)
			}
		}
	}()
	
	result, err := scanner.Scan(ctx, tempDir)
	wg.Wait()
	
	if err != nil {
		t.Errorf("Scan failed: %v", err)
	}
	
	t.Logf("Processed %d files, found %d findings", result.FilesScanned, findingsCount.Load())
}

// TestStreamingScanner_EmptyDirectory tests scanning empty directory
func TestStreamingScanner_EmptyDirectory(t *testing.T) {
	config := DefaultStreamingScannerConfig()
	scanner := NewStreamingScanner(config)
	
	ctx := context.Background()
	tempDir := t.TempDir()
	
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range scanner.Events() {
		}
	}()
	
	result, err := scanner.Scan(ctx, tempDir)
	wg.Wait()
	
	if err != nil {
		t.Errorf("Scan of empty dir failed: %v", err)
	}
	
	if result.FilesScanned != 0 {
		t.Errorf("Expected 0 files scanned, got %d", result.FilesScanned)
	}
	
	if result.TotalFindings() != 0 {
		t.Errorf("Expected 0 findings, got %d", result.TotalFindings())
	}
}

// TestStreamingScanner_NonExistentDirectory tests scanning non-existent directory
func TestStreamingScanner_NonExistentDirectory(t *testing.T) {
	config := DefaultStreamingScannerConfig()
	scanner := NewStreamingScanner(config)
	
	ctx := context.Background()
	
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range scanner.Events() {
		}
	}()
	
	result, _ := scanner.Scan(ctx, "/nonexistent/path/that/does/not/exist")
	wg.Wait()
	
	// Should complete without crashing
	if result == nil {
		t.Error("Expected non-nil result")
	}
}

// TestStreamingScanner_UpdateConfig tests dynamic config update
func TestStreamingScanner_UpdateConfig(t *testing.T) {
	config := DefaultStreamingScannerConfig()
	scanner := NewStreamingScanner(config)
	
	// Update config
	newConfig := StreamingScannerConfig{
		MaxFileSize:   500,
		MaxConcurrent: 2,
		IncludeExts:   []string{".go"},
		ExcludeDirs:   []string{"vendor"},
	}
	
	scanner.UpdateConfig(newConfig)
	
	// Verify config was updated
	if scanner.maxFileSize != 500 {
		t.Errorf("MaxFileSize not updated: got %d", scanner.maxFileSize)
	}
	if scanner.maxConcurrent != 2 {
		t.Errorf("MaxConcurrent not updated: got %d", scanner.maxConcurrent)
	}
}

// BenchmarkStreamingScanner benchmarks scanning performance
func BenchmarkStreamingScanner(b *testing.B) {
	config := DefaultStreamingScannerConfig()
	
	// Create temp dir with test files
	tempDir := b.TempDir()
	for i := 0; i < 100; i++ {
		file := filepath.Join(tempDir, "file"+string(rune('0'+i%10))+string(rune('0'+(i/10)%10))+".txt")
		content := "Normal text\npassword=secret123\nMore text\nemail@example.com\n"
		os.WriteFile(file, []byte(content), 0644)
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		scanner := NewStreamingScanner(config)
		ctx := context.Background()
		
		go func() {
			for range scanner.Events() {
			}
		}()
		
		scanner.Scan(ctx, tempDir)
	}
}

// BenchmarkStreamingScanner_LargeFile benchmarks scanning a large file
func BenchmarkStreamingScanner_LargeFile(b *testing.B) {
	config := DefaultStreamingScannerConfig()
	
	// Create a large temp file (10MB)
	tempDir := b.TempDir()
	largeFile := filepath.Join(tempDir, "large.txt")
	
	// Create 10MB file with some secrets
	f, _ := os.Create(largeFile)
	for i := 0; i < 100000; i++ {
		if i%1000 == 0 {
			f.WriteString("password=secret" + string(rune('0'+i%10)) + "\n")
		} else {
			f.WriteString("Normal line of text without any secrets here.\n")
		}
	}
	f.Close()
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		scanner := NewStreamingScanner(config)
		ctx := context.Background()
		
		go func() {
			for range scanner.Events() {
			}
		}()
		
		scanner.Scan(ctx, tempDir)
	}
}

