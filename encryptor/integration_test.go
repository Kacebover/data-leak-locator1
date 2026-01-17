package encryptor

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alexmullins/zip"
)

// TestIntegrationFullWorkflow tests the complete encryption workflow
func TestIntegrationFullWorkflow(t *testing.T) {
	tmpDir := t.TempDir()

	// Step 1: Create a realistic directory structure with sensitive files
	sourceDir := filepath.Join(tmpDir, "sensitive_data")

	files := map[string]string{
		"credentials/database.env":      "DB_PASSWORD=super_secret_123\nDB_HOST=localhost",
		"credentials/api_keys.txt":      "API_KEY=sk-abc123xyz789\nSECRET_KEY=secret_value",
		"config/settings.json":          `{"password": "admin123", "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"}`,
		"logs/access.log":               "2024-01-01 User logged in with password: test123",
		"documents/report.txt":          "Confidential report with sensitive information",
		"documents/nested/deep/data.csv": "name,ssn\nJohn,123-45-6789\nJane,987-65-4321",
	}

	for path, content := range files {
		fullPath := filepath.Join(sourceDir, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			t.Fatalf("Failed to create directory: %v", err)
		}
		if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to create file: %v", err)
		}
	}

	// Step 2: Generate a secure password
	password, err := GeneratePassword(24)
	if err != nil {
		t.Fatalf("Failed to generate password: %v", err)
	}

	if err := ValidatePassword(password); err != nil {
		t.Fatalf("Generated password failed validation: %v", err)
	}

	// Step 3: Configure and run encryption
	outputPath := filepath.Join(tmpDir, "encrypted_backup.zip")

	var progressUpdates []float64
	var mu sync.Mutex

	config := DefaultConfig()
	config.Password = password
	config.OutputPath = outputPath
	config.Method = AES256
	config.CompressionLevel = 6
	config.PreserveStructure = true
	config.OnProgress = func(processed, total int64, currentFile string) {
		if total > 0 {
			mu.Lock()
			progressUpdates = append(progressUpdates, float64(processed)/float64(total)*100)
			mu.Unlock()
		}
	}

	enc, err := NewEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	result, err := enc.EncryptFilesWithResult([]FileEntry{{SourcePath: sourceDir}})
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Step 4: Verify result
	if result.FilesEncrypted != len(files) {
		t.Errorf("Expected %d files encrypted, got %d", len(files), result.FilesEncrypted)
	}

	if result.ArchiveSize == 0 {
		t.Error("Archive size should not be 0")
	}

	// Step 5: Verify archive can be opened and contents are correct
	reader, err := zip.OpenReader(outputPath)
	if err != nil {
		t.Fatalf("Failed to open ZIP: %v", err)
	}
	defer reader.Close()

	if len(reader.File) != len(files) {
		t.Errorf("Expected %d files in archive, got %d", len(files), len(reader.File))
	}

	for _, f := range reader.File {
		f.SetPassword(password)
		rc, err := f.Open()
		if err != nil {
			t.Errorf("Failed to open %s with correct password: %v", f.Name, err)
			continue
		}

		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Errorf("Failed to read %s: %v", f.Name, err)
			continue
		}

		// Find corresponding original content
		var originalContent string
		for path, c := range files {
			if strings.HasSuffix(f.Name, path) || strings.Contains(f.Name, strings.ReplaceAll(path, "/", string(os.PathSeparator))) {
				originalContent = c
				break
			}
		}

		if originalContent != "" && string(content) != originalContent {
			t.Errorf("Content mismatch for %s", f.Name)
		}
	}

	// Step 6: Verify wrong password fails
	for _, f := range reader.File {
		f.SetPassword("wrong_password")
		rc, err := f.Open()
		if err != nil {
			continue // Expected
		}

		_, err = io.ReadAll(rc)
		rc.Close()
		if err == nil {
			t.Errorf("Expected wrong password to fail for %s", f.Name)
		}
	}

	// Step 7: Verify progress was tracked
	mu.Lock()
	if len(progressUpdates) == 0 {
		t.Error("No progress updates received")
	}
	mu.Unlock()
}

// TestIntegrationConcurrentOperations tests thread safety
func TestIntegrationConcurrentOperations(t *testing.T) {
	tmpDir := t.TempDir()

	// Create shared test files
	var testFiles []string
	for i := 0; i < 5; i++ {
		path := filepath.Join(tmpDir, "shared_"+string(rune('a'+i))+".txt")
		os.WriteFile(path, []byte("Content "+string(rune('0'+i))), 0644)
		testFiles = append(testFiles, path)
	}

	// Run multiple encryptions concurrently
	var wg sync.WaitGroup
	var successCount int32
	numWorkers := 5

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			outputPath := filepath.Join(tmpDir, "output_"+string(rune('0'+workerID))+".zip")
			password := "Worker" + string(rune('0'+workerID)) + "Password!"

			config := DefaultConfig()
			config.Password = password
			config.OutputPath = outputPath

			enc, err := NewEncryptor(config)
			if err != nil {
				t.Errorf("Worker %d: failed to create encryptor: %v", workerID, err)
				return
			}

			var entries []FileEntry
			for _, f := range testFiles {
				entries = append(entries, FileEntry{SourcePath: f})
			}

			err = enc.EncryptFiles(entries)
			if err != nil {
				t.Errorf("Worker %d: encryption failed: %v", workerID, err)
				return
			}

			// Verify output
			reader, err := zip.OpenReader(outputPath)
			if err != nil {
				t.Errorf("Worker %d: failed to open ZIP: %v", workerID, err)
				return
			}
			reader.Close()

			atomic.AddInt32(&successCount, 1)
		}(i)
	}

	wg.Wait()

	if int(successCount) != numWorkers {
		t.Errorf("Expected %d successful encryptions, got %d", numWorkers, successCount)
	}
}

// TestIntegrationLargeFileWithProgress tests progress reporting for large files
func TestIntegrationLargeFileWithProgress(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large file test in short mode")
	}

	tmpDir := t.TempDir()

	// Create 20MB file
	largeFile := filepath.Join(tmpDir, "large.bin")
	file, _ := os.Create(largeFile)
	buf := make([]byte, 1024*1024) // 1MB buffer
	for i := 0; i < 20; i++ {
		rand.Read(buf)
		file.Write(buf)
	}
	file.Close()

	outputPath := filepath.Join(tmpDir, "large.zip")
	password := "LargeFileTest!"

	var lastProgress float64
	var progressIncreasing bool = true

	config := DefaultConfig()
	config.Password = password
	config.OutputPath = outputPath
	config.OnProgress = func(processed, total int64, currentFile string) {
		if total > 0 {
			progress := float64(processed) / float64(total) * 100
			if progress < lastProgress {
				progressIncreasing = false
			}
			lastProgress = progress
		}
	}

	enc, err := NewEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	err = enc.EncryptFiles([]FileEntry{{SourcePath: largeFile}})
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if !progressIncreasing {
		t.Error("Progress should always increase")
	}

	if lastProgress < 99 {
		t.Errorf("Final progress should be ~100%%, got %.1f%%", lastProgress)
	}
}

// TestIntegrationSecureDeleteAfterEncrypt tests encrypt-then-delete workflow
func TestIntegrationSecureDeleteAfterEncrypt(t *testing.T) {
	tmpDir := t.TempDir()

	// Create sensitive files
	sensitiveFiles := []string{
		filepath.Join(tmpDir, "secret1.txt"),
		filepath.Join(tmpDir, "secret2.txt"),
		filepath.Join(tmpDir, "secret3.txt"),
	}

	originalContents := make(map[string][]byte)
	for i, f := range sensitiveFiles {
		content := []byte("Sensitive content #" + string(rune('1'+i)))
		os.WriteFile(f, content, 0644)
		originalContents[f] = content
	}

	// Encrypt files
	outputPath := filepath.Join(tmpDir, "secrets.zip")
	password := "SecureDeleteTest!"

	config := DefaultConfig()
	config.Password = password
	config.OutputPath = outputPath

	enc, err := NewEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	var entries []FileEntry
	for _, f := range sensitiveFiles {
		entries = append(entries, FileEntry{SourcePath: f})
	}

	err = enc.EncryptFiles(entries)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify archive exists and is valid
	reader, err := zip.OpenReader(outputPath)
	if err != nil {
		t.Fatalf("Failed to open archive: %v", err)
	}
	reader.Close()

	// Securely delete original files
	var deletedFiles int
	err = SecureDeleteMultiple(sensitiveFiles, 3, func(current, total int, path string) {
		deletedFiles++
	})
	if err != nil {
		t.Fatalf("Secure delete failed: %v", err)
	}

	// Verify originals are gone
	for _, f := range sensitiveFiles {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("File %s should be deleted", f)
		}
	}

	// Verify archive still works
	reader, err = zip.OpenReader(outputPath)
	if err != nil {
		t.Fatalf("Failed to open archive after deletion: %v", err)
	}
	defer reader.Close()

	for _, f := range reader.File {
		f.SetPassword(password)
		rc, err := f.Open()
		if err != nil {
			t.Errorf("Failed to open %s: %v", f.Name, err)
			continue
		}

		content, _ := io.ReadAll(rc)
		rc.Close()

		// Verify content matches original
		for origPath, origContent := range originalContents {
			if strings.HasSuffix(origPath, f.Name) || strings.Contains(f.Name, filepath.Base(origPath)) {
				if !bytes.Equal(content, origContent) {
					t.Errorf("Content mismatch for %s", f.Name)
				}
			}
		}
	}
}

// TestIntegrationCancellationCleanup tests that cancellation cleans up properly
func TestIntegrationCancellationCleanup(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a larger file to ensure we have time to cancel
	largeFile := filepath.Join(tmpDir, "large.bin")
	file, _ := os.Create(largeFile)
	buf := make([]byte, 1024*1024)
	for i := 0; i < 10; i++ { // 10MB
		rand.Read(buf)
		file.Write(buf)
	}
	file.Close()

	outputPath := filepath.Join(tmpDir, "cancelled.zip")
	password := "CancelTest!"

	config := DefaultConfig()
	config.Password = password
	config.OutputPath = outputPath
	config.BufferSize = 4096 // Small buffer to slow things down

	enc, err := NewEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// Start encryption in goroutine
	done := make(chan error, 1)
	go func() {
		done <- enc.EncryptFiles([]FileEntry{{SourcePath: largeFile}})
	}()

	// Cancel after a short delay
	time.Sleep(50 * time.Millisecond)
	enc.Cancel()

	// Wait for completion
	err = <-done

	if err == nil {
		t.Error("Expected cancellation error")
	}

	// Verify partial file is cleaned up
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Error("Partial output file should be removed after cancellation")
	}

	// Original file should still exist
	if _, err := os.Stat(largeFile); os.IsNotExist(err) {
		t.Error("Original file should not be affected by cancellation")
	}
}

// TestIntegrationMixedFileTypes tests encryption of various file types
func TestIntegrationMixedFileTypes(t *testing.T) {
	tmpDir := t.TempDir()

	// Create files of different types
	files := map[string][]byte{
		"text.txt":   []byte("Plain text content"),
		"binary.bin": make([]byte, 1024),     // Random binary
		"empty.dat":  []byte{},               // Empty file
		"unicode.txt": []byte("Hello 世界 🌍"), // Unicode content
		"large.txt":  make([]byte, 100000),   // Larger file
	}

	// Fill random data
	rand.Read(files["binary.bin"])
	rand.Read(files["large.txt"])

	var entries []FileEntry
	for name, content := range files {
		path := filepath.Join(tmpDir, name)
		os.WriteFile(path, content, 0644)
		entries = append(entries, FileEntry{SourcePath: path})
	}

	outputPath := filepath.Join(tmpDir, "mixed.zip")
	password := "MixedTypes!"

	config := DefaultConfig()
	config.Password = password
	config.OutputPath = outputPath

	enc, err := NewEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	err = enc.EncryptFiles(entries)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// Verify all files
	reader, err := zip.OpenReader(outputPath)
	if err != nil {
		t.Fatalf("Failed to open ZIP: %v", err)
	}
	defer reader.Close()

	for _, f := range reader.File {
		f.SetPassword(password)
		rc, err := f.Open()
		if err != nil {
			t.Errorf("Failed to open %s: %v", f.Name, err)
			continue
		}

		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Errorf("Failed to read %s: %v", f.Name, err)
			continue
		}

		// Verify content matches
		originalContent, ok := files[f.Name]
		if ok && !bytes.Equal(content, originalContent) {
			t.Errorf("Content mismatch for %s: got %d bytes, want %d bytes",
				f.Name, len(content), len(originalContent))
		}
	}
}

// TestIntegrationErrorRecovery tests recovery from errors
func TestIntegrationErrorRecovery(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a valid file
	validFile := filepath.Join(tmpDir, "valid.txt")
	os.WriteFile(validFile, []byte("Valid content"), 0644)

	// Test 1: First operation fails (invalid output path)
	config := DefaultConfig()
	config.Password = "TestPassword!"
	config.OutputPath = "/nonexistent/directory/output.zip"

	enc, err := NewEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	err = enc.EncryptFiles([]FileEntry{{SourcePath: validFile}})
	if err == nil {
		t.Error("Expected error for invalid output path")
	}

	// Test 2: Subsequent operation with valid config should succeed
	config.OutputPath = filepath.Join(tmpDir, "valid_output.zip")

	enc, err = NewEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	err = enc.EncryptFiles([]FileEntry{{SourcePath: validFile}})
	if err != nil {
		t.Errorf("Valid operation should succeed after failed one: %v", err)
	}
}

// TestIntegrationPasswordStrength tests various password strengths
func TestIntegrationPasswordStrength(t *testing.T) {
	tmpDir := t.TempDir()

	testFile := filepath.Join(tmpDir, "test.txt")
	os.WriteFile(testFile, []byte("Test content"), 0644)

	passwords := []string{
		"1234",                   // Short numeric
		"password",              // Common word
		"P@ssw0rd!",             // Mixed characters
		"ThisIsAVeryLongPasswordThatShouldStillWork123!", // Long password
		strings.Repeat("a", 100), // Very long password
	}

	for _, password := range passwords {
		t.Run(password[:min(10, len(password))], func(t *testing.T) {
			outputPath := filepath.Join(tmpDir, "pwd_test.zip")

			config := DefaultConfig()
			config.Password = password
			config.OutputPath = outputPath

			enc, err := NewEncryptor(config)
			if err != nil {
				t.Fatalf("Failed to create encryptor: %v", err)
			}

			err = enc.EncryptFiles([]FileEntry{{SourcePath: testFile}})
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Verify decryption
			reader, err := zip.OpenReader(outputPath)
			if err != nil {
				t.Fatalf("Failed to open ZIP: %v", err)
			}

			for _, f := range reader.File {
				f.SetPassword(password)
				rc, err := f.Open()
				if err != nil {
					t.Errorf("Failed to decrypt: %v", err)
					continue
				}

				_, err = io.ReadAll(rc)
				rc.Close()
				if err != nil {
					t.Errorf("Failed to read decrypted content: %v", err)
				}
			}
			reader.Close()

			os.Remove(outputPath)
		})
	}
}

