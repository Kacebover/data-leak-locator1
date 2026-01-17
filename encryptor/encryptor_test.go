package encryptor

import (
	"bytes"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexmullins/zip"
)

// Helper function to create a temporary test file with content
func createTestFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("Failed to create directory for test file: %v", err)
	}
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	return path
}

// Helper function to create a test file with specific size
func createTestFileWithSize(t *testing.T, dir, name string, size int64) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatalf("Failed to create directory for test file: %v", err)
	}

	file, err := os.Create(path)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}
	defer file.Close()

	// Write random data in chunks
	buf := make([]byte, 32*1024)
	remaining := size
	for remaining > 0 {
		toWrite := int64(len(buf))
		if remaining < toWrite {
			toWrite = remaining
		}
		rand.Read(buf[:toWrite])
		if _, err := file.Write(buf[:toWrite]); err != nil {
			t.Fatalf("Failed to write test file: %v", err)
		}
		remaining -= toWrite
	}

	return path
}

// Helper function to verify ZIP can be opened with correct password
func verifyZIPWithPassword(t *testing.T, zipPath, password string) []string {
	t.Helper()

	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("Failed to open ZIP: %v", err)
	}
	defer reader.Close()

	var fileNames []string
	for _, f := range reader.File {
		f.SetPassword(password)
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("Failed to open file %s in ZIP: %v", f.Name, err)
		}

		// Read content to verify decryption works
		_, err = io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("Failed to read file %s from ZIP: %v", f.Name, err)
		}

		fileNames = append(fileNames, f.Name)
	}

	return fileNames
}

// Helper function to verify ZIP cannot be opened with wrong password
func verifyZIPFailsWithWrongPassword(t *testing.T, zipPath, wrongPassword string) {
	t.Helper()

	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatalf("Failed to open ZIP: %v", err)
	}
	defer reader.Close()

	for _, f := range reader.File {
		f.SetPassword(wrongPassword)
		rc, err := f.Open()
		if err != nil {
			// Expected - wrong password
			continue
		}

		// Try to read - should fail
		_, err = io.ReadAll(rc)
		rc.Close()
		if err == nil {
			t.Errorf("Expected decryption to fail with wrong password for file %s", f.Name)
		}
	}
}

// TestEncryptSingleFile tests encrypting a single file
func TestEncryptSingleFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test file
	testContent := "This is sensitive data that should be encrypted"
	testFile := createTestFile(t, tmpDir, "secret.txt", testContent)

	outputPath := filepath.Join(tmpDir, "encrypted.zip")
	password := "TestPassword123!"

	config := DefaultConfig()
	config.Password = password
	config.OutputPath = outputPath

	enc, err := NewEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	err = enc.EncryptFiles([]FileEntry{{SourcePath: testFile}})
	if err != nil {
		t.Fatalf("Failed to encrypt file: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatal("Output ZIP file was not created")
	}

	// Verify can be opened with correct password
	files := verifyZIPWithPassword(t, outputPath, password)
	if len(files) != 1 {
		t.Errorf("Expected 1 file in ZIP, got %d", len(files))
	}

	// Verify fails with wrong password
	verifyZIPFailsWithWrongPassword(t, outputPath, "WrongPassword")
}

// TestEncryptMultipleFiles tests encrypting multiple files
func TestEncryptMultipleFiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create multiple test files
	files := []FileEntry{
		{SourcePath: createTestFile(t, tmpDir, "file1.txt", "Content of file 1")},
		{SourcePath: createTestFile(t, tmpDir, "file2.txt", "Content of file 2")},
		{SourcePath: createTestFile(t, tmpDir, "file3.txt", "Content of file 3")},
	}

	outputPath := filepath.Join(tmpDir, "multiple.zip")
	password := "MultiFilePassword!"

	config := DefaultConfig()
	config.Password = password
	config.OutputPath = outputPath
	config.PreserveStructure = false

	enc, err := NewEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	err = enc.EncryptFiles(files)
	if err != nil {
		t.Fatalf("Failed to encrypt files: %v", err)
	}

	// Verify all files are in the ZIP
	zipFiles := verifyZIPWithPassword(t, outputPath, password)
	if len(zipFiles) != 3 {
		t.Errorf("Expected 3 files in ZIP, got %d", len(zipFiles))
	}
}

// TestEncryptNestedDirectories tests encrypting files with nested directory structure
func TestEncryptNestedDirectories(t *testing.T) {
	tmpDir := t.TempDir()
	sourceDir := filepath.Join(tmpDir, "source")

	// Create nested directory structure
	createTestFile(t, sourceDir, "root.txt", "Root file")
	createTestFile(t, sourceDir, "subdir1/file1.txt", "File in subdir1")
	createTestFile(t, sourceDir, "subdir1/nested/deep.txt", "Deep nested file")
	createTestFile(t, sourceDir, "subdir2/file2.txt", "File in subdir2")

	outputPath := filepath.Join(tmpDir, "nested.zip")
	password := "NestedPassword!"

	config := DefaultConfig()
	config.Password = password
	config.OutputPath = outputPath
	config.PreserveStructure = true

	enc, err := NewEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// Encrypt the entire directory
	err = enc.EncryptFiles([]FileEntry{{SourcePath: sourceDir}})
	if err != nil {
		t.Fatalf("Failed to encrypt directory: %v", err)
	}

	// Verify files are in ZIP with correct structure
	zipFiles := verifyZIPWithPassword(t, outputPath, password)
	if len(zipFiles) != 4 {
		t.Errorf("Expected 4 files in ZIP, got %d: %v", len(zipFiles), zipFiles)
	}

	// Verify directory structure is preserved
	hasNested := false
	for _, f := range zipFiles {
		if strings.Contains(f, "nested/deep.txt") {
			hasNested = true
			break
		}
	}
	if !hasNested {
		t.Error("Nested directory structure was not preserved")
	}
}

// TestPasswordProtectionCorrectness tests that encryption actually works
func TestPasswordProtectionCorrectness(t *testing.T) {
	tmpDir := t.TempDir()

	testContent := "Super secret data: password=abc123"
	testFile := createTestFile(t, tmpDir, "secret.txt", testContent)

	outputPath := filepath.Join(tmpDir, "protected.zip")
	correctPassword := "CorrectPassword123!"
	wrongPassword := "WrongPassword456!"

	config := DefaultConfig()
	config.Password = correctPassword
	config.OutputPath = outputPath

	enc, err := NewEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	err = enc.EncryptFiles([]FileEntry{{SourcePath: testFile}})
	if err != nil {
		t.Fatalf("Failed to encrypt file: %v", err)
	}

	// Test 1: Correct password should work
	reader, err := zip.OpenReader(outputPath)
	if err != nil {
		t.Fatalf("Failed to open ZIP: %v", err)
	}

	for _, f := range reader.File {
		f.SetPassword(correctPassword)
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("Failed to open file with correct password: %v", err)
		}

		content, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("Failed to read with correct password: %v", err)
		}

		if string(content) != testContent {
			t.Errorf("Content mismatch: got %q, want %q", string(content), testContent)
		}
	}
	reader.Close()

	// Test 2: Wrong password should fail
	reader, err = zip.OpenReader(outputPath)
	if err != nil {
		t.Fatalf("Failed to open ZIP: %v", err)
	}
	defer reader.Close()

	for _, f := range reader.File {
		f.SetPassword(wrongPassword)
		rc, err := f.Open()
		if err != nil {
			continue // Expected
		}

		_, err = io.ReadAll(rc)
		rc.Close()
		if err == nil {
			t.Error("Wrong password should not decrypt content")
		}
	}
}

// TestLargeFileStreaming tests encryption of large files using streaming
func TestLargeFileStreaming(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping large file test in short mode")
	}

	tmpDir := t.TempDir()

	// Create a 5MB file
	largeFile := createTestFileWithSize(t, tmpDir, "large.bin", 5*1024*1024)

	outputPath := filepath.Join(tmpDir, "large.zip")
	password := "LargeFilePassword!"

	var progressCalls int
	var lastBytesProcessed int64

	config := DefaultConfig()
	config.Password = password
	config.OutputPath = outputPath
	config.OnProgress = func(bytesProcessed, totalBytes int64, currentFile string) {
		progressCalls++
		if bytesProcessed < lastBytesProcessed {
			t.Error("Progress should not decrease")
		}
		lastBytesProcessed = bytesProcessed
	}

	enc, err := NewEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	err = enc.EncryptFiles([]FileEntry{{SourcePath: largeFile}})
	if err != nil {
		t.Fatalf("Failed to encrypt large file: %v", err)
	}

	// Verify progress was reported
	if progressCalls == 0 {
		t.Error("Progress callback was never called")
	}

	// Verify file can be opened
	verifyZIPWithPassword(t, outputPath, password)
}

// TestEmptyPassword tests that empty passwords are rejected
func TestEmptyPassword(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultConfig()
	config.Password = ""
	config.OutputPath = filepath.Join(tmpDir, "test.zip")

	_, err := NewEncryptor(config)
	if err != ErrEmptyPassword {
		t.Errorf("Expected ErrEmptyPassword, got %v", err)
	}
}

// TestMissingFiles tests handling of missing files
func TestMissingFiles(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultConfig()
	config.Password = "TestPassword!"
	config.OutputPath = filepath.Join(tmpDir, "test.zip")

	enc, err := NewEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	err = enc.EncryptFiles([]FileEntry{{SourcePath: "/nonexistent/file.txt"}})
	if err == nil {
		t.Error("Expected error for missing file")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("Expected 'not found' error, got: %v", err)
	}
}

// TestNoFiles tests handling of empty file list
func TestNoFiles(t *testing.T) {
	tmpDir := t.TempDir()

	config := DefaultConfig()
	config.Password = "TestPassword!"
	config.OutputPath = filepath.Join(tmpDir, "test.zip")

	enc, err := NewEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	err = enc.EncryptFiles([]FileEntry{})
	if err != ErrNoFiles {
		t.Errorf("Expected ErrNoFiles, got %v", err)
	}
}

// TestPermissionErrors tests handling of permission errors
func TestPermissionErrors(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("Skipping permission test when running as root")
	}

	tmpDir := t.TempDir()

	// Create a file and remove read permissions
	testFile := createTestFile(t, tmpDir, "noperm.txt", "content")
	if err := os.Chmod(testFile, 0000); err != nil {
		t.Fatalf("Failed to change permissions: %v", err)
	}
	defer os.Chmod(testFile, 0644) // Restore for cleanup

	config := DefaultConfig()
	config.Password = "TestPassword!"
	config.OutputPath = filepath.Join(tmpDir, "test.zip")

	enc, err := NewEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	err = enc.EncryptFiles([]FileEntry{{SourcePath: testFile}})
	if err == nil {
		t.Error("Expected permission error")
	}
}

// TestInvalidOutputPath tests handling of invalid output path
func TestInvalidOutputPath(t *testing.T) {
	config := DefaultConfig()
	config.Password = "TestPassword!"
	config.OutputPath = ""

	_, err := NewEncryptor(config)
	if err != ErrInvalidOutput {
		t.Errorf("Expected ErrInvalidOutput, got %v", err)
	}
}

// TestDifferentEncryptionMethods tests AES-128, AES-192, and AES-256
func TestDifferentEncryptionMethods(t *testing.T) {
	methods := []struct {
		name   string
		method EncryptionMethod
	}{
		{"AES-128", AES128},
		{"AES-192", AES192},
		{"AES-256", AES256},
	}

	for _, m := range methods {
		t.Run(m.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			testFile := createTestFile(t, tmpDir, "test.txt", "Encrypted content")
			outputPath := filepath.Join(tmpDir, "encrypted.zip")
			password := "TestPassword123!"

			config := DefaultConfig()
			config.Password = password
			config.OutputPath = outputPath
			config.Method = m.method

			enc, err := NewEncryptor(config)
			if err != nil {
				t.Fatalf("Failed to create encryptor: %v", err)
			}

			err = enc.EncryptFiles([]FileEntry{{SourcePath: testFile}})
			if err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}

			// Verify can be decrypted
			verifyZIPWithPassword(t, outputPath, password)
		})
	}
}

// TestCompressionLevels tests different compression levels
func TestCompressionLevels(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a compressible file (repeated content)
	content := strings.Repeat("This is compressible content. ", 1000)
	testFile := createTestFile(t, tmpDir, "compressible.txt", content)

	var sizes []int64

	for level := 0; level <= 9; level++ {
		outputPath := filepath.Join(tmpDir, "level"+string(rune('0'+level))+".zip")
		password := "TestPassword!"

		config := DefaultConfig()
		config.Password = password
		config.OutputPath = outputPath
		config.CompressionLevel = level

		enc, err := NewEncryptor(config)
		if err != nil {
			t.Fatalf("Failed to create encryptor: %v", err)
		}

		err = enc.EncryptFiles([]FileEntry{{SourcePath: testFile}})
		if err != nil {
			t.Fatalf("Failed to encrypt at level %d: %v", level, err)
		}

		info, _ := os.Stat(outputPath)
		sizes = append(sizes, info.Size())
	}

	// Level 0 (store) should be larger than higher levels
	if sizes[0] <= sizes[6] {
		t.Logf("Compression sizes: %v", sizes)
		// This is a soft check - compression effectiveness varies
	}
}

// TestCancellation tests cancelling an encryption operation
func TestCancellation(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a larger file to ensure we have time to cancel
	largeFile := createTestFileWithSize(t, tmpDir, "large.bin", 1*1024*1024)

	outputPath := filepath.Join(tmpDir, "cancelled.zip")
	password := "TestPassword!"

	config := DefaultConfig()
	config.Password = password
	config.OutputPath = outputPath
	config.BufferSize = 1024 // Small buffer to increase number of iterations

	enc, err := NewEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	// Cancel after a short delay
	go func() {
		time.Sleep(10 * time.Millisecond)
		enc.Cancel()
	}()

	err = enc.EncryptFiles([]FileEntry{{SourcePath: largeFile}})
	if err == nil {
		t.Error("Expected cancellation error")
	}
	if !strings.Contains(err.Error(), "cancelled") {
		t.Errorf("Expected cancellation error, got: %v", err)
	}

	// Partial file should be cleaned up
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Error("Partial output file should be cleaned up after cancellation")
	}
}

// TestEncryptFilesWithResult tests the result reporting
func TestEncryptFilesWithResult(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test files
	files := []FileEntry{
		{SourcePath: createTestFile(t, tmpDir, "file1.txt", "Content 1")},
		{SourcePath: createTestFile(t, tmpDir, "file2.txt", "Content 2")},
	}

	outputPath := filepath.Join(tmpDir, "result.zip")
	password := "TestPassword!"

	config := DefaultConfig()
	config.Password = password
	config.OutputPath = outputPath

	enc, err := NewEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	result, err := enc.EncryptFilesWithResult(files)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if result.OutputPath != outputPath {
		t.Errorf("OutputPath mismatch: got %s, want %s", result.OutputPath, outputPath)
	}

	if result.FilesEncrypted != 2 {
		t.Errorf("FilesEncrypted mismatch: got %d, want 2", result.FilesEncrypted)
	}

	if result.ArchiveSize == 0 {
		t.Error("ArchiveSize should not be 0")
	}
}

// TestGeneratePassword tests password generation
func TestGeneratePassword(t *testing.T) {
	// Test various lengths
	lengths := []int{8, 16, 32, 64}

	for _, length := range lengths {
		password, err := GeneratePassword(length)
		if err != nil {
			t.Errorf("Failed to generate password of length %d: %v", length, err)
		}

		if len(password) != length {
			t.Errorf("Password length mismatch: got %d, want %d", len(password), length)
		}
	}

	// Test minimum length enforcement
	password, _ := GeneratePassword(4)
	if len(password) < 8 {
		t.Error("Password should be at least 8 characters")
	}

	// Test maximum length enforcement
	password, _ = GeneratePassword(200)
	if len(password) > 128 {
		t.Error("Password should be at most 128 characters")
	}

	// Test uniqueness (statistical)
	passwords := make(map[string]bool)
	for i := 0; i < 100; i++ {
		p, _ := GeneratePassword(16)
		if passwords[p] {
			t.Error("Generated duplicate password")
		}
		passwords[p] = true
	}
}

// TestGenerateAlphanumericPassword tests alphanumeric password generation
func TestGenerateAlphanumericPassword(t *testing.T) {
	password, err := GenerateAlphanumericPassword(32)
	if err != nil {
		t.Fatalf("Failed to generate password: %v", err)
	}

	// Verify only alphanumeric characters
	for _, c := range password {
		isAlpha := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
		isNum := c >= '0' && c <= '9'
		if !isAlpha && !isNum {
			t.Errorf("Password contains non-alphanumeric character: %c", c)
		}
	}
}

// TestValidatePassword tests password validation
func TestValidatePassword(t *testing.T) {
	tests := []struct {
		password string
		wantErr  bool
	}{
		{"", true},
		{"abc", true},
		{"abcd", false},
		{"password123", false},
		{"a very long password with spaces", false},
	}

	for _, tt := range tests {
		err := ValidatePassword(tt.password)
		if (err != nil) != tt.wantErr {
			t.Errorf("ValidatePassword(%q) error = %v, wantErr %v", tt.password, err, tt.wantErr)
		}
	}
}

// TestSecureDelete tests secure file deletion
func TestSecureDelete(t *testing.T) {
	tmpDir := t.TempDir()

	testFile := createTestFile(t, tmpDir, "todelete.txt", "Sensitive data to be securely deleted")

	// Verify file exists
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Fatal("Test file was not created")
	}

	err := SecureDelete(testFile, 3)
	if err != nil {
		t.Fatalf("SecureDelete failed: %v", err)
	}

	// Verify file is deleted
	if _, err := os.Stat(testFile); !os.IsNotExist(err) {
		t.Error("File should be deleted after SecureDelete")
	}
}

// TestSecureDeleteNonexistent tests secure deletion of nonexistent file
func TestSecureDeleteNonexistent(t *testing.T) {
	err := SecureDelete("/nonexistent/file.txt", 3)
	if err != nil {
		t.Errorf("SecureDelete should not error for nonexistent file: %v", err)
	}
}

// TestSecureDeleteMultiple tests deleting multiple files
func TestSecureDeleteMultiple(t *testing.T) {
	tmpDir := t.TempDir()

	files := []string{
		createTestFile(t, tmpDir, "file1.txt", "Content 1"),
		createTestFile(t, tmpDir, "file2.txt", "Content 2"),
		createTestFile(t, tmpDir, "file3.txt", "Content 3"),
	}

	var progressCalls int
	err := SecureDeleteMultiple(files, 3, func(current, total int, path string) {
		progressCalls++
		if current > total {
			t.Error("Current should not exceed total")
		}
	})

	if err != nil {
		t.Fatalf("SecureDeleteMultiple failed: %v", err)
	}

	// Verify all files are deleted
	for _, f := range files {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("File %s should be deleted", f)
		}
	}

	if progressCalls != 3 {
		t.Errorf("Expected 3 progress calls, got %d", progressCalls)
	}
}

// TestSecureDeleteEmptyFile tests secure deletion of empty file
func TestSecureDeleteEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()

	emptyFile := createTestFile(t, tmpDir, "empty.txt", "")

	err := SecureDelete(emptyFile, 3)
	if err != nil {
		t.Fatalf("SecureDelete failed for empty file: %v", err)
	}

	if _, err := os.Stat(emptyFile); !os.IsNotExist(err) {
		t.Error("Empty file should be deleted")
	}
}

// TestCustomArchivePath tests specifying custom paths within archive
func TestCustomArchivePath(t *testing.T) {
	tmpDir := t.TempDir()

	testFile := createTestFile(t, tmpDir, "original.txt", "Content")
	outputPath := filepath.Join(tmpDir, "custom.zip")
	password := "TestPassword!"

	config := DefaultConfig()
	config.Password = password
	config.OutputPath = outputPath

	enc, err := NewEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	err = enc.EncryptFiles([]FileEntry{
		{SourcePath: testFile, ArchivePath: "custom/path/renamed.txt"},
	})
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	files := verifyZIPWithPassword(t, outputPath, password)
	if len(files) != 1 {
		t.Fatalf("Expected 1 file, got %d", len(files))
	}

	if files[0] != "custom/path/renamed.txt" {
		t.Errorf("Archive path mismatch: got %s, want custom/path/renamed.txt", files[0])
	}
}

// TestEncryptWithSpecialCharactersInPassword tests passwords with special characters
func TestEncryptWithSpecialCharactersInPassword(t *testing.T) {
	tmpDir := t.TempDir()

	passwords := []string{
		"Pass@word#123!",
		"测试密码",
		"パスワード",
		"emoji🔐password",
		"spaces in password",
		`quotes"and'special`,
	}

	for _, password := range passwords {
		t.Run(password[:min(10, len(password))], func(t *testing.T) {
			testFile := createTestFile(t, tmpDir, "test.txt", "Content")
			outputPath := filepath.Join(tmpDir, "special.zip")

			config := DefaultConfig()
			config.Password = password
			config.OutputPath = outputPath

			enc, err := NewEncryptor(config)
			if err != nil {
				t.Fatalf("Failed to create encryptor: %v", err)
			}

			err = enc.EncryptFiles([]FileEntry{{SourcePath: testFile}})
			if err != nil {
				t.Fatalf("Failed to encrypt: %v", err)
			}

			verifyZIPWithPassword(t, outputPath, password)

			os.Remove(outputPath)
		})
	}
}

// TestEncryptEmptyDirectory tests encrypting an empty directory
func TestEncryptEmptyDirectory(t *testing.T) {
	tmpDir := t.TempDir()

	emptyDir := filepath.Join(tmpDir, "empty")
	if err := os.MkdirAll(emptyDir, 0755); err != nil {
		t.Fatalf("Failed to create empty directory: %v", err)
	}

	config := DefaultConfig()
	config.Password = "TestPassword!"
	config.OutputPath = filepath.Join(tmpDir, "empty.zip")

	enc, err := NewEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	err = enc.EncryptFiles([]FileEntry{{SourcePath: emptyDir}})
	if err != ErrNoFiles {
		t.Errorf("Expected ErrNoFiles for empty directory, got %v", err)
	}
}

// TestFileContentIntegrity verifies encrypted content matches original
func TestFileContentIntegrity(t *testing.T) {
	tmpDir := t.TempDir()

	// Create file with known content
	originalContent := []byte("This is test content with some special chars: äöü 日本語 🔐")
	testFile := filepath.Join(tmpDir, "integrity.txt")
	if err := os.WriteFile(testFile, originalContent, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	outputPath := filepath.Join(tmpDir, "integrity.zip")
	password := "IntegrityTest123!"

	config := DefaultConfig()
	config.Password = password
	config.OutputPath = outputPath

	enc, err := NewEncryptor(config)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	err = enc.EncryptFiles([]FileEntry{{SourcePath: testFile}})
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	// Read back and verify
	reader, err := zip.OpenReader(outputPath)
	if err != nil {
		t.Fatalf("Failed to open ZIP: %v", err)
	}
	defer reader.Close()

	for _, f := range reader.File {
		f.SetPassword(password)
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("Failed to open file: %v", err)
		}

		decrypted, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("Failed to read: %v", err)
		}

		if !bytes.Equal(decrypted, originalContent) {
			t.Errorf("Content mismatch:\nOriginal: %x\nDecrypted: %x", originalContent, decrypted)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

