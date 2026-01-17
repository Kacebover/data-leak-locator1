package searcher

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSearchInFile tests the SearchInFile function
func TestSearchInFile(t *testing.T) {
	// Create a temporary file for testing
	tmpFile, err := os.CreateTemp("", "test_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write test content
	content := "This is a test.\nIt contains password here.\nAnd another line.\n"
	_, err = tmpFile.WriteString(content)
	if err != nil {
		t.Fatalf("Failed to write to temporary file: %v", err)
	}
	tmpFile.Close()

	// Test searching for keyword
	results, err := SearchInFile(tmpFile.Name(), "password")
	if err != nil {
		t.Fatalf("SearchInFile returned an error: %v", err)
	}

	// Verify results
	if len(results) != 1 {
		t.Errorf("Expected 1 line with 'password', got %d", len(results))
	}

	if len(results) > 0 && results[0] != 2 {
		t.Errorf("Expected 'password' on line 2, got line %d", results[0])
	}
}

// TestSearchInFileNotFound tests when keyword is not found
func TestSearchInFileNotFound(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := "This file does not contain the keyword.\nJust some random text.\n"
	_, err = tmpFile.WriteString(content)
	if err != nil {
		t.Fatalf("Failed to write to temporary file: %v", err)
	}
	tmpFile.Close()

	results, err := SearchInFile(tmpFile.Name(), "password")
	if err != nil {
		t.Fatalf("SearchInFile returned an error: %v", err)
	}

	if len(results) != 0 {
		t.Errorf("Expected no lines with 'password', got %d", len(results))
	}
}

// TestSearchInFileCaseInsensitive tests case-insensitive search
func TestSearchInFileCaseInsensitive(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := "Line 1\nPASSWORD in uppercase\npassword in lowercase\nPassWord mixed case\n"
	_, err = tmpFile.WriteString(content)
	if err != nil {
		t.Fatalf("Failed to write to temporary file: %v", err)
	}
	tmpFile.Close()

	results, err := SearchInFile(tmpFile.Name(), "password")
	if err != nil {
		t.Fatalf("SearchInFile returned an error: %v", err)
	}

	if len(results) != 3 {
		t.Errorf("Expected 3 lines with 'password' (case-insensitive), got %d", len(results))
	}

	expectedLines := []int{2, 3, 4}
	for i, expected := range expectedLines {
		if len(results) > i && results[i] != expected {
			t.Errorf("Expected 'password' on line %d, got line %d", expected, results[i])
		}
	}
}

// TestSearchInFileMultipleOccurrences tests multiple occurrences on same line
func TestSearchInFileMultipleOccurrences(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test_*.txt")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	content := "Line 1\nPassword and password on same line\nLine 3\n"
	_, err = tmpFile.WriteString(content)
	if err != nil {
		t.Fatalf("Failed to write to temporary file: %v", err)
	}
	tmpFile.Close()

	results, err := SearchInFile(tmpFile.Name(), "password")
	if err != nil {
		t.Fatalf("SearchInFile returned an error: %v", err)
	}

	// Line 2 contains password, so it should be returned once
	if len(results) != 1 {
		t.Errorf("Expected 1 line (even with multiple occurrences), got %d", len(results))
	}

	if len(results) > 0 && results[0] != 2 {
		t.Errorf("Expected 'password' on line 2, got line %d", results[0])
	}
}

// TestSearchInFileNonExistent tests searching in non-existent file
func TestSearchInFileNonExistent(t *testing.T) {
	_, err := SearchInFile("/nonexistent/file.txt", "password")
	if err == nil {
		t.Error("Expected error for non-existent file, got nil")
	}
}

// TestSearchInFileIntegration tests with actual test data files
func TestSearchInFileIntegration(t *testing.T) {
	testFile := filepath.Join("../testdata/file1.txt")
	
	// Only run if test data exists
	if _, err := os.Stat(testFile); err != nil {
		t.Skip("Test data files not available")
	}

	results, err := SearchInFile(testFile, "password")
	if err != nil {
		t.Fatalf("SearchInFile returned an error: %v", err)
	}

	// file1.txt should have password on lines 2 and 3
	if len(results) < 1 {
		t.Error("Expected to find 'password' in test file")
	}
}
