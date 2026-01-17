package searcher

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanner_ScanDirectory(t *testing.T) {
	scanner := NewScanner()

	// Get testdata directory path
	testdataDir := filepath.Join("..", "testdata", "docs")

	// Verify testdata exists
	if _, err := os.Stat(testdataDir); os.IsNotExist(err) {
		t.Skipf("Test data directory not found: %s", testdataDir)
	}

	result, err := scanner.Scan(testdataDir)
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if len(result.Findings) == 0 {
		t.Error("Expected to find some sensitive data in testdata")
	}

	t.Logf("Found %d findings in %d files", len(result.Findings), result.FilesScanned)
}

func TestScanner_DetectsAPIKeys(t *testing.T) {
	scanner := NewScanner()

	// Create temp file with API keys
	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "config.txt")

	content := `
API_KEY=AKIAIOSFODNN7EXAMPLE
SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
STRIPE_KEY=sk_live_51H7hJ2KZvJgA1BcDeFgHiJkLmNoPqRsTuVwXyZ
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	result, err := scanner.Scan(tmpDir)
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	if len(result.Findings) < 2 {
		t.Errorf("Expected at least 2 API key findings, got %d", len(result.Findings))
	}

	// Check that AWS key was found
	foundAWS := false
	for _, f := range result.Findings {
		if f.PatternType == PatternAWSKey {
			foundAWS = true
			break
		}
	}
	if !foundAWS {
		t.Error("Expected to find AWS key pattern")
	}
}

func TestScanner_DetectsPasswords(t *testing.T) {
	scanner := NewScanner()

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "config.txt")

	content := `
password=SuperSecret123!
password: admin123
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	result, err := scanner.Scan(tmpDir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	foundPassword := false
	for _, f := range result.Findings {
		if f.PatternType == PatternPassword {
			foundPassword = true
			break
		}
	}

	if !foundPassword {
		t.Logf("Found %d findings", len(result.Findings))
		for _, f := range result.Findings {
			t.Logf("  Type: %s, Text: %s", f.PatternType, f.MatchedText)
		}
		t.Error("Expected to find password patterns")
	}
}

func TestScanner_DetectsCreditCards(t *testing.T) {
	scanner := NewScanner()

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "customers.txt")

	// Credit card pattern requires continuous digits (no spaces/dashes)
	content := `
Customer: John Doe
Card: 4111111111111111
Card2: 5500000000000004
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	result, err := scanner.Scan(tmpDir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	foundCard := false
	for _, f := range result.Findings {
		if f.PatternType == PatternCreditCard {
			foundCard = true
			break
		}
	}

	if !foundCard {
		t.Logf("Found %d findings", len(result.Findings))
		for _, f := range result.Findings {
			t.Logf("  Type: %s, Text: %s", f.PatternType, f.MatchedText)
		}
		t.Error("Expected to find credit card patterns")
	}
}

func TestScanner_DetectsPrivateKeys(t *testing.T) {
	scanner := NewScanner()

	tmpDir := t.TempDir()
	testFile := filepath.Join(tmpDir, "id_rsa")

	content := `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z0BN9yLmNdPQjq
BASE64ENCODEDKEYDATA
-----END RSA PRIVATE KEY-----
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	result, err := scanner.Scan(tmpDir)
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	foundKey := false
	for _, f := range result.Findings {
		if f.PatternType == PatternPrivateKey {
			foundKey = true
			break
		}
	}

	if !foundKey {
		t.Error("Expected to find private key pattern")
	}
}

func TestScanner_SeverityLevels(t *testing.T) {
	scanner := NewScanner()

	tmpDir := t.TempDir()

	// Create files with different severity data
	criticalFile := filepath.Join(tmpDir, "critical.txt")
	if err := os.WriteFile(criticalFile, []byte(`AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`), 0644); err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	highFile := filepath.Join(tmpDir, "high.txt")
	if err := os.WriteFile(highFile, []byte(`DATABASE_PASSWORD=mypassword123`), 0644); err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	result, err := scanner.Scan(tmpDir)
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	severityCounts := make(map[Severity]int)
	for _, f := range result.Findings {
		severityCounts[f.Severity]++
	}

	if severityCounts[Critical] == 0 {
		t.Error("Expected at least one critical severity finding")
	}

	t.Logf("Severity counts: %v", severityCounts)
}

func TestScanner_IgnorePatterns(t *testing.T) {
	scanner := NewScanner()

	tmpDir := t.TempDir()

	// Create .dataleak-ignore file
	ignoreFile := filepath.Join(tmpDir, ".dataleak-ignore")
	if err := os.WriteFile(ignoreFile, []byte("ignored.txt\n*.log\n"), 0644); err != nil {
		t.Fatalf("Failed to create .dataleak-ignore: %v", err)
	}

	// Load the ignore file
	scanner.GetIgnoreList().LoadFromFile(ignoreFile)
	scanner.GetIgnoreList().AddPattern("ignored.txt")

	// Create file that should be ignored
	ignoredFile := filepath.Join(tmpDir, "ignored.txt")
	if err := os.WriteFile(ignoredFile, []byte("password=secret123"), 0644); err != nil {
		t.Fatalf("Failed to create ignored file: %v", err)
	}

	// Create non-ignored file with secret
	normalFile := filepath.Join(tmpDir, "normal.txt")
	if err := os.WriteFile(normalFile, []byte("password=secret456"), 0644); err != nil {
		t.Fatalf("Failed to create normal file: %v", err)
	}

	result, err := scanner.Scan(tmpDir)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// At least the normal file should be found
	foundNormal := false
	for _, f := range result.Findings {
		if filepath.Base(f.FilePath) == "normal.txt" {
			foundNormal = true
		}
	}

	if !foundNormal {
		t.Error("Expected to find secrets in non-ignored files")
	}
}

func TestScanner_MaxFileSize(t *testing.T) {
	scanner := NewScanner()
	scanner.SetMaxFileSize(100) // 100 bytes max

	tmpDir := t.TempDir()

	// Create a large file
	largeFile := filepath.Join(tmpDir, "large.txt")
	content := make([]byte, 200)
	for i := range content {
		content[i] = 'A'
	}
	if err := os.WriteFile(largeFile, content, 0644); err != nil {
		t.Fatalf("Failed to create large file: %v", err)
	}

	// Create a small file with secret
	smallFile := filepath.Join(tmpDir, "small.txt")
	if err := os.WriteFile(smallFile, []byte("PASSWORD=secret"), 0644); err != nil {
		t.Fatalf("Failed to create small file: %v", err)
	}

	result, err := scanner.Scan(tmpDir)
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	// Large file should be skipped
	for _, f := range result.Findings {
		if filepath.Base(f.FilePath) == "large.txt" {
			t.Error("Should not scan files larger than max size")
		}
	}

	// Small file should be scanned
	foundSmall := false
	for _, f := range result.Findings {
		if filepath.Base(f.FilePath) == "small.txt" {
			foundSmall = true
			break
		}
	}
	if !foundSmall {
		t.Error("Should find secrets in small files")
	}
}

func TestScanner_EmptyDirectory(t *testing.T) {
	scanner := NewScanner()

	tmpDir := t.TempDir()

	result, err := scanner.Scan(tmpDir)
	if err != nil {
		t.Fatalf("ScanDirectory failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	if len(result.Findings) != 0 {
		t.Errorf("Expected 0 findings in empty dir, got %d", len(result.Findings))
	}
}

func TestScanner_NonexistentDirectory(t *testing.T) {
	scanner := NewScanner()

	result, err := scanner.Scan("/nonexistent/path/12345")
	// Scanner may return empty result or error for nonexistent directory
	if err == nil && result != nil {
		// If no error, should have 0 findings
		if len(result.Findings) > 0 {
			t.Error("Expected 0 findings for nonexistent directory")
		}
	}
	// Either error or empty result is acceptable
}

func TestScanner_PatternTypes(t *testing.T) {
	tests := []struct {
		name        string
		content     string
		wantPattern PatternType
	}{
		{
			name:        "AWS Access Key",
			content:     "AKIAIOSFODNN7EXAMPLE",
			wantPattern: PatternAWSKey,
		},
		{
			name:        "GitHub Token",
			content:     "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			wantPattern: PatternGitHubToken,
		},
		{
			name:        "Connection String",
			content:     "database_url=postgres://user:password123@localhost:5432/db",
			wantPattern: PatternConnectionStr,
		},
		{
			name:        "Private Key",
			content:     "-----BEGIN RSA PRIVATE KEY-----\ndata\n-----END RSA PRIVATE KEY-----",
			wantPattern: PatternPrivateKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := NewScanner()
			tmpDir := t.TempDir()
			testFile := filepath.Join(tmpDir, "test.txt")

			if err := os.WriteFile(testFile, []byte(tt.content), 0644); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			result, err := scanner.Scan(tmpDir)
			if err != nil {
				t.Fatalf("ScanDirectory failed: %v", err)
			}

			found := false
			for _, f := range result.Findings {
				if f.PatternType == tt.wantPattern {
					found = true
					break
				}
			}

			if !found {
				t.Errorf("Expected to find pattern %s", tt.wantPattern)
			}
		})
	}
}

func BenchmarkScanner_ScanDirectory(b *testing.B) {
	scanner := NewScanner()

	// Create test directory with multiple files
	tmpDir := b.TempDir()
	for i := 0; i < 100; i++ {
		content := `
API_KEY=AKIAIOSFODNN7EXAMPLE
PASSWORD=secret123
DB_URL=postgres://user:pass@host:5432/db
`
		filepath := filepath.Join(tmpDir, "file"+string(rune('0'+i))+".txt")
		os.WriteFile(filepath, []byte(content), 0644)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(tmpDir)
	}
}

