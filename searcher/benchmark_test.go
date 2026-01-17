package searcher

import (
	"context"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// BenchmarkScanner_SmallFiles benchmarks scanning many small files
func BenchmarkScanner_SmallFiles(b *testing.B) {
	tempDir := b.TempDir()
	
	// Create 100 small files
	for i := 0; i < 100; i++ {
		file := filepath.Join(tempDir, "file"+string(rune('a'+i%26))+string(rune('0'+i/26))+".txt")
		content := "Normal text line\n"
		if i%10 == 0 {
			content += "password=secret123\n"
		}
		os.WriteFile(file, []byte(content), 0644)
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		scanner := NewScanner()
		scanner.Scan(tempDir)
	}
}

// BenchmarkScanner_LargeFile benchmarks scanning a single large file
func BenchmarkScanner_LargeFile(b *testing.B) {
	tempDir := b.TempDir()
	largeFile := filepath.Join(tempDir, "large.txt")
	
	// Create 10MB file with embedded secrets
	var builder strings.Builder
	for i := 0; i < 200000; i++ { // ~50 bytes per line = ~10MB
		if i%1000 == 0 {
			builder.WriteString("password=secret" + string(rune('0'+i%10)) + "\n")
		} else {
			builder.WriteString("This is a normal line of text without any secrets.\n")
		}
	}
	os.WriteFile(largeFile, []byte(builder.String()), 0644)
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		scanner := NewScanner()
		scanner.Scan(tempDir)
	}
}

// BenchmarkScanner_MixedContent benchmarks scanning mixed content
func BenchmarkScanner_MixedContent(b *testing.B) {
	tempDir := b.TempDir()
	
	// Create files with various patterns
	patterns := []string{
		"password=secret123",
		"AKIAIOSFODNN7EXAMPLE",
		"user@example.com",
		"4111111111111111",
		"-----BEGIN RSA PRIVATE KEY-----",
		"ghp_1234567890abcdefghijklmnopqrstuvwxyz1234",
		"123-45-6789",
	}
	
	for i := 0; i < 50; i++ {
		file := filepath.Join(tempDir, "file"+string(rune('0'+i%10))+string(rune('0'+i/10))+".txt")
		var content strings.Builder
		for j := 0; j < 100; j++ {
			if j%10 == 0 {
				content.WriteString(patterns[j/10%len(patterns)])
				content.WriteString("\n")
			} else {
				content.WriteString("Normal line of text here.\n")
			}
		}
		os.WriteFile(file, []byte(content.String()), 0644)
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		scanner := NewScanner()
		scanner.Scan(tempDir)
	}
}

// BenchmarkStreamingScanner_Throughput benchmarks streaming scanner throughput
func BenchmarkStreamingScanner_Throughput(b *testing.B) {
	tempDir := b.TempDir()
	
	// Create 10MB of synthetic text with secrets
	totalSize := int64(0)
	for i := 0; i < 100; i++ {
		file := filepath.Join(tempDir, "file"+string(rune('0'+i%10))+string(rune('a'+i/10))+".txt")
		var content strings.Builder
		for j := 0; j < 1000; j++ {
			if j%50 == 0 {
				content.WriteString("api_key=sk_live_1234567890abcdefghijklmnop\n")
			} else {
				content.WriteString("Regular content line without any sensitive data.\n")
			}
		}
		data := []byte(content.String())
		totalSize += int64(len(data))
		os.WriteFile(file, data, 0644)
	}
	
	b.ResetTimer()
	b.SetBytes(totalSize)
	
	for i := 0; i < b.N; i++ {
		config := DefaultStreamingScannerConfig()
		scanner := NewStreamingScanner(config)
		ctx := context.Background()
		
		go func() {
			for range scanner.Events() {
			}
		}()
		
		scanner.Scan(ctx, tempDir)
	}
}

// BenchmarkPatternMatching_AllPatterns benchmarks all pattern matching
func BenchmarkPatternMatching_AllPatterns(b *testing.B) {
	patterns := NewPatterns()
	
	// Text with various patterns
	inputs := []string{
		"password=secret123 and more text",
		"AKIAIOSFODNN7EXAMPLE aws key here",
		"contact us at user@example.com for info",
		"card number is 4111111111111111",
		"token: ghp_1234567890abcdefghijklmnopqrstuvwxyz1234",
		"SSN: 123-45-6789 for John Doe",
		`{"api_key": "super_secret_key_12345"}`,
		"export AWS_SECRET=wJalrXUtnFEMI/K7MDENG",
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		for _, input := range inputs {
			patterns.FindAll(input)
		}
	}
}

// BenchmarkEntropyCalculation benchmarks entropy calculation
func BenchmarkEntropyCalculation(b *testing.B) {
	calc := NewEntropyCalculator()
	
	// Various test strings
	inputs := []string{
		"aaaaaaaaaaaaaaaa",                         // Low entropy
		"abcdefghijklmnop",                         // Medium entropy
		"aB3$xY9!kL2@mN7#",                         // High entropy
		"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLE",   // AWS-like key
		"ghp_1234567890abcdefghijklmnopqrstuvwxyz", // GitHub token
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		for _, input := range inputs {
			calc.CalculateEntropy(input)
		}
	}
}

// BenchmarkRiskScoring benchmarks risk score calculation
func BenchmarkRiskScoring(b *testing.B) {
	scorer := NewRiskScorer()
	
	pattern := &DetectedPattern{
		Type:         PatternPassword,
		Severity:     Critical,
		MatchText:    "password=SuperSecret123!@#",
		Context:      "DB_PASSWORD=SuperSecret123!@# # production database",
		EntropyScore: 4.5,
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		scorer.CalculateRiskScore(pattern)
	}
}

// BenchmarkLuhnValidation benchmarks Luhn algorithm
func BenchmarkLuhnValidation(b *testing.B) {
	validator := NewLuhnValidator()
	
	cardNumbers := []string{
		"4111111111111111",
		"5425233430109903",
		"378282246310005",
		"4111-1111-1111-1111",
		"4111 1111 1111 1111",
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		for _, card := range cardNumbers {
			validator.IsValid(card)
		}
	}
}

// BenchmarkIgnoreList benchmarks ignore list checking
func BenchmarkIgnoreList(b *testing.B) {
	ignoreList := NewIgnoreList()
	ignoreList.AddDefaultIgnores()
	
	paths := []string{
		"/home/user/project/src/main.go",
		"/home/user/project/node_modules/express/index.js",
		"/home/user/project/.git/objects/pack/pack-123.pack",
		"/home/user/project/vendor/github.com/lib/pq/conn.go",
		"/home/user/project/build/output.exe",
		"/home/user/project/images/logo.png",
	}
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		for _, path := range paths {
			ignoreList.ShouldIgnorePath(path)
		}
	}
}

// BenchmarkConcurrentScanning benchmarks concurrent scanning performance
func BenchmarkConcurrentScanning(b *testing.B) {
	tempDir := b.TempDir()
	
	// Create files
	for i := 0; i < 200; i++ {
		file := filepath.Join(tempDir, "file"+string(rune('a'+i%26))+string(rune('0'+i/26%10))+".txt")
		content := "Normal text\npassword=secret" + string(rune('0'+i%10)) + "\n"
		os.WriteFile(file, []byte(content), 0644)
	}
	
	concurrencyLevels := []int{1, 2, 4, 8, 16}
	
	for _, concurrency := range concurrencyLevels {
		b.Run("workers_"+string(rune('0'+concurrency/10))+string(rune('0'+concurrency%10)), func(b *testing.B) {
			b.ResetTimer()
			
			for i := 0; i < b.N; i++ {
				config := DefaultStreamingScannerConfig()
				config.MaxConcurrent = concurrency
				scanner := NewStreamingScanner(config)
				ctx := context.Background()
				
				go func() {
					for range scanner.Events() {
					}
				}()
				
				scanner.Scan(ctx, tempDir)
			}
		})
	}
}

// BenchmarkSyntheticLargeFile benchmarks with 10MB synthetic file
func BenchmarkSyntheticLargeFile(b *testing.B) {
	tempDir := b.TempDir()
	largeFile := filepath.Join(tempDir, "synthetic_10mb.txt")
	
	// Generate 10MB of random-like text with embedded secrets
	const targetSize = 10 * 1024 * 1024
	var content strings.Builder
	
	secrets := []string{
		"password=RandomSecret" + randomString(10),
		"AKIAIOSFODNN7EXAMPLE",
		"api_key=sk_live_" + randomString(24),
		"4111111111111111",
		"ghp_" + randomString(36),
	}
	
	lineCount := 0
	for content.Len() < targetSize {
		if lineCount%100 == 0 && lineCount > 0 {
			// Insert a secret every 100 lines
			content.WriteString(secrets[lineCount/100%len(secrets)])
			content.WriteString("\n")
		} else {
			// Normal line
			content.WriteString("This is line ")
			content.WriteString(string(rune('0' + lineCount%10)))
			content.WriteString(" of regular text content without sensitive information.\n")
		}
		lineCount++
	}
	
	os.WriteFile(largeFile, []byte(content.String()), 0644)
	
	fileInfo, _ := os.Stat(largeFile)
	b.SetBytes(fileInfo.Size())
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		scanner := NewScanner()
		scanner.Scan(tempDir)
	}
}

// Helper function to generate random strings
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[rand.Intn(len(charset))]
	}
	return string(result)
}

// BenchmarkReportGeneration benchmarks report generation
func BenchmarkReportGeneration(b *testing.B) {
	// Create a result with many findings
	result := NewScanResult()
	for i := 0; i < 1000; i++ {
		result.AddFinding(&Finding{
			FilePath:     "/path/to/file" + string(rune('0'+i%10)) + ".txt",
			LineNumber:   i + 1,
			PatternType:  PatternPassword,
			Severity:     Critical,
			Description:  "Password detected",
			MatchedText:  "password=secret" + string(rune('0'+i%10)),
			Context:      "Some context around the password=secret" + string(rune('0'+i%10)) + " finding",
			RiskScore:    75.0 + float64(i%25),
			EntropyScore: 4.5,
		})
	}
	result.FilesScanned = 100
	result.StartTime = 1000000
	result.EndTime = 1000010
	
	tempDir := b.TempDir()
	
	b.ResetTimer()
	
	for i := 0; i < b.N; i++ {
		reporter := NewReportGenerator(result)
		reporter.GenerateReport(tempDir)
	}
}

