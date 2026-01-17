package encryptor

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
)

// createBenchFile creates a test file of specified size with random content
func createBenchFile(b *testing.B, dir string, size int64) string {
	b.Helper()

	path := filepath.Join(dir, "bench.bin")
	file, err := os.Create(path)
	if err != nil {
		b.Fatalf("Failed to create bench file: %v", err)
	}
	defer file.Close()

	buf := make([]byte, 64*1024) // 64KB buffer
	remaining := size
	for remaining > 0 {
		toWrite := int64(len(buf))
		if remaining < toWrite {
			toWrite = remaining
		}
		rand.Read(buf[:toWrite])
		if _, err := file.Write(buf[:toWrite]); err != nil {
			b.Fatalf("Failed to write bench file: %v", err)
		}
		remaining -= toWrite
	}

	return path
}

// BenchmarkEncrypt1MB benchmarks encryption of 1MB file
func BenchmarkEncrypt1MB(b *testing.B) {
	benchmarkEncryptSize(b, 1*1024*1024)
}

// BenchmarkEncrypt10MB benchmarks encryption of 10MB file
func BenchmarkEncrypt10MB(b *testing.B) {
	benchmarkEncryptSize(b, 10*1024*1024)
}

// BenchmarkEncrypt50MB benchmarks encryption of 50MB file
func BenchmarkEncrypt50MB(b *testing.B) {
	benchmarkEncryptSize(b, 50*1024*1024)
}

// BenchmarkEncrypt100MB benchmarks encryption of 100MB file
func BenchmarkEncrypt100MB(b *testing.B) {
	benchmarkEncryptSize(b, 100*1024*1024)
}

func benchmarkEncryptSize(b *testing.B, size int64) {
	tmpDir := b.TempDir()

	// Create test file once
	testFile := createBenchFile(b, tmpDir, size)
	password := "BenchmarkPassword123!"

	b.ResetTimer()
	b.SetBytes(size)

	for i := 0; i < b.N; i++ {
		outputPath := filepath.Join(tmpDir, "bench_output.zip")

		config := DefaultConfig()
		config.Password = password
		config.OutputPath = outputPath
		config.CompressionLevel = 6 // Default compression

		enc, err := NewEncryptor(config)
		if err != nil {
			b.Fatalf("Failed to create encryptor: %v", err)
		}

		err = enc.EncryptFiles([]FileEntry{{SourcePath: testFile}})
		if err != nil {
			b.Fatalf("Failed to encrypt: %v", err)
		}

		// Clean up for next iteration
		os.Remove(outputPath)
	}
}

// BenchmarkEncryptNoCompression benchmarks encryption without compression
func BenchmarkEncryptNoCompression(b *testing.B) {
	tmpDir := b.TempDir()
	size := int64(10 * 1024 * 1024) // 10MB

	testFile := createBenchFile(b, tmpDir, size)
	password := "BenchmarkPassword123!"

	b.ResetTimer()
	b.SetBytes(size)

	for i := 0; i < b.N; i++ {
		outputPath := filepath.Join(tmpDir, "bench_output.zip")

		config := DefaultConfig()
		config.Password = password
		config.OutputPath = outputPath
		config.CompressionLevel = 0 // No compression

		enc, err := NewEncryptor(config)
		if err != nil {
			b.Fatalf("Failed to create encryptor: %v", err)
		}

		err = enc.EncryptFiles([]FileEntry{{SourcePath: testFile}})
		if err != nil {
			b.Fatalf("Failed to encrypt: %v", err)
		}

		os.Remove(outputPath)
	}
}

// BenchmarkEncryptMaxCompression benchmarks encryption with maximum compression
func BenchmarkEncryptMaxCompression(b *testing.B) {
	tmpDir := b.TempDir()
	size := int64(10 * 1024 * 1024) // 10MB

	testFile := createBenchFile(b, tmpDir, size)
	password := "BenchmarkPassword123!"

	b.ResetTimer()
	b.SetBytes(size)

	for i := 0; i < b.N; i++ {
		outputPath := filepath.Join(tmpDir, "bench_output.zip")

		config := DefaultConfig()
		config.Password = password
		config.OutputPath = outputPath
		config.CompressionLevel = 9 // Maximum compression

		enc, err := NewEncryptor(config)
		if err != nil {
			b.Fatalf("Failed to create encryptor: %v", err)
		}

		err = enc.EncryptFiles([]FileEntry{{SourcePath: testFile}})
		if err != nil {
			b.Fatalf("Failed to encrypt: %v", err)
		}

		os.Remove(outputPath)
	}
}

// BenchmarkEncryptMultipleFiles benchmarks encryption of multiple files
func BenchmarkEncryptMultipleFiles(b *testing.B) {
	tmpDir := b.TempDir()

	// Create 10 files of 1MB each
	var files []FileEntry
	var totalSize int64
	for i := 0; i < 10; i++ {
		path := filepath.Join(tmpDir, "file"+string(rune('0'+i))+".bin")
		file, _ := os.Create(path)
		data := make([]byte, 1024*1024)
		rand.Read(data)
		file.Write(data)
		file.Close()
		files = append(files, FileEntry{SourcePath: path})
		totalSize += int64(len(data))
	}

	password := "BenchmarkPassword123!"

	b.ResetTimer()
	b.SetBytes(totalSize)

	for i := 0; i < b.N; i++ {
		outputPath := filepath.Join(tmpDir, "bench_output.zip")

		config := DefaultConfig()
		config.Password = password
		config.OutputPath = outputPath

		enc, err := NewEncryptor(config)
		if err != nil {
			b.Fatalf("Failed to create encryptor: %v", err)
		}

		err = enc.EncryptFiles(files)
		if err != nil {
			b.Fatalf("Failed to encrypt: %v", err)
		}

		os.Remove(outputPath)
	}
}

// BenchmarkEncryptAES128 benchmarks AES-128 encryption
func BenchmarkEncryptAES128(b *testing.B) {
	benchmarkEncryptMethod(b, AES128)
}

// BenchmarkEncryptAES192 benchmarks AES-192 encryption
func BenchmarkEncryptAES192(b *testing.B) {
	benchmarkEncryptMethod(b, AES192)
}

// BenchmarkEncryptAES256 benchmarks AES-256 encryption
func BenchmarkEncryptAES256(b *testing.B) {
	benchmarkEncryptMethod(b, AES256)
}

func benchmarkEncryptMethod(b *testing.B, method EncryptionMethod) {
	tmpDir := b.TempDir()
	size := int64(10 * 1024 * 1024) // 10MB

	testFile := createBenchFile(b, tmpDir, size)
	password := "BenchmarkPassword123!"

	b.ResetTimer()
	b.SetBytes(size)

	for i := 0; i < b.N; i++ {
		outputPath := filepath.Join(tmpDir, "bench_output.zip")

		config := DefaultConfig()
		config.Password = password
		config.OutputPath = outputPath
		config.Method = method

		enc, err := NewEncryptor(config)
		if err != nil {
			b.Fatalf("Failed to create encryptor: %v", err)
		}

		err = enc.EncryptFiles([]FileEntry{{SourcePath: testFile}})
		if err != nil {
			b.Fatalf("Failed to encrypt: %v", err)
		}

		os.Remove(outputPath)
	}
}

// BenchmarkPasswordGeneration benchmarks password generation
func BenchmarkPasswordGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := GeneratePassword(32)
		if err != nil {
			b.Fatalf("Failed to generate password: %v", err)
		}
	}
}

// BenchmarkSecureDelete1MB benchmarks secure deletion of 1MB file
func BenchmarkSecureDelete1MB(b *testing.B) {
	tmpDir := b.TempDir()

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// Create a new file for each iteration
		path := filepath.Join(tmpDir, "delete.bin")
		file, _ := os.Create(path)
		data := make([]byte, 1024*1024)
		file.Write(data)
		file.Close()
		b.StartTimer()

		err := SecureDelete(path, 3)
		if err != nil {
			b.Fatalf("SecureDelete failed: %v", err)
		}
	}
}

// BenchmarkBufferSizes compares different buffer sizes
func BenchmarkBufferSize8KB(b *testing.B) {
	benchmarkBufferSize(b, 8*1024)
}

func BenchmarkBufferSize32KB(b *testing.B) {
	benchmarkBufferSize(b, 32*1024)
}

func BenchmarkBufferSize64KB(b *testing.B) {
	benchmarkBufferSize(b, 64*1024)
}

func BenchmarkBufferSize128KB(b *testing.B) {
	benchmarkBufferSize(b, 128*1024)
}

func benchmarkBufferSize(b *testing.B, bufSize int) {
	tmpDir := b.TempDir()
	size := int64(10 * 1024 * 1024) // 10MB

	testFile := createBenchFile(b, tmpDir, size)
	password := "BenchmarkPassword123!"

	b.ResetTimer()
	b.SetBytes(size)

	for i := 0; i < b.N; i++ {
		outputPath := filepath.Join(tmpDir, "bench_output.zip")

		config := DefaultConfig()
		config.Password = password
		config.OutputPath = outputPath
		config.BufferSize = bufSize

		enc, err := NewEncryptor(config)
		if err != nil {
			b.Fatalf("Failed to create encryptor: %v", err)
		}

		err = enc.EncryptFiles([]FileEntry{{SourcePath: testFile}})
		if err != nil {
			b.Fatalf("Failed to encrypt: %v", err)
		}

		os.Remove(outputPath)
	}
}

