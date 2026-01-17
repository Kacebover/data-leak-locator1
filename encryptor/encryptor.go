// Package encryptor provides secure file encryption functionality
// using AES-256 encrypted ZIP archives.
package encryptor

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/alexmullins/zip"
)

// Common errors
var (
	ErrEmptyPassword   = errors.New("password cannot be empty")
	ErrNoFiles         = errors.New("no files provided for encryption")
	ErrFileNotFound    = errors.New("file not found")
	ErrPermissionDenied = errors.New("permission denied")
	ErrInvalidOutput   = errors.New("invalid output path")
)

// EncryptionMethod specifies the ZIP encryption method
// The alexmullins/zip library uses AES-256 by default which is the most secure option
type EncryptionMethod int

const (
	// AES256 uses AES-256 encryption (recommended, secure)
	// This is the default and only method supported by this package
	AES256 EncryptionMethod = iota
	// AES128 uses AES-128 encryption (not currently supported, reserved for future use)
	AES128
	// AES192 uses AES-192 encryption (not currently supported, reserved for future use)
	AES192
)

// ProgressCallback is called during encryption to report progress
// bytesProcessed: total bytes written so far
// totalBytes: total bytes to be written (estimated)
// currentFile: name of the file currently being processed
type ProgressCallback func(bytesProcessed, totalBytes int64, currentFile string)

// Config holds encryption configuration
type Config struct {
	// Password for the encrypted archive (required, min 1 character)
	Password string

	// OutputPath is the full path for the output ZIP file
	OutputPath string

	// Method specifies the encryption method (default: AES256)
	Method EncryptionMethod

	// CompressionLevel: 0 = store only, 1-9 = deflate compression levels
	CompressionLevel int

	// PreserveStructure preserves directory structure in the archive
	PreserveStructure bool

	// BasePath is used when PreserveStructure is true to calculate relative paths
	BasePath string

	// OnProgress is called to report encryption progress
	OnProgress ProgressCallback

	// BufferSize for streaming operations (default: 32KB)
	BufferSize int
}

// DefaultConfig returns a Config with sensible defaults
func DefaultConfig() Config {
	return Config{
		Method:            AES256,
		CompressionLevel:  6,
		PreserveStructure: true,
		BufferSize:        32 * 1024, // 32KB
	}
}

// Encryptor handles file encryption operations
type Encryptor struct {
	config Config
	mu     sync.Mutex

	// Progress tracking
	bytesProcessed int64
	totalBytes     int64
	currentFile    string
	cancelled      int32
	filesEncrypted int32
}

// NewEncryptor creates a new Encryptor with the given config
func NewEncryptor(config Config) (*Encryptor, error) {
	if config.Password == "" {
		return nil, ErrEmptyPassword
	}

	if config.OutputPath == "" {
		return nil, ErrInvalidOutput
	}

	if config.BufferSize <= 0 {
		config.BufferSize = 32 * 1024
	}

	if config.CompressionLevel < 0 {
		config.CompressionLevel = 0
	}
	if config.CompressionLevel > 9 {
		config.CompressionLevel = 9
	}

	return &Encryptor{
		config: config,
	}, nil
}

// FileEntry represents a file to be encrypted
type FileEntry struct {
	// SourcePath is the absolute path to the source file
	SourcePath string

	// ArchivePath is the path within the archive (optional, derived from SourcePath if empty)
	ArchivePath string
}

// EncryptFiles encrypts the given files into a password-protected ZIP archive
func (e *Encryptor) EncryptFiles(files []FileEntry) error {
	if len(files) == 0 {
		return ErrNoFiles
	}

	// Reset state
	atomic.StoreInt32(&e.cancelled, 0)
	atomic.StoreInt64(&e.bytesProcessed, 0)
	atomic.StoreInt32(&e.filesEncrypted, 0)

	// Calculate total size and validate files
	var totalSize int64
	validFiles := make([]FileEntry, 0, len(files))

	for _, file := range files {
		info, err := os.Stat(file.SourcePath)
		if err != nil {
			if os.IsNotExist(err) {
				return fmt.Errorf("%w: %s", ErrFileNotFound, file.SourcePath)
			}
			if os.IsPermission(err) {
				return fmt.Errorf("%w: %s", ErrPermissionDenied, file.SourcePath)
			}
			return fmt.Errorf("failed to stat file %s: %w", file.SourcePath, err)
		}

		if info.IsDir() {
			// Recursively add directory contents
			dirFiles, dirSize, err := e.walkDirectory(file.SourcePath)
			if err != nil {
				return err
			}
			validFiles = append(validFiles, dirFiles...)
			totalSize += dirSize
		} else {
			totalSize += info.Size()
			validFiles = append(validFiles, file)
		}
	}

	if len(validFiles) == 0 {
		return ErrNoFiles
	}

	atomic.StoreInt64(&e.totalBytes, totalSize)

	// Create output directory if needed
	outputDir := filepath.Dir(e.config.OutputPath)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Create the ZIP file
	zipFile, err := os.Create(e.config.OutputPath)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer zipFile.Close()

	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Process each file
	for _, file := range validFiles {
		if atomic.LoadInt32(&e.cancelled) == 1 {
			// Clean up partial file on cancellation
			zipWriter.Close()
			zipFile.Close()
			os.Remove(e.config.OutputPath)
			return fmt.Errorf("encryption cancelled")
		}

		if err := e.addFileToArchive(zipWriter, file); err != nil {
			// Clean up on error
			zipWriter.Close()
			zipFile.Close()
			os.Remove(e.config.OutputPath)
			return err
		}
	}

	return nil
}

// Cancel cancels an ongoing encryption operation
func (e *Encryptor) Cancel() {
	atomic.StoreInt32(&e.cancelled, 1)
}

// walkDirectory recursively collects files from a directory
func (e *Encryptor) walkDirectory(dirPath string) ([]FileEntry, int64, error) {
	var files []FileEntry
	var totalSize int64

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() {
			relPath, err := filepath.Rel(dirPath, path)
			if err != nil {
				relPath = filepath.Base(path)
			}

			files = append(files, FileEntry{
				SourcePath:  path,
				ArchivePath: filepath.Join(filepath.Base(dirPath), relPath),
			})
			totalSize += info.Size()
		}

		return nil
	})

	return files, totalSize, err
}

// addFileToArchive adds a single file to the ZIP archive
func (e *Encryptor) addFileToArchive(zipWriter *zip.Writer, file FileEntry) error {
	// Open source file
	srcFile, err := os.Open(file.SourcePath)
	if err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("%w: %s", ErrPermissionDenied, file.SourcePath)
		}
		return fmt.Errorf("failed to open file %s: %w", file.SourcePath, err)
	}
	defer srcFile.Close()

	// Determine archive path
	archivePath := file.ArchivePath
	if archivePath == "" {
		if e.config.PreserveStructure && e.config.BasePath != "" {
			relPath, err := filepath.Rel(e.config.BasePath, file.SourcePath)
			if err == nil {
				archivePath = relPath
			} else {
				archivePath = filepath.Base(file.SourcePath)
			}
		} else {
			archivePath = filepath.Base(file.SourcePath)
		}
	}

	// Normalize path separators for ZIP
	archivePath = strings.ReplaceAll(archivePath, string(os.PathSeparator), "/")

	// Update current file for progress reporting
	e.currentFile = archivePath
	e.reportProgress()

	// Create encrypted writer for this file
	// The alexmullins/zip library uses AES-256 encryption by default
	writer, err := zipWriter.Encrypt(archivePath, e.config.Password)
	if err != nil {
		return fmt.Errorf("failed to create encrypted archive entry for %s: %w", file.SourcePath, err)
	}

	// Copy file content with progress tracking
	buf := make([]byte, e.config.BufferSize)
	for {
		if atomic.LoadInt32(&e.cancelled) == 1 {
			return fmt.Errorf("encryption cancelled")
		}

		n, readErr := srcFile.Read(buf)
		if n > 0 {
			_, writeErr := writer.Write(buf[:n])
			if writeErr != nil {
				return fmt.Errorf("failed to write to archive: %w", writeErr)
			}

			atomic.AddInt64(&e.bytesProcessed, int64(n))
			e.reportProgress()
		}

		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return fmt.Errorf("failed to read file %s: %w", file.SourcePath, readErr)
		}
	}

	// Increment files encrypted counter
	atomic.AddInt32(&e.filesEncrypted, 1)

	return nil
}

// reportProgress calls the progress callback if configured
func (e *Encryptor) reportProgress() {
	if e.config.OnProgress != nil {
		e.config.OnProgress(
			atomic.LoadInt64(&e.bytesProcessed),
			atomic.LoadInt64(&e.totalBytes),
			e.currentFile,
		)
	}
}

// GeneratePassword generates a cryptographically secure random password
// of the specified length using alphanumeric characters and symbols.
func GeneratePassword(length int) (string, error) {
	if length < 8 {
		length = 8
	}
	if length > 128 {
		length = 128
	}

	// Character set for password generation
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"

	password := make([]byte, length)
	randomBytes := make([]byte, length)

	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	for i := 0; i < length; i++ {
		password[i] = charset[randomBytes[i]%byte(len(charset))]
	}

	return string(password), nil
}

// GenerateAlphanumericPassword generates a password using only alphanumeric characters
// (easier to type and share)
func GenerateAlphanumericPassword(length int) (string, error) {
	if length < 8 {
		length = 8
	}
	if length > 128 {
		length = 128
	}

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	password := make([]byte, length)
	randomBytes := make([]byte, length)

	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	for i := 0; i < length; i++ {
		password[i] = charset[randomBytes[i]%byte(len(charset))]
	}

	return string(password), nil
}

// ValidatePassword checks if a password meets minimum security requirements
func ValidatePassword(password string) error {
	if password == "" {
		return ErrEmptyPassword
	}
	if len(password) < 4 {
		return errors.New("password must be at least 4 characters")
	}
	return nil
}

// SecureDelete securely deletes a file by overwriting it multiple times
// before removing it. This provides better protection than simple deletion.
// passes: number of overwrite passes (recommended: 3)
func SecureDelete(filePath string, passes int) error {
	if passes < 1 {
		passes = 1
	}
	if passes > 10 {
		passes = 10
	}

	// Open file for writing
	file, err := os.OpenFile(filePath, os.O_WRONLY, 0)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // File doesn't exist, nothing to delete
		}
		return fmt.Errorf("failed to open file for secure deletion: %w", err)
	}

	// Get file size
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return fmt.Errorf("failed to stat file: %w", err)
	}
	size := info.Size()

	if size == 0 {
		file.Close()
		return os.Remove(filePath)
	}

	// Prepare buffer
	bufSize := int64(32 * 1024)
	if size < bufSize {
		bufSize = size
	}
	buf := make([]byte, bufSize)

	// Perform overwrite passes
	for pass := 0; pass < passes; pass++ {
		// Seek to beginning
		if _, err := file.Seek(0, 0); err != nil {
			file.Close()
			return fmt.Errorf("failed to seek: %w", err)
		}

		// Determine pattern for this pass
		var pattern byte
		switch pass % 3 {
		case 0:
			pattern = 0x00 // Zeros
		case 1:
			pattern = 0xFF // Ones
		case 2:
			// Random data
			if _, err := rand.Read(buf); err != nil {
				file.Close()
				return fmt.Errorf("failed to generate random data: %w", err)
			}
		}

		// Fill buffer with pattern (if not random)
		if pass%3 != 2 {
			for i := range buf {
				buf[i] = pattern
			}
		}

		// Write pattern to entire file
		remaining := size
		for remaining > 0 {
			writeSize := bufSize
			if remaining < bufSize {
				writeSize = remaining
			}

			if pass%3 == 2 && writeSize < bufSize {
				// Generate fresh random data for last chunk
				if _, err := rand.Read(buf[:writeSize]); err != nil {
					file.Close()
					return fmt.Errorf("failed to generate random data: %w", err)
				}
			}

			if _, err := file.Write(buf[:writeSize]); err != nil {
				file.Close()
				return fmt.Errorf("failed to overwrite file: %w", err)
			}

			remaining -= writeSize
		}

		// Sync to disk
		if err := file.Sync(); err != nil {
			file.Close()
			return fmt.Errorf("failed to sync file: %w", err)
		}
	}

	file.Close()

	// Finally remove the file
	return os.Remove(filePath)
}

// SecureDeleteMultiple securely deletes multiple files
func SecureDeleteMultiple(filePaths []string, passes int, onProgress func(current int, total int, path string)) error {
	total := len(filePaths)
	for i, path := range filePaths {
		if onProgress != nil {
			onProgress(i+1, total, path)
		}
		if err := SecureDelete(path, passes); err != nil {
			return fmt.Errorf("failed to securely delete %s: %w", path, err)
		}
	}
	return nil
}

// Result contains the result of an encryption operation
type Result struct {
	// OutputPath is the path to the created archive
	OutputPath string

	// FilesEncrypted is the number of files added to the archive
	FilesEncrypted int

	// TotalSize is the total uncompressed size of encrypted files
	TotalSize int64

	// ArchiveSize is the size of the resulting archive
	ArchiveSize int64

	// CompressionRatio is the compression ratio (archive size / total size)
	CompressionRatio float64
}

// EncryptFilesWithResult encrypts files and returns detailed result
func (e *Encryptor) EncryptFilesWithResult(files []FileEntry) (*Result, error) {
	if err := e.EncryptFiles(files); err != nil {
		return nil, err
	}

	// Get archive info
	archiveInfo, err := os.Stat(e.config.OutputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to stat output archive: %w", err)
	}

	totalSize := atomic.LoadInt64(&e.totalBytes)
	archiveSize := archiveInfo.Size()
	filesCount := int(atomic.LoadInt32(&e.filesEncrypted))

	var ratio float64
	if totalSize > 0 {
		ratio = float64(archiveSize) / float64(totalSize)
	}

	return &Result{
		OutputPath:       e.config.OutputPath,
		FilesEncrypted:   filesCount,
		TotalSize:        totalSize,
		ArchiveSize:      archiveSize,
		CompressionRatio: ratio,
	}, nil
}

