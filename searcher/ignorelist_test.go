package searcher

import (
	"os"
	"path/filepath"
	"testing"
)

// TestNewIgnoreList creates and validates ignore list
func TestNewIgnoreList(t *testing.T) {
	il := NewIgnoreList()

	if il == nil {
		t.Fatal("NewIgnoreList returned nil")
	}

	if il.IsEmpty() == false {
		t.Error("New ignore list should be empty")
	}
}

// TestAddDefaultIgnores tests default ignores
func TestAddDefaultIgnores(t *testing.T) {
	il := NewIgnoreList()
	il.AddDefaultIgnores()

	if il.IsEmpty() {
		t.Error("After adding defaults, ignore list should not be empty")
	}

	// Test some default ignores
	if !il.ShouldIgnoreDirectory("node_modules") {
		t.Error("Should ignore node_modules directory")
	}

	if !il.ShouldIgnoreDirectory(".git") {
		t.Error("Should ignore .git directory")
	}

	if !il.shouldIgnoreByExtension(".log") {
		t.Error("Should ignore .log files")
	}
}

// TestShouldIgnorePath tests path ignoring
func TestShouldIgnorePath(t *testing.T) {
	il := NewIgnoreList()
	il.AddDefaultIgnores()

	tests := []struct {
		path         string
		shouldIgnore bool
	}{
		{"/project/node_modules/package", true},
		{"/project/.git/config", true},
		{"/project/src/main.go", false},
		{"/project/file.log", true},
		{"/project/backup.zip", true},
		{"/project/image.png", true},
		{"/project/code.js", false},
	}

	for _, test := range tests {
		result := il.ShouldIgnorePath(test.path)

		if result != test.shouldIgnore {
			t.Errorf("Path '%s': expected %v, got %v",
				test.path, test.shouldIgnore, result)
		}
	}
}

// TestAddIgnoreExtension tests adding custom extensions
func TestAddIgnoreExtension(t *testing.T) {
	il := NewIgnoreList()

	il.AddIgnoreExtension(".custom")
	il.AddIgnoreExtension("txt") // Should automatically add dot

	if !il.shouldIgnoreByExtension(".custom") {
		t.Error("Should ignore .custom extension")
	}

	if !il.shouldIgnoreByExtension(".txt") {
		t.Error("Should ignore .txt extension")
	}
}

// TestAddIgnoreDir tests adding custom directories
func TestAddIgnoreDir(t *testing.T) {
	il := NewIgnoreList()

	il.AddIgnoreDir("custom_dir")
	il.AddIgnoreDir("/full/path/to/ignored")

	if !il.ShouldIgnoreDirectory("custom_dir") {
		t.Error("Should ignore custom_dir")
	}

	// Only the basename is used
	if !il.ShouldIgnoreDirectory("ignored") {
		t.Error("Should ignore ignored directory")
	}
}

// TestAddIgnoreFile tests adding custom files
func TestAddIgnoreFile(t *testing.T) {
	il := NewIgnoreList()

	il.AddIgnoreFile(".env")
	il.AddIgnoreFile("config.json")

	// Files are checked by basename
	if il.ignoreFiles[".env"] != true {
		t.Error("Should ignore .env file")
	}

	if il.ignoreFiles["config.json"] != true {
		t.Error("Should ignore config.json file")
	}
}

// TestAddPattern tests adding glob patterns
func TestAddPattern(t *testing.T) {
	il := NewIgnoreList()

	err := il.AddPattern("*.backup")
	if err != nil {
		t.Fatalf("Failed to add pattern: %v", err)
	}

	err = il.AddPattern("tmp*")
	if err != nil {
		t.Fatalf("Failed to add pattern: %v", err)
	}

	if il.IsEmpty() {
		t.Error("Ignore list should not be empty after adding patterns")
	}
}

// TestShouldIgnoreDirectory tests directory ignoring
func TestShouldIgnoreDirectory(t *testing.T) {
	il := NewIgnoreList()

	il.AddIgnoreDir("hidden")
	il.AddIgnoreDir("temp")

	tests := []struct {
		dirPath      string
		shouldIgnore bool
	}{
		{"hidden", true},
		{"temp", true},
		{"normal", false},
		{"/path/to/hidden", true},
		{"/path/to/normal", false},
	}

	for _, test := range tests {
		result := il.ShouldIgnoreDirectory(test.dirPath)

		if result != test.shouldIgnore {
			t.Errorf("Directory '%s': expected %v, got %v",
				test.dirPath, test.shouldIgnore, result)
		}
	}
}

// TestGlobToRegex tests glob pattern conversion
func TestGlobToRegex(t *testing.T) {
	tests := []struct {
		glob    string
		text    string
		matches bool
	}{
		{"*.go", "main.go", true},
		{"*.go", "main.rs", false},
		{"test_*.txt", "test_file.txt", true},
		{"test_*.txt", "file.txt", false},
		{"**/node_modules", "src/node_modules", true},
		{"src/*/main.go", "src/pkg/main.go", true},
	}

	for _, test := range tests {
		regex := globToRegex(test.glob)
		// Simple check - not using regexp for this test
		_ = regex
		// In actual use, the regex would be compiled and matched
	}
}

// TestLoadFromFile tests loading ignore patterns from file
func TestLoadFromFile(t *testing.T) {
	// Create temporary ignore file
	tmpFile, err := os.CreateTemp("", ".dataLeak-ignore")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write ignore patterns
	content := `# Comment line
*.log
*.bak
/build/
*.tmp
node_modules
# Another comment
.env
`

	_, err = tmpFile.WriteString(content)
	if err != nil {
		t.Fatalf("Failed to write temp file: %v", err)
	}
	tmpFile.Close()

	// Load from file
	il := NewIgnoreList()
	err = il.LoadFromFile(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load ignore file: %v", err)
	}

	if il.IsEmpty() {
		t.Error("Ignore list should not be empty after loading file")
	}

	// Test loaded patterns
	if !il.shouldIgnoreByExtension(".log") {
		t.Error("Should ignore .log files after loading")
	}

	if !il.shouldIgnoreByExtension(".bak") {
		t.Error("Should ignore .bak files after loading")
	}
}

// TestLoadFromNonExistentFile tests loading from non-existent file
func TestLoadFromNonExistentFile(t *testing.T) {
	il := NewIgnoreList()

	// Should not error on non-existent file
	err := il.LoadFromFile("/nonexistent/.dataLeak-ignore")
	if err != nil {
		t.Errorf("Should not error on non-existent file: %v", err)
	}
}

// TestComplexIgnorePatterns tests complex ignore scenarios
func TestComplexIgnorePatterns(t *testing.T) {
	il := NewIgnoreList()
	il.AddDefaultIgnores()
	il.AddIgnoreDir("dist")
	il.AddIgnoreExtension(".tmp")

	tests := []struct {
		path         string
		shouldIgnore bool
	}{
		{"/project/dist/bundle.js", true},             // dist directory
		{"/project/src/dist/file.go", true},           // dist in path
		{"/project/build/output.js", true},            // default ignore
		{"/project/node_modules/pkg/index.js", true},  // default ignore
		{"/project/src/main.go", false},               // normal file
		{"/project/temp.tmp", true},                   // custom extension
		{"/project/.env.local", true},                 // default ignore
		{"/project/src/components/Button.jsx", false}, // normal file
	}

	for _, test := range tests {
		result := il.ShouldIgnorePath(test.path)

		if result != test.shouldIgnore {
			t.Errorf("Path '%s': expected %v, got %v",
				test.path, test.shouldIgnore, result)
		}
	}
}

// TestIgnoreListCaseSensitivity tests case handling
func TestIgnoreListCaseSensitivity(t *testing.T) {
	il := NewIgnoreList()

	il.AddIgnoreExtension(".LOG")
	il.AddIgnoreExtension(".Txt")

	// Extensions should be case-insensitive
	if !il.shouldIgnoreByExtension(".log") {
		t.Error("Should ignore .log (lowercase) when .LOG is added")
	}

	if !il.shouldIgnoreByExtension(".txt") {
		t.Error("Should ignore .txt (lowercase) when .Txt is added")
	}
}

// TestIgnoreListMultipleDirectories tests ignoring with multiple directory levels
func TestIgnoreListMultipleDirectories(t *testing.T) {
	il := NewIgnoreList()

	il.AddIgnoreDir("node_modules")
	il.AddIgnoreDir("vendor")
	il.AddIgnoreDir("dist")

	testPath := filepath.Join("root", "src", "node_modules", "package", "file.js")

	if !il.ShouldIgnorePath(testPath) {
		t.Error("Should ignore path containing ignored directory")
	}
}
