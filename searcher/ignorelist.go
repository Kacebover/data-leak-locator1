package searcher

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// IgnoreList manages file/directory exclusions and pattern whitelisting
type IgnoreList struct {
	ignorePatterns   []*regexp.Regexp
	ignoreDirs       map[string]bool
	ignoreFiles      map[string]bool
	ignoreExtensions map[string]bool
}

// NewIgnoreList creates a new IgnoreList
func NewIgnoreList() *IgnoreList {
	return &IgnoreList{
		ignorePatterns:   make([]*regexp.Regexp, 0),
		ignoreDirs:       make(map[string]bool),
		ignoreFiles:      make(map[string]bool),
		ignoreExtensions: make(map[string]bool),
	}
}

// AddDefaultIgnores adds common directories and files to ignore
func (il *IgnoreList) AddDefaultIgnores() {
	// Directories
	defaultDirs := []string{
		".git", ".hg", ".svn", ".bzr",
		"node_modules", "vendor", ".cargo",
		"target", "build", "dist", "out",
		".venv", "venv", ".env", "__pycache__",
		"coverage", ".coverage", ".tox",
	}

	for _, dir := range defaultDirs {
		il.ignoreDirs[dir] = true
	}

	// Files
	defaultFiles := []string{
		".gitignore", ".env", ".env.local",
		"package-lock.json", "yarn.lock",
	}

	for _, file := range defaultFiles {
		il.ignoreFiles[file] = true
	}

	// Extensions (binary files, logs)
	defaultExts := []string{
		".exe", ".dll", ".so", ".dylib",
		".zip", ".tar", ".gz", ".rar", ".7z",
		".jpg", ".png", ".gif", ".pdf", ".iso",
		".mp3", ".mp4", ".avi", ".mov",
		".log", ".bak", ".tmp", ".swp",
	}

	for _, ext := range defaultExts {
		il.ignoreExtensions[strings.ToLower(ext)] = true
	}
}

// AddPattern adds a glob pattern to the ignore list
func (il *IgnoreList) AddPattern(pattern string) error {
	// Convert glob pattern to regex
	regexPattern := globToRegex(pattern)
	regex, err := regexp.Compile(regexPattern)
	if err != nil {
		return err
	}

	il.ignorePatterns = append(il.ignorePatterns, regex)
	return nil
}

// AddIgnoreDir marks a directory to be ignored
func (il *IgnoreList) AddIgnoreDir(dir string) {
	il.ignoreDirs[filepath.Base(dir)] = true
}

// AddIgnoreFile marks a file to be ignored
func (il *IgnoreList) AddIgnoreFile(file string) {
	il.ignoreFiles[filepath.Base(file)] = true
}

// AddIgnoreExtension marks a file extension to be ignored
func (il *IgnoreList) AddIgnoreExtension(ext string) {
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	il.ignoreExtensions[strings.ToLower(ext)] = true
}

// RemoveIgnoreExtension removes a file extension from the ignore list
func (il *IgnoreList) RemoveIgnoreExtension(ext string) {
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	delete(il.ignoreExtensions, strings.ToLower(ext))
}

// EnableDocumentScanning removes document extensions from ignore list
func (il *IgnoreList) EnableDocumentScanning() {
	docExts := []string{".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".odt", ".ods", ".odp"}
	for _, ext := range docExts {
		il.RemoveIgnoreExtension(ext)
	}
}

// EnableImageScanning removes image extensions from ignore list
func (il *IgnoreList) EnableImageScanning() {
	imageExts := []string{".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".tif", ".webp"}
	for _, ext := range imageExts {
		il.RemoveIgnoreExtension(ext)
	}
}

// EnableArchiveScanning removes archive extensions from ignore list
func (il *IgnoreList) EnableArchiveScanning() {
	archiveExts := []string{".zip", ".tar", ".gz", ".tgz", ".rar", ".7z", ".bz2", ".xz"}
	for _, ext := range archiveExts {
		il.RemoveIgnoreExtension(ext)
	}
}

// ShouldIgnorePath returns true if the path should be ignored
func (il *IgnoreList) ShouldIgnorePath(path string) bool {
	// Check if file extension should be ignored
	if il.shouldIgnoreByExtension(path) {
		return true
	}

	// Check if file name should be ignored
	baseName := filepath.Base(path)
	if il.ignoreFiles[baseName] {
		return true
	}

	// Check directory components
	parts := strings.Split(path, string(filepath.Separator))
	for _, part := range parts {
		if il.ignoreDirs[part] {
			return true
		}
	}

	// Check regex patterns
	for _, pattern := range il.ignorePatterns {
		if pattern.MatchString(path) {
			return true
		}
	}

	return false
}

// ShouldIgnoreDirectory returns true if the directory should be ignored
func (il *IgnoreList) ShouldIgnoreDirectory(dirPath string) bool {
	dirName := filepath.Base(dirPath)
	return il.ignoreDirs[dirName]
}

// shouldIgnoreByExtension checks if file extension should be ignored
func (il *IgnoreList) shouldIgnoreByExtension(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return il.ignoreExtensions[ext]
}

// LoadFromFile loads ignore patterns from a .dataLeak-ignore file
func (il *IgnoreList) LoadFromFile(filePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		// File doesn't exist is not an error
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Process pattern
		if strings.HasPrefix(line, "/") {
			// Directory pattern
			il.AddIgnoreDir(line[1:])
		} else if strings.HasPrefix(line, "*.") {
			// Extension pattern
			il.AddIgnoreExtension(line[1:])
		} else if strings.Contains(line, "*") || strings.Contains(line, "?") {
			// Glob pattern
			il.AddPattern(line)
		} else {
			// Literal file or directory name
			il.ignoreFiles[line] = true
		}
	}

	return scanner.Err()
}

// globToRegex converts a glob pattern to a regex pattern
func globToRegex(pattern string) string {
	var regex strings.Builder
	regex.WriteString("^")

	for i := 0; i < len(pattern); i++ {
		c := pattern[i]

		switch c {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				// ** matches any number of directories
				regex.WriteString(".*")
				i++ // Skip next *
			} else {
				// * matches anything except /
				regex.WriteString("[^/]*")
			}
		case '?':
			// ? matches any single character except /
			regex.WriteString("[^/]")
		case '.', '+', '^', '$', '(', ')', '[', ']', '{', '}', '|', '\\':
			// Escape regex special characters
			regex.WriteByte('\\')
			regex.WriteByte(c)
		default:
			regex.WriteByte(c)
		}
	}

	regex.WriteString("$")
	return regex.String()
}

// IsEmpty returns true if the ignore list has no patterns
func (il *IgnoreList) IsEmpty() bool {
	return len(il.ignorePatterns) == 0 &&
		len(il.ignoreDirs) == 0 &&
		len(il.ignoreFiles) == 0 &&
		len(il.ignoreExtensions) == 0
}
