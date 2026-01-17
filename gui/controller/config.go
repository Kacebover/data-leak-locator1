package controller

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
)

// AppConfig holds all application configuration
type AppConfig struct {
	// Scan settings
	MaxFileSize       int64    `json:"max_file_size"`
	Concurrency       int      `json:"concurrency"`
	FollowSymlinks    bool     `json:"follow_symlinks"`
	ScanBinaries      bool     `json:"scan_binaries"`
	IncludeExtensions []string `json:"include_extensions"`
	ExcludeExtensions []string `json:"exclude_extensions"`
	IncludeDirs       []string `json:"include_dirs"`
	ExcludeDirs       []string `json:"exclude_dirs"`
	
	// UI settings
	Theme             string `json:"theme"` // "dark", "light", "system"
	ShowNotifications bool   `json:"show_notifications"`
	ConfirmDestructive bool  `json:"confirm_destructive"`
	MaskSensitiveData bool   `json:"mask_sensitive_data"`
	
	// Window settings
	WindowWidth  int `json:"window_width"`
	WindowHeight int `json:"window_height"`
	WindowX      int `json:"window_x"`
	WindowY      int `json:"window_y"`
	
	// Export settings
	DefaultExportDir string `json:"default_export_dir"`
	ExportFormat     string `json:"export_format"` // "json", "csv", "all"
	
	// Recent directories
	RecentDirs []string `json:"recent_dirs"`
	
	// Feature flags
	OCREnabled bool `json:"ocr_enabled"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() *AppConfig {
	homeDir, _ := os.UserHomeDir()
	
	return &AppConfig{
		MaxFileSize:       100 * 1024 * 1024, // 100MB
		Concurrency:       runtime.NumCPU(),
		FollowSymlinks:    false,
		ScanBinaries:      false,
		IncludeExtensions: nil,
		ExcludeExtensions: []string{".exe", ".dll", ".so", ".dylib", ".zip", ".tar", ".gz", ".rar", ".7z", ".jpg", ".png", ".gif", ".pdf", ".iso", ".mp3", ".mp4", ".avi", ".mov"},
		IncludeDirs:       nil,
		ExcludeDirs:       []string{".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "target", "build", "dist"},
		
		Theme:              "system",
		ShowNotifications:  true,
		ConfirmDestructive: true,
		MaskSensitiveData:  true,
		
		WindowWidth:  1400,
		WindowHeight: 900,
		WindowX:      -1,
		WindowY:      -1,
		
		DefaultExportDir: filepath.Join(homeDir, "DataLeakReports"),
		ExportFormat:     "all",
		
		RecentDirs: []string{},
		
		OCREnabled: false,
	}
}

// getConfigDir returns the configuration directory path
func getConfigDir() string {
	var configDir string
	
	switch runtime.GOOS {
	case "windows":
		configDir = os.Getenv("APPDATA")
		if configDir == "" {
			configDir = filepath.Join(os.Getenv("USERPROFILE"), "AppData", "Roaming")
		}
	case "darwin":
		homeDir, _ := os.UserHomeDir()
		configDir = filepath.Join(homeDir, "Library", "Application Support")
	default: // linux and others
		configDir = os.Getenv("XDG_CONFIG_HOME")
		if configDir == "" {
			homeDir, _ := os.UserHomeDir()
			configDir = filepath.Join(homeDir, ".config")
		}
	}
	
	appConfigDir := filepath.Join(configDir, "DataLeakLocator")
	_ = os.MkdirAll(appConfigDir, 0755)
	
	return appConfigDir
}

// getConfigPath returns the full path to the config file
func getConfigPath() string {
	return filepath.Join(getConfigDir(), "config.json")
}

// LoadConfig loads configuration from disk or returns defaults
func LoadConfig() *AppConfig {
	config := DefaultConfig()
	
	data, err := os.ReadFile(getConfigPath())
	if err != nil {
		return config
	}
	
	if err := json.Unmarshal(data, config); err != nil {
		return DefaultConfig()
	}
	
	return config
}

// SaveConfig saves configuration to disk
func SaveConfig(config *AppConfig) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	
	return os.WriteFile(getConfigPath(), data, 0644)
}

// AddRecentDir adds a directory to the recent list
func (c *AppConfig) AddRecentDir(dir string) {
	// Remove if already exists
	newDirs := make([]string, 0, len(c.RecentDirs)+1)
	newDirs = append(newDirs, dir)
	
	for _, d := range c.RecentDirs {
		if d != dir {
			newDirs = append(newDirs, d)
		}
	}
	
	// Keep only last 10
	if len(newDirs) > 10 {
		newDirs = newDirs[:10]
	}
	
	c.RecentDirs = newDirs
}

// ValidateConfig validates and normalizes configuration values
func (c *AppConfig) ValidateConfig() {
	// Ensure sensible ranges
	if c.MaxFileSize < 1024 {
		c.MaxFileSize = 1024 // 1KB minimum
	}
	if c.MaxFileSize > 1024*1024*1024 {
		c.MaxFileSize = 1024 * 1024 * 1024 // 1GB maximum
	}
	
	if c.Concurrency < 1 {
		c.Concurrency = 1
	}
	if c.Concurrency > 64 {
		c.Concurrency = 64
	}
	
	if c.WindowWidth < 800 {
		c.WindowWidth = 800
	}
	if c.WindowHeight < 600 {
		c.WindowHeight = 600
	}
}

// Clone creates a deep copy of the config
func (c *AppConfig) Clone() *AppConfig {
	clone := *c
	
	// Deep copy slices
	if c.IncludeExtensions != nil {
		clone.IncludeExtensions = make([]string, len(c.IncludeExtensions))
		copy(clone.IncludeExtensions, c.IncludeExtensions)
	}
	if c.ExcludeExtensions != nil {
		clone.ExcludeExtensions = make([]string, len(c.ExcludeExtensions))
		copy(clone.ExcludeExtensions, c.ExcludeExtensions)
	}
	if c.IncludeDirs != nil {
		clone.IncludeDirs = make([]string, len(c.IncludeDirs))
		copy(clone.IncludeDirs, c.IncludeDirs)
	}
	if c.ExcludeDirs != nil {
		clone.ExcludeDirs = make([]string, len(c.ExcludeDirs))
		copy(clone.ExcludeDirs, c.ExcludeDirs)
	}
	if c.RecentDirs != nil {
		clone.RecentDirs = make([]string, len(c.RecentDirs))
		copy(clone.RecentDirs, c.RecentDirs)
	}
	
	return &clone
}

// FormatFileSize formats bytes to human readable string
func FormatFileSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return formatInt(bytes) + " B"
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return formatFloat(float64(bytes)/float64(div)) + " " + []string{"KB", "MB", "GB", "TB"}[exp]
}

func formatInt(n int64) string {
	s := ""
	for n > 0 {
		if len(s) > 0 && len(s)%3 == 0 {
			s = "," + s
		}
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	if s == "" {
		return "0"
	}
	return s
}

func formatFloat(f float64) string {
	// Simple float formatting
	i := int64(f * 100)
	whole := i / 100
	frac := i % 100
	if frac == 0 {
		return formatInt(whole)
	}
	return formatInt(whole) + "." + string(rune('0'+frac/10)) + string(rune('0'+frac%10))
}

// ParseFileSize parses a human readable file size string to bytes
func ParseFileSize(s string) int64 {
	// Simple implementation
	var size int64
	var unit string
	
	for i, c := range s {
		if c >= '0' && c <= '9' {
			size = size*10 + int64(c-'0')
		} else {
			unit = s[i:]
			break
		}
	}
	
	switch unit {
	case "KB", "kb", "K", "k":
		return size * 1024
	case "MB", "mb", "M", "m":
		return size * 1024 * 1024
	case "GB", "gb", "G", "g":
		return size * 1024 * 1024 * 1024
	case "TB", "tb", "T", "t":
		return size * 1024 * 1024 * 1024 * 1024
	default:
		return size
	}
}

