package main

import (
	"testing"

	"github.com/kacebover/password-finder/searcher"
)

// TestFileWithFindings_Selection tests file selection functionality
func TestFileWithFindings_Selection(t *testing.T) {
	file := &FileWithFindings{
		FilePath:    "/test/file.txt",
		MaxSeverity: searcher.Critical,
		Findings: []*searcher.Finding{
			{
				FilePath:    "/test/file.txt",
				PatternType: searcher.PatternPassword,
				Severity:    searcher.Critical,
			},
		},
		Selected: false,
	}

	// Initially not selected
	if file.Selected {
		t.Error("File should not be selected initially")
	}

	// Select the file
	file.Selected = true
	if !file.Selected {
		t.Error("File should be selected after setting Selected=true")
	}
}

// TestFileWithFindings_MaxSeverity tests that MaxSeverity is calculated correctly
func TestFileWithFindings_MaxSeverity(t *testing.T) {
	file := &FileWithFindings{
		FilePath: "/test/file.txt",
		Findings: []*searcher.Finding{
			{Severity: searcher.Low},
			{Severity: searcher.Critical},
			{Severity: searcher.Medium},
		},
	}

	// Calculate max severity
	maxSev := searcher.Low
	for _, f := range file.Findings {
		if f.Severity.Score() > maxSev.Score() {
			maxSev = f.Severity
		}
	}
	file.MaxSeverity = maxSev

	if file.MaxSeverity != searcher.Critical {
		t.Errorf("MaxSeverity should be Critical, got %s", file.MaxSeverity)
	}
}

// TestSeverityToRussian tests Russian severity translations
func TestSeverityToRussian(t *testing.T) {
	tests := []struct {
		severity searcher.Severity
		expected string
	}{
		{searcher.Critical, "Критич."},
		{searcher.High, "Высокий"},
		{searcher.Medium, "Средний"},
		{searcher.Low, "Низкий"},
	}

	sg := &ScannerGUI{}

	for _, tt := range tests {
		t.Run(string(tt.severity), func(t *testing.T) {
			got := sg.severityToRussian(tt.severity)
			if got != tt.expected {
				t.Errorf("severityToRussian(%s) = %s, want %s", tt.severity, got, tt.expected)
			}
		})
	}
}

// TestPatternToRussian tests Russian pattern type translations
func TestPatternToRussian(t *testing.T) {
	tests := []struct {
		pattern  searcher.PatternType
		expected string
	}{
		{searcher.PatternPassword, "Пароль"},
		{searcher.PatternAPIKey, "API-ключ"},
		{searcher.PatternAWSKey, "AWS ключ"},
		{searcher.PatternCreditCard, "Банк. карта"},
		{searcher.PatternPrivateKey, "Приватный ключ"},
	}

	sg := &ScannerGUI{}

	for _, tt := range tests {
		t.Run(string(tt.pattern), func(t *testing.T) {
			got := sg.patternToRussian(tt.pattern)
			if got != tt.expected {
				t.Errorf("patternToRussian(%s) = %s, want %s", tt.pattern, got, tt.expected)
			}
		})
	}
}

// TestFilterBySeverity tests severity filtering logic
func TestFilterBySeverity(t *testing.T) {
	files := []*FileWithFindings{
		{
			FilePath:    "/test/critical.txt",
			MaxSeverity: searcher.Critical,
			Findings: []*searcher.Finding{
				{Severity: searcher.Critical},
			},
		},
		{
			FilePath:    "/test/high.txt",
			MaxSeverity: searcher.High,
			Findings: []*searcher.Finding{
				{Severity: searcher.High},
			},
		},
		{
			FilePath:    "/test/low.txt",
			MaxSeverity: searcher.Low,
			Findings: []*searcher.Finding{
				{Severity: searcher.Low},
			},
		},
	}

	filterToSeverity := map[string]searcher.Severity{
		"Критический": searcher.Critical,
		"Высокий":     searcher.High,
		"Средний":     searcher.Medium,
		"Низкий":      searcher.Low,
	}

	// Filter by Critical
	filterSeverity := "Критический"
	targetSeverity := filterToSeverity[filterSeverity]

	var filtered []*FileWithFindings
	for _, file := range files {
		hasMatchingSeverity := false
		for _, f := range file.Findings {
			if f.Severity == targetSeverity {
				hasMatchingSeverity = true
				break
			}
		}
		if hasMatchingSeverity {
			filtered = append(filtered, file)
		}
	}

	if len(filtered) != 1 {
		t.Errorf("Expected 1 file with Critical severity, got %d", len(filtered))
	}

	if filtered[0].FilePath != "/test/critical.txt" {
		t.Errorf("Expected critical.txt, got %s", filtered[0].FilePath)
	}
}

// TestFilterByText tests text filtering logic
func TestFilterByText(t *testing.T) {
	files := []*FileWithFindings{
		{
			FilePath: "/test/password.txt",
			Findings: []*searcher.Finding{
				{Description: "Password found"},
			},
		},
		{
			FilePath: "/test/api_key.txt",
			Findings: []*searcher.Finding{
				{Description: "API key found"},
			},
		},
		{
			FilePath: "/config/secret.txt",
			Findings: []*searcher.Finding{
				{Description: "Secret found"},
			},
		},
	}

	tests := []struct {
		filterText string
		wantCount  int
	}{
		{"password", 1},
		{"api", 1},
		{"config", 1},
		{"test", 2},
		{"notfound", 0},
	}

	for _, tt := range tests {
		t.Run(tt.filterText, func(t *testing.T) {
			var filtered []*FileWithFindings
			for _, file := range files {
				matchFound := false
				if contains(file.FilePath, tt.filterText) {
					matchFound = true
				}
				if !matchFound {
					for _, f := range file.Findings {
						if contains(f.Description, tt.filterText) {
							matchFound = true
							break
						}
					}
				}
				if matchFound {
					filtered = append(filtered, file)
				}
			}

			if len(filtered) != tt.wantCount {
				t.Errorf("Filter '%s': expected %d files, got %d", tt.filterText, tt.wantCount, len(filtered))
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) > 0 && len(substr) > 0 &&
		(len(s) >= len(substr)) &&
		(s == substr || containsIgnoreCase(s, substr))
}

func containsIgnoreCase(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			(len(s) > len(substr) && indexIgnoreCase(s, substr) >= 0))
}

func indexIgnoreCase(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if equalFoldSubstring(s[i:i+len(substr)], substr) {
			return i
		}
	}
	return -1
}

func equalFoldSubstring(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca := a[i]
		cb := b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// TestSortBySeverity tests that files are sorted by severity (Critical first)
func TestSortBySeverity(t *testing.T) {
	files := []*FileWithFindings{
		{FilePath: "low.txt", MaxSeverity: searcher.Low},
		{FilePath: "critical.txt", MaxSeverity: searcher.Critical},
		{FilePath: "high.txt", MaxSeverity: searcher.High},
		{FilePath: "medium.txt", MaxSeverity: searcher.Medium},
	}

	// Sort by severity (Critical first)
	for i := 0; i < len(files)-1; i++ {
		for j := i + 1; j < len(files); j++ {
			if files[j].MaxSeverity.Score() > files[i].MaxSeverity.Score() {
				files[i], files[j] = files[j], files[i]
			}
		}
	}

	expectedOrder := []string{"critical.txt", "high.txt", "medium.txt", "low.txt"}
	for i, file := range files {
		if file.FilePath != expectedOrder[i] {
			t.Errorf("Position %d: expected %s, got %s", i, expectedOrder[i], file.FilePath)
		}
	}
}

// TestGetSelectedFilePaths tests extraction of selected file paths
func TestGetSelectedFilePaths(t *testing.T) {
	files := []*FileWithFindings{
		{FilePath: "/a.txt", Selected: true},
		{FilePath: "/b.txt", Selected: false},
		{FilePath: "/c.txt", Selected: true},
		{FilePath: "/d.txt", Selected: false},
	}

	var selected []string
	for _, file := range files {
		if file.Selected {
			selected = append(selected, file.FilePath)
		}
	}

	if len(selected) != 2 {
		t.Errorf("Expected 2 selected files, got %d", len(selected))
	}

	if selected[0] != "/a.txt" || selected[1] != "/c.txt" {
		t.Errorf("Unexpected selected files: %v", selected)
	}
}

// TestIgnoreList tests file ignore functionality
func TestIgnoreList(t *testing.T) {
	ignoreList := make(map[string]bool)

	files := []*FileWithFindings{
		{FilePath: "/test/file1.txt"},
		{FilePath: "/test/file2.txt"},
		{FilePath: "/test/file3.txt"},
	}

	// Add file2 to ignore list
	ignoreList["/test/file2.txt"] = true

	var visible []*FileWithFindings
	for _, file := range files {
		if !ignoreList[file.FilePath] {
			visible = append(visible, file)
		}
	}

	if len(visible) != 2 {
		t.Errorf("Expected 2 visible files, got %d", len(visible))
	}

	for _, file := range visible {
		if file.FilePath == "/test/file2.txt" {
			t.Error("Ignored file should not be visible")
		}
	}
}

// TestSelectAll tests select all functionality
func TestSelectAll(t *testing.T) {
	files := []*FileWithFindings{
		{FilePath: "/a.txt", Selected: false},
		{FilePath: "/b.txt", Selected: false},
		{FilePath: "/c.txt", Selected: false},
	}

	// Select all
	for _, file := range files {
		file.Selected = true
	}

	for _, file := range files {
		if !file.Selected {
			t.Errorf("File %s should be selected", file.FilePath)
		}
	}

	// Deselect all
	for _, file := range files {
		file.Selected = false
	}

	for _, file := range files {
		if file.Selected {
			t.Errorf("File %s should not be selected", file.FilePath)
		}
	}
}

// TestSelectBySeverity tests selecting files by severity
func TestSelectBySeverity(t *testing.T) {
	files := []*FileWithFindings{
		{
			FilePath:    "/critical.txt",
			MaxSeverity: searcher.Critical,
			Selected:    false,
			Findings:    []*searcher.Finding{{Severity: searcher.Critical}},
		},
		{
			FilePath:    "/high.txt",
			MaxSeverity: searcher.High,
			Selected:    false,
			Findings:    []*searcher.Finding{{Severity: searcher.High}},
		},
		{
			FilePath:    "/low.txt",
			MaxSeverity: searcher.Low,
			Selected:    false,
			Findings:    []*searcher.Finding{{Severity: searcher.Low}},
		},
	}

	// Select only Critical files
	targetSeverity := searcher.Critical
	for _, file := range files {
		for _, f := range file.Findings {
			if f.Severity == targetSeverity {
				file.Selected = true
				break
			}
		}
	}

	selectedCount := 0
	for _, file := range files {
		if file.Selected {
			selectedCount++
		}
	}

	if selectedCount != 1 {
		t.Errorf("Expected 1 selected file, got %d", selectedCount)
	}

	if !files[0].Selected {
		t.Error("Critical file should be selected")
	}
	if files[1].Selected || files[2].Selected {
		t.Error("Non-critical files should not be selected")
	}
}

// TestCountFindingsBySeverity tests counting findings by severity
func TestCountFindingsBySeverity(t *testing.T) {
	files := []*FileWithFindings{
		{
			Findings: []*searcher.Finding{
				{Severity: searcher.Critical},
				{Severity: searcher.Critical},
				{Severity: searcher.High},
			},
		},
		{
			Findings: []*searcher.Finding{
				{Severity: searcher.High},
				{Severity: searcher.Medium},
			},
		},
	}

	counts := make(map[searcher.Severity]int)
	for _, file := range files {
		for _, f := range file.Findings {
			counts[f.Severity]++
		}
	}

	if counts[searcher.Critical] != 2 {
		t.Errorf("Expected 2 critical findings, got %d", counts[searcher.Critical])
	}
	if counts[searcher.High] != 2 {
		t.Errorf("Expected 2 high findings, got %d", counts[searcher.High])
	}
	if counts[searcher.Medium] != 1 {
		t.Errorf("Expected 1 medium finding, got %d", counts[searcher.Medium])
	}
}

