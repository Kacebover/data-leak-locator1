package searcher

import (
	"sync"
	"time"
)

// Severity represents the risk level of a detected pattern
type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
)

// SeverityScore returns a numeric score for severity (higher = more severe)
func (s Severity) Score() int {
	switch s {
	case Critical:
		return 4
	case High:
		return 3
	case Medium:
		return 2
	case Low:
		return 1
	default:
		return 0
	}
}

// DetectedPattern represents a single pattern match with context
type DetectedPattern struct {
	Type         PatternType
	Pattern      string
	Severity     Severity
	Description  string
	StartIndex   int
	EndIndex     int
	MatchText    string
	LineNumber   int     // Set during file scanning
	FilePath     string  // Set during file scanning
	Context      string  // Line context where match was found
	EntropyScore float64 // Entropy score if applicable
}

// Finding represents a complete finding with all details
type Finding struct {
	FilePath     string
	LineNumber   int
	ColumnStart  int
	ColumnEnd    int
	PatternType  PatternType
	Severity     Severity
	Description  string
	MatchedText  string
	Context      string // The full line of context
	EntropyScore float64
	RiskScore    float64 // Combined score including entropy
}

// ScanResult holds all results from a scan
type ScanResult struct {
	Findings        []*Finding
	FilesScanned    int
	FilesSkipped    int
	StartTime       int64
	EndTime         int64
	TotalSize       int64
	ErrorCount      int
	SeveritySummary map[Severity]int
	SkipReasons     map[string]string // file path -> reason
	mu              sync.Mutex        // Protects concurrent access
}

// NewScanResult creates a new ScanResult
func NewScanResult() *ScanResult {
	return &ScanResult{
		Findings:        make([]*Finding, 0),
		SeveritySummary: make(map[Severity]int),
		SkipReasons:     make(map[string]string),
	}
}

// AddSkipReason records why a file was skipped (thread-safe)
func (sr *ScanResult) AddSkipReason(filePath, reason string) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.SkipReasons[filePath] = reason
}

// AddFinding adds a finding to the result (thread-safe)
func (sr *ScanResult) AddFinding(finding *Finding) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.Findings = append(sr.Findings, finding)
	sr.SeveritySummary[finding.Severity]++
}

// GetSeverityCount returns the count of findings for a specific severity (thread-safe)
func (sr *ScanResult) GetSeverityCount(severity Severity) int {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	return sr.SeveritySummary[severity]
}

// TotalFindings returns the total number of findings (thread-safe)
func (sr *ScanResult) TotalFindings() int {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	return len(sr.Findings)
}

// IncrementFilesScanned increments the files scanned counter (thread-safe)
func (sr *ScanResult) IncrementFilesScanned() {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.FilesScanned++
}

// IncrementFilesSkipped increments the files skipped counter (thread-safe)
func (sr *ScanResult) IncrementFilesSkipped() {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.FilesSkipped++
}

// IncrementErrorCount increments the error counter (thread-safe)
func (sr *ScanResult) IncrementErrorCount() {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.ErrorCount++
}

// AddTotalSize adds to the total size counter (thread-safe)
func (sr *ScanResult) AddTotalSize(size int64) {
	sr.mu.Lock()
	defer sr.mu.Unlock()
	sr.TotalSize += size
}

// GeneratedAt returns the time when the scan ended
func (sr *ScanResult) GeneratedAt() time.Time {
	return time.Unix(sr.EndTime, 0)
}
