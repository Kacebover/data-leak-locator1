package searcher

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ScanEvent represents different types of events emitted during scanning
type ScanEvent struct {
	Type        ScanEventType
	Finding     *Finding
	FilePath    string
	Message     string
	Error       error
	Progress    ScanProgress
	Severity    Severity
	Timestamp   time.Time
}

// ScanEventType represents the type of scan event
type ScanEventType int

const (
	EventFinding ScanEventType = iota
	EventFileStarted
	EventFileCompleted
	EventFileSkipped
	EventError
	EventProgress
	EventLogInfo
	EventLogWarning
	EventLogError
	EventScanStarted
	EventScanPaused
	EventScanResumed
	EventScanCompleted
	EventScanCancelled
)

// ScanProgress represents current scan progress
type ScanProgress struct {
	FilesQueued     int64
	FilesProcessed  int64
	FilesSkipped    int64
	FindingsCount   int64
	ErrorCount      int64
	BytesScanned    int64
	CurrentFile     string
	ElapsedTime     time.Duration
	EstimatedTotal  int64
}

// ScanState represents the current state of the scanner
type ScanState int

const (
	StateIdle ScanState = iota
	StateRunning
	StatePaused
	StateCancelled
	StateCompleted
)

// StreamingScanner performs scans with real-time event streaming
type StreamingScanner struct {
	patterns          *Patterns
	ignoreList        *IgnoreList
	riskScorer        *RiskScorer
	entropyCalculator *EntropyCalculator
	
	// Configuration
	maxFileSize      int64
	maxConcurrent    int
	followSymlinks   bool
	scanBinaries     bool
	includeExts      map[string]bool
	excludeExts      map[string]bool
	includeDirs      []string
	excludeDirs      []string
	
	// State management
	state          atomic.Int32
	pauseChan      chan struct{}
	resumeChan     chan struct{}
	
	// Progress tracking
	filesQueued    atomic.Int64
	filesProcessed atomic.Int64
	filesSkipped   atomic.Int64
	findingsCount  atomic.Int64
	errorCount     atomic.Int64
	bytesScanned   atomic.Int64
	
	// Results
	result      *ScanResult
	resultMutex sync.Mutex
	startTime   time.Time
	
	// Event channel
	eventChan chan ScanEvent
}

// StreamingScannerConfig holds configuration for the streaming scanner
type StreamingScannerConfig struct {
	MaxFileSize    int64
	MaxConcurrent  int
	FollowSymlinks bool
	ScanBinaries   bool
	IncludeExts    []string
	ExcludeExts    []string
	IncludeDirs    []string
	ExcludeDirs    []string
}

// DefaultStreamingScannerConfig returns default configuration
func DefaultStreamingScannerConfig() StreamingScannerConfig {
	return StreamingScannerConfig{
		MaxFileSize:    MaxFileSize,
		MaxConcurrent:  MaxConcurrentFiles,
		FollowSymlinks: false,
		ScanBinaries:   false,
		IncludeExts:    nil,
		ExcludeExts:    nil,
		IncludeDirs:    nil,
		ExcludeDirs:    nil,
	}
}

// NewStreamingScanner creates a new streaming scanner
func NewStreamingScanner(config StreamingScannerConfig) *StreamingScanner {
	includeExts := make(map[string]bool)
	for _, ext := range config.IncludeExts {
		includeExts[strings.ToLower(ext)] = true
	}
	
	excludeExts := make(map[string]bool)
	for _, ext := range config.ExcludeExts {
		excludeExts[strings.ToLower(ext)] = true
	}
	
	return &StreamingScanner{
		patterns:          NewPatterns(),
		ignoreList:        NewIgnoreList(),
		riskScorer:        NewRiskScorer(),
		entropyCalculator: NewEntropyCalculator(),
		maxFileSize:       config.MaxFileSize,
		maxConcurrent:     config.MaxConcurrent,
		followSymlinks:    config.FollowSymlinks,
		scanBinaries:      config.ScanBinaries,
		includeExts:       includeExts,
		excludeExts:       excludeExts,
		includeDirs:       config.IncludeDirs,
		excludeDirs:       config.ExcludeDirs,
		pauseChan:         make(chan struct{}),
		resumeChan:        make(chan struct{}),
		eventChan:         make(chan ScanEvent, 1000),
	}
}

// Events returns the event channel for receiving scan events
func (ss *StreamingScanner) Events() <-chan ScanEvent {
	return ss.eventChan
}

// GetState returns the current scan state
func (ss *StreamingScanner) GetState() ScanState {
	return ScanState(ss.state.Load())
}

// GetProgress returns current scan progress
func (ss *StreamingScanner) GetProgress() ScanProgress {
	return ScanProgress{
		FilesQueued:    ss.filesQueued.Load(),
		FilesProcessed: ss.filesProcessed.Load(),
		FilesSkipped:   ss.filesSkipped.Load(),
		FindingsCount:  ss.findingsCount.Load(),
		ErrorCount:     ss.errorCount.Load(),
		BytesScanned:   ss.bytesScanned.Load(),
		ElapsedTime:    time.Since(ss.startTime),
	}
}

// Pause pauses the scan
func (ss *StreamingScanner) Pause() {
	if ss.state.CompareAndSwap(int32(StateRunning), int32(StatePaused)) {
		ss.emitEvent(ScanEvent{Type: EventScanPaused, Message: "Scan paused", Timestamp: time.Now()})
	}
}

// Resume resumes a paused scan
func (ss *StreamingScanner) Resume() {
	if ss.state.CompareAndSwap(int32(StatePaused), int32(StateRunning)) {
		select {
		case ss.resumeChan <- struct{}{}:
		default:
		}
		ss.emitEvent(ScanEvent{Type: EventScanResumed, Message: "Scan resumed", Timestamp: time.Now()})
	}
}

// IsPaused returns true if the scanner is paused
func (ss *StreamingScanner) IsPaused() bool {
	return ss.GetState() == StatePaused
}

// Scan starts a scan with context for cancellation
func (ss *StreamingScanner) Scan(ctx context.Context, rootDir string) (*ScanResult, error) {
	ss.startTime = time.Now()
	ss.state.Store(int32(StateRunning))
	ss.result = NewScanResult()
	ss.result.StartTime = ss.startTime.Unix()
	
	// Reset counters
	ss.filesQueued.Store(0)
	ss.filesProcessed.Store(0)
	ss.filesSkipped.Store(0)
	ss.findingsCount.Store(0)
	ss.errorCount.Store(0)
	ss.bytesScanned.Store(0)
	
	// Initialize ignore list
	ss.ignoreList.AddDefaultIgnores()
	for _, dir := range ss.excludeDirs {
		ss.ignoreList.AddIgnoreDir(dir)
	}
	
	// Try to load .dataLeak-ignore file
	ignoreFilePath := filepath.Join(rootDir, ".dataLeak-ignore")
	_ = ss.ignoreList.LoadFromFile(ignoreFilePath)
	
	ss.emitEvent(ScanEvent{
		Type:      EventScanStarted,
		Message:   "Scan started: " + rootDir,
		Timestamp: time.Now(),
	})
	
	// Create worker pool
	fileChan := make(chan string, 1000)
	var wg sync.WaitGroup
	
	// Start workers
	for i := 0; i < ss.maxConcurrent; i++ {
		wg.Add(1)
		go ss.worker(ctx, fileChan, &wg)
	}
	
	// Start directory walker
	go func() {
		defer close(fileChan)
		ss.walkDirectory(ctx, rootDir, fileChan)
	}()
	
	// Wait for all workers to complete
	wg.Wait()
	
	// Finalize result
	ss.resultMutex.Lock()
	ss.result.EndTime = time.Now().Unix()
	ss.result.FilesScanned = int(ss.filesProcessed.Load())
	ss.result.FilesSkipped = int(ss.filesSkipped.Load())
	ss.result.TotalSize = ss.bytesScanned.Load()
	ss.result.ErrorCount = int(ss.errorCount.Load())
	result := ss.result
	ss.resultMutex.Unlock()
	
	// Emit completion event
	if ctx.Err() != nil {
		ss.state.Store(int32(StateCancelled))
		ss.emitEvent(ScanEvent{
			Type:      EventScanCancelled,
			Message:   "Scan cancelled",
			Progress:  ss.GetProgress(),
			Timestamp: time.Now(),
		})
	} else {
		ss.state.Store(int32(StateCompleted))
		ss.emitEvent(ScanEvent{
			Type:      EventScanCompleted,
			Message:   "Scan completed",
			Progress:  ss.GetProgress(),
			Timestamp: time.Now(),
		})
	}
	
	// Close event channel
	close(ss.eventChan)
	
	return result, ctx.Err()
}

// worker processes files from the channel
func (ss *StreamingScanner) worker(ctx context.Context, fileChan <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	
	for {
		select {
		case <-ctx.Done():
			return
		case filePath, ok := <-fileChan:
			if !ok {
				return
			}
			
			// Check for pause
			for ss.GetState() == StatePaused {
				select {
				case <-ctx.Done():
					return
				case <-ss.resumeChan:
					// Resume
				case <-time.After(100 * time.Millisecond):
					// Check again
				}
			}
			
			ss.scanFile(ctx, filePath)
		}
	}
}

// walkDirectory recursively walks directories
func (ss *StreamingScanner) walkDirectory(ctx context.Context, dir string, fileChan chan<- string) {
	select {
	case <-ctx.Done():
		return
	default:
	}
	
	entries, err := os.ReadDir(dir)
	if err != nil {
		ss.errorCount.Add(1)
		ss.emitEvent(ScanEvent{
			Type:      EventError,
			FilePath:  dir,
			Error:     err,
			Message:   "Failed to read directory: " + err.Error(),
			Timestamp: time.Now(),
		})
		return
	}
	
	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return
		default:
		}
		
		fullPath := filepath.Join(dir, entry.Name())
		
		if ss.ignoreList.ShouldIgnorePath(fullPath) {
			continue
		}
		
		if entry.IsDir() {
			if !ss.ignoreList.ShouldIgnoreDirectory(fullPath) {
				ss.walkDirectory(ctx, fullPath, fileChan)
			}
		} else {
			// Check file extension filters
			ext := strings.ToLower(filepath.Ext(fullPath))
			if len(ss.includeExts) > 0 && !ss.includeExts[ext] {
				ss.filesSkipped.Add(1)
				continue
			}
			if ss.excludeExts[ext] {
				ss.filesSkipped.Add(1)
				continue
			}
			
			ss.filesQueued.Add(1)
			select {
			case fileChan <- fullPath:
			case <-ctx.Done():
				return
			}
		}
	}
}

// scanFile scans a single file
func (ss *StreamingScanner) scanFile(ctx context.Context, filePath string) {
	select {
	case <-ctx.Done():
		return
	default:
	}
	
	ss.emitEvent(ScanEvent{
		Type:      EventFileStarted,
		FilePath:  filePath,
		Timestamp: time.Now(),
	})
	
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		ss.errorCount.Add(1)
		ss.emitEvent(ScanEvent{
			Type:      EventError,
			FilePath:  filePath,
			Error:     err,
			Message:   "Failed to stat file: " + err.Error(),
			Timestamp: time.Now(),
		})
		return
	}
	
	// Skip files that are too large
	if fileInfo.Size() > ss.maxFileSize {
		ss.filesSkipped.Add(1)
		ss.emitEvent(ScanEvent{
			Type:      EventFileSkipped,
			FilePath:  filePath,
			Message:   "File too large",
			Timestamp: time.Now(),
		})
		return
	}
	
	// Check symlinks
	if !ss.followSymlinks {
		if fileInfo.Mode()&os.ModeSymlink != 0 {
			ss.filesSkipped.Add(1)
			ss.emitEvent(ScanEvent{
				Type:      EventFileSkipped,
				FilePath:  filePath,
				Message:   "Symlink skipped",
				Timestamp: time.Now(),
			})
			return
		}
	}
	
	// Check if binary
	if !ss.scanBinaries && ss.isBinaryFile(filePath) {
		ss.filesSkipped.Add(1)
		ss.emitEvent(ScanEvent{
			Type:      EventFileSkipped,
			FilePath:  filePath,
			Message:   "Binary file skipped",
			Timestamp: time.Now(),
		})
		return
	}
	
	// Scan file content
	findings, err := ss.scanFileContent(ctx, filePath)
	if err != nil {
		ss.errorCount.Add(1)
		ss.emitEvent(ScanEvent{
			Type:      EventError,
			FilePath:  filePath,
			Error:     err,
			Message:   "Failed to scan file: " + err.Error(),
			Timestamp: time.Now(),
		})
		return
	}
	
	// Add findings
	for _, finding := range findings {
		ss.resultMutex.Lock()
		ss.result.AddFinding(finding)
		ss.resultMutex.Unlock()
		
		ss.findingsCount.Add(1)
		ss.emitEvent(ScanEvent{
			Type:      EventFinding,
			Finding:   finding,
			FilePath:  filePath,
			Severity:  finding.Severity,
			Timestamp: time.Now(),
		})
	}
	
	ss.filesProcessed.Add(1)
	ss.bytesScanned.Add(fileInfo.Size())
	
	// Emit progress event periodically
	if ss.filesProcessed.Load()%10 == 0 {
		ss.emitEvent(ScanEvent{
			Type:      EventProgress,
			Progress:  ss.GetProgress(),
			Timestamp: time.Now(),
		})
	}
	
	ss.emitEvent(ScanEvent{
		Type:      EventFileCompleted,
		FilePath:  filePath,
		Timestamp: time.Now(),
	})
}

// scanFileContent scans file content for sensitive patterns
func (ss *StreamingScanner) scanFileContent(ctx context.Context, filePath string) ([]*Finding, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	var findings []*Finding
	scanner := bufio.NewScanner(file)
	lineNum := 1
	
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}
		
		line := scanner.Text()
		
		if strings.TrimSpace(line) == "" {
			lineNum++
			continue
		}
		
		patterns := ss.patterns.FindAll(line)
		for _, pattern := range patterns {
			pattern.LineNumber = lineNum
			pattern.FilePath = filePath
			pattern.Context = line
			pattern.EntropyScore = ss.entropyCalculator.CalculateEntropy(pattern.MatchText)
			
			riskScore := ss.riskScorer.CalculateRiskScore(pattern)
			
			finding := &Finding{
				FilePath:     filePath,
				LineNumber:   lineNum,
				ColumnStart:  pattern.StartIndex,
				ColumnEnd:    pattern.EndIndex,
				PatternType:  pattern.Type,
				Severity:     pattern.Severity,
				Description:  pattern.Description,
				MatchedText:  pattern.MatchText,
				Context:      line,
				EntropyScore: pattern.EntropyScore,
				RiskScore:    riskScore,
			}
			
			findings = append(findings, finding)
		}
		
		lineNum++
	}
	
	return findings, scanner.Err()
}

// isBinaryFile checks if a file is likely binary
func (ss *StreamingScanner) isBinaryFile(filePath string) bool {
	file, err := os.Open(filePath)
	if err != nil {
		return true
	}
	defer file.Close()
	
	buf := make([]byte, 512)
	n, _ := file.Read(buf)
	
	if n == 0 {
		return false
	}
	
	for i := 0; i < n; i++ {
		if buf[i] == 0 {
			return true
		}
	}
	
	return false
}

// emitEvent sends an event to the event channel
func (ss *StreamingScanner) emitEvent(event ScanEvent) {
	select {
	case ss.eventChan <- event:
	default:
		// Channel full, drop event
	}
}

// GetResult returns the current scan result
func (ss *StreamingScanner) GetResult() *ScanResult {
	ss.resultMutex.Lock()
	defer ss.resultMutex.Unlock()
	return ss.result
}

// UpdateConfig updates scanner configuration
func (ss *StreamingScanner) UpdateConfig(config StreamingScannerConfig) {
	ss.maxFileSize = config.MaxFileSize
	ss.maxConcurrent = config.MaxConcurrent
	ss.followSymlinks = config.FollowSymlinks
	ss.scanBinaries = config.ScanBinaries
	
	ss.includeExts = make(map[string]bool)
	for _, ext := range config.IncludeExts {
		ss.includeExts[strings.ToLower(ext)] = true
	}
	
	ss.excludeExts = make(map[string]bool)
	for _, ext := range config.ExcludeExts {
		ss.excludeExts[strings.ToLower(ext)] = true
	}
	
	ss.includeDirs = config.IncludeDirs
	ss.excludeDirs = config.ExcludeDirs
}

