package main

import (
	"fmt"
	"image/color"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/kacebover/password-finder/encryptor"
	"github.com/kacebover/password-finder/searcher"
)

// Colors
var (
	colorCritical = color.NRGBA{R: 220, G: 53, B: 69, A: 255}
	colorHigh     = color.NRGBA{R: 253, G: 126, B: 20, A: 255}
	colorMedium   = color.NRGBA{R: 255, G: 193, B: 7, A: 255}
	colorLow      = color.NRGBA{R: 40, G: 167, B: 69, A: 255}
)

// Settings holds app configuration
type Settings struct {
	MaxFileSize    int64
	Concurrency    int
	FollowSymlinks bool
	ScanBinaries   bool
	ExcludeDirs    []string
	ExcludeExts    []string
}

func defaultSettings() *Settings {
	return &Settings{
		MaxFileSize:    100 * 1024 * 1024,
		Concurrency:    runtime.NumCPU(),
		FollowSymlinks: false,
		ScanBinaries:   false,
		ExcludeDirs:    []string{".git", "node_modules", "vendor", ".venv", "venv", "__pycache__", "build", "dist"},
		ExcludeExts:    []string{".exe", ".dll", ".so", ".dylib", ".zip", ".tar", ".gz", ".jpg", ".png", ".gif", ".pdf"},
	}
}

// FileWithFindings groups all findings for a single file
type FileWithFindings struct {
	FilePath    string
	Findings    []*searcher.Finding
	Selected    bool
	MaxSeverity searcher.Severity
}

// ScannerGUI represents the GUI application
type ScannerGUI struct {
	app    fyne.App
	window fyne.Window

	// Input fields
	scanDir   *widget.Entry
	outputDir *widget.Entry

	// Buttons
	scanButton     *widget.Button
	pauseButton    *widget.Button
	cancelButton   *widget.Button
	exportButton   *widget.Button
	encryptButton  *widget.Button
	settingsButton *widget.Button

	// Progress
	progressBar   *widget.ProgressBar
	statusLabel   *widget.Label
	progressLabel *widget.Label

	// Statistics
	criticalLabel *widget.Label
	highLabel     *widget.Label
	mediumLabel   *widget.Label
	lowLabel      *widget.Label
	totalLabel    *widget.Label
	filesLabel    *widget.Label
	timeLabel     *widget.Label

	// Results - grouped by file
	filesList          *widget.List
	filesData          []*FileWithFindings
	filesMutex         sync.RWMutex
	detailContainer    *fyne.Container
	selectedFile       *FileWithFindings
	selectAllCheck     *widget.Check
	selectedCountLabel *widget.Label

	// Search/Filter
	searchEntry    *widget.Entry
	severitySelect *widget.Select
	fileTypeSelect *widget.Select
	filterText     string
	filterSeverity string
	filterFileType string

	// Scan options
	scanDocsCheck     *widget.Check
	scanArchivesCheck *widget.Check
	enableOCRCheck    *widget.Check
	enableAICheck     *widget.Check
	fileTypeFilter    *widget.Select

	// State
	resultData  *searcher.ScanResult
	scanning    atomic.Bool
	paused      atomic.Bool
	cancelled   atomic.Bool
	encrypting  atomic.Bool
	scanMutex   sync.Mutex
	settings    *Settings
	ignoreList  map[string]bool
	ignoreMutex sync.Mutex

	// Progress tracking
	filesQueued    atomic.Int64
	filesProcessed atomic.Int64
	findingsCount  atomic.Int64
	startTime      time.Time
}

// NewScannerGUI creates a new GUI instance
func NewScannerGUI() *ScannerGUI {
	a := app.NewWithID("com.dataleaklocator.app")
	w := a.NewWindow("🔍 Поиск Утечек Данных")
	w.Resize(fyne.NewSize(1400, 900))
	w.CenterOnScreen()

	sg := &ScannerGUI{
		app:        a,
		window:     w,
		filesData:  make([]*FileWithFindings, 0),
		settings:   defaultSettings(),
		ignoreList: make(map[string]bool),
	}

	sg.buildUI()
	sg.setupShortcuts()
	return sg
}

func (sg *ScannerGUI) buildUI() {
	// === HEADER ===
	titleText := canvas.NewText("🔍 Поиск Утечек Данных", theme.ForegroundColor())
	titleText.TextSize = 28
	titleText.TextStyle.Bold = true

	subtitleText := canvas.NewText("Сканер Безопасности", theme.ForegroundColor())
	subtitleText.TextSize = 14

	sg.settingsButton = widget.NewButton("⚙️ Настройки", sg.showSettings)
	sg.settingsButton.Importance = widget.LowImportance

	helpButton := widget.NewButton("❓ Справка", sg.showHelp)
	helpButton.Importance = widget.LowImportance

	header := container.NewBorder(
		nil, nil,
		container.NewVBox(titleText, subtitleText),
		container.NewHBox(sg.settingsButton, helpButton),
	)

	// === LEFT PANEL - CONTROLS ===
	leftPanel := sg.buildControlPanel()

	// === CENTER PANEL - RESULTS ===
	centerPanel := sg.buildResultsPanel()

	// === RIGHT PANEL - DETAILS ===
	rightPanel := sg.buildDetailsPanel()

	// === MAIN LAYOUT ===
	mainSplit := container.NewHSplit(
		container.NewHSplit(leftPanel, centerPanel),
		rightPanel,
	)
	mainSplit.SetOffset(0.55)

	content := container.NewBorder(
		container.NewVBox(container.NewPadded(header), widget.NewSeparator()),
		nil, nil, nil,
		mainSplit,
	)

	sg.window.SetContent(content)
}

func (sg *ScannerGUI) buildControlPanel() fyne.CanvasObject {
	// Target directory section
	dirLabel := widget.NewLabelWithStyle("📁 Целевая Директория", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	sg.scanDir = widget.NewEntry()
	sg.scanDir.SetPlaceHolder("Выберите или введите путь к директории...")

	browseBtn := widget.NewButton("📂 Обзор...", func() {
		dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
			if err != nil {
				dialog.ShowError(err, sg.window)
				return
			}
			if uri != nil {
				sg.scanDir.SetText(uri.Path())
			}
		}, sg.window)
	})
	browseBtn.Importance = widget.MediumImportance

	// Quick access buttons
	homeBtn := widget.NewButton("🏠 Домой", func() {
		home, _ := os.UserHomeDir()
		sg.scanDir.SetText(home)
	})
	homeBtn.Importance = widget.LowImportance

	testBtn := widget.NewButton("📂 Тест", func() {
		wd, _ := os.Getwd()
		sg.scanDir.SetText(filepath.Join(wd, "testdata"))
	})
	testBtn.Importance = widget.LowImportance

	cwdBtn := widget.NewButton("📁 Текущая", func() {
		wd, _ := os.Getwd()
		sg.scanDir.SetText(wd)
	})
	cwdBtn.Importance = widget.LowImportance

	quickButtons := container.NewHBox(homeBtn, testBtn, cwdBtn)

	dirSection := container.NewVBox(
		dirLabel,
		sg.scanDir,
		browseBtn,
		quickButtons,
	)

	// Output directory section
	outLabel := widget.NewLabelWithStyle("📊 Папка для Отчётов", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	sg.outputDir = widget.NewEntry()
	sg.outputDir.SetText("./reports")

	outBrowseBtn := widget.NewButton("📂 Обзор...", func() {
		dialog.ShowFolderOpen(func(uri fyne.ListableURI, err error) {
			if err == nil && uri != nil {
				sg.outputDir.SetText(uri.Path())
			}
		}, sg.window)
	})
	outBrowseBtn.Importance = widget.LowImportance

	outSection := container.NewVBox(
		outLabel,
		sg.outputDir,
		outBrowseBtn,
	)

	// File type filter section
	fileTypeLabel := widget.NewLabelWithStyle("📂 Типы Файлов", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	sg.fileTypeFilter = widget.NewSelect(
		[]string{
			"Все файлы",
			"Только текст/код (.txt, .json, .env, .go, .py...)",
			"Только документы (.pdf, .docx, .xlsx...)",
			"Только изображения (.png, .jpg, .gif...)",
			"Только архивы (.zip, .tar, .gz...)",
		},
		func(s string) {
			sg.filterFileType = s
		},
	)
	sg.fileTypeFilter.SetSelected("Все файлы")

	fileTypeHint := widget.NewLabel("Какие файлы сканировать")
	fileTypeHint.TextStyle.Italic = true

	fileTypeSection := container.NewVBox(
		fileTypeLabel,
		sg.fileTypeFilter,
		fileTypeHint,
	)

	// Additional scan options section
	optionsLabel := widget.NewLabelWithStyle("⚙️ Доп. Обработка", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	sg.scanDocsCheck = widget.NewCheck("📄 Извлекать текст из PDF/DOCX/XLSX", nil)
	sg.scanArchivesCheck = widget.NewCheck("📦 Сканировать внутри архивов", nil)
	sg.enableOCRCheck = widget.NewCheck("🔍 OCR для изображений (нужен Tesseract)", nil)
	sg.enableAICheck = widget.NewCheck("🤖 AI-анализ после скана (нужен Ollama)", nil)

	optionsSection := container.NewVBox(
		fileTypeSection,
		widget.NewSeparator(),
		optionsLabel,
		sg.scanDocsCheck,
		sg.scanArchivesCheck,
		sg.enableOCRCheck,
		sg.enableAICheck,
	)

	// Control buttons
	sg.scanButton = widget.NewButton("▶️ НАЧАТЬ СКАНИРОВАНИЕ", sg.onStartScan)
	sg.scanButton.Importance = widget.HighImportance

	sg.pauseButton = widget.NewButton("⏸️ Пауза", sg.onPauseScan)
	sg.pauseButton.Disable()

	sg.cancelButton = widget.NewButton("⏹️ Отмена", sg.onCancelScan)
	sg.cancelButton.Importance = widget.DangerImportance
	sg.cancelButton.Disable()

	sg.exportButton = widget.NewButton("💾 Экспорт Отчёта", sg.onExport)
	sg.exportButton.Disable()

	sg.encryptButton = widget.NewButton("🔐 Зашифровать", sg.onEncrypt)
	sg.encryptButton.Importance = widget.HighImportance
	sg.encryptButton.Disable()

	controlButtons := container.NewGridWithColumns(2,
		sg.scanButton, sg.pauseButton,
		sg.cancelButton, sg.exportButton,
	)

	encryptRow := container.NewVBox(
		widget.NewSeparator(),
		sg.encryptButton,
	)

	// Progress section
	progressLabel := widget.NewLabelWithStyle("📈 Прогресс", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	sg.progressBar = widget.NewProgressBar()
	sg.progressBar.Min = 0
	sg.progressBar.Max = 1
	sg.progressBar.SetValue(0)

	sg.progressLabel = widget.NewLabel("0 / 0 файлов")
	sg.statusLabel = widget.NewLabel("Готов к сканированию")
	sg.timeLabel = widget.NewLabel("Время: --")

	progressSection := container.NewVBox(
		progressLabel,
		sg.progressBar,
		container.NewHBox(sg.progressLabel, layout.NewSpacer(), sg.timeLabel),
		sg.statusLabel,
	)

	// Statistics section
	statsLabel := widget.NewLabelWithStyle("📊 Статистика", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	sg.totalLabel = widget.NewLabel("0")
	sg.totalLabel.TextStyle.Bold = true
	sg.criticalLabel = widget.NewLabel("0")
	sg.highLabel = widget.NewLabel("0")
	sg.mediumLabel = widget.NewLabel("0")
	sg.lowLabel = widget.NewLabel("0")
	sg.filesLabel = widget.NewLabel("0")

	statsGrid := container.NewGridWithColumns(5,
		container.NewVBox(widget.NewLabel("Всего"), sg.totalLabel),
		container.NewVBox(widget.NewLabel("🔴 Крит."), sg.criticalLabel),
		container.NewVBox(widget.NewLabel("🟠 Выс."), sg.highLabel),
		container.NewVBox(widget.NewLabel("🟡 Сред."), sg.mediumLabel),
		container.NewVBox(widget.NewLabel("🟢 Низ."), sg.lowLabel),
	)

	filesRow := container.NewHBox(
		widget.NewLabel("Файлов просканировано:"),
		sg.filesLabel,
	)

	statsSection := container.NewVBox(
		statsLabel,
		statsGrid,
		filesRow,
	)

	// Combine all sections
	leftContent := container.NewVBox(
		dirSection,
		widget.NewSeparator(),
		outSection,
		widget.NewSeparator(),
		optionsSection,
		widget.NewSeparator(),
		controlButtons,
		encryptRow,
		widget.NewSeparator(),
		progressSection,
		widget.NewSeparator(),
		statsSection,
	)

	scroll := container.NewScroll(leftContent)
	scroll.SetMinSize(fyne.NewSize(350, 0))

	return container.NewPadded(scroll)
}

func (sg *ScannerGUI) buildResultsPanel() fyne.CanvasObject {
	// Files list - grouped by file path
	sg.filesList = widget.NewList(
		func() int {
			sg.filesMutex.RLock()
			defer sg.filesMutex.RUnlock()
			return len(sg.getFilteredFiles())
		},
		func() fyne.CanvasObject {
			return sg.createFileItem()
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			sg.updateFileItem(id, obj)
		},
	)

	sg.filesList.OnSelected = func(id widget.ListItemID) {
		sg.filesMutex.RLock()
		filtered := sg.getFilteredFiles()
		if id < len(filtered) {
			sg.selectedFile = filtered[id]
		}
		sg.filesMutex.RUnlock()
		sg.updateDetailsPanel()
	}

	// Search and filter bar
	sg.searchEntry = widget.NewEntry()
	sg.searchEntry.SetPlaceHolder("🔍 Поиск по имени файла...")
	sg.searchEntry.OnChanged = func(s string) {
		sg.filterText = s
		sg.refreshFilesList()
	}

	sg.severitySelect = widget.NewSelect(
		[]string{"Все уровни", "Критический", "Высокий", "Средний", "Низкий"},
		func(s string) {
			sg.filterSeverity = s
			sg.refreshFilesList()
		},
	)
	sg.severitySelect.SetSelected("Все уровни")

	filterBar := container.NewBorder(nil, nil, nil, sg.severitySelect, sg.searchEntry)

	resultsHeader := widget.NewLabelWithStyle("📁 Файлы с уязвимостями", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	// Selection toolbar
	sg.selectAllCheck = widget.NewCheck("Выбрать все", func(checked bool) {
		sg.toggleSelectAll(checked)
	})

	sg.selectedCountLabel = widget.NewLabel("0 файлов выбрано")

	selectCriticalBtn := widget.NewButton("🔴 Крит.", func() {
		sg.selectBySeverity(searcher.Critical)
	})
	selectCriticalBtn.Importance = widget.DangerImportance

	selectHighBtn := widget.NewButton("🟠 Выс.", func() {
		sg.selectBySeverity(searcher.High)
	})
	selectHighBtn.Importance = widget.WarningImportance

	clearSelectionBtn := widget.NewButton("Сброс", func() {
		sg.toggleSelectAll(false)
		fyne.Do(func() {
			sg.selectAllCheck.SetChecked(false)
		})
	})
	clearSelectionBtn.Importance = widget.LowImportance

	selectionBar := container.NewHBox(
		sg.selectAllCheck,
		widget.NewSeparator(),
		selectCriticalBtn,
		selectHighBtn,
		layout.NewSpacer(),
		clearSelectionBtn,
	)

	selectedInfoBar := container.NewHBox(
		sg.selectedCountLabel,
		layout.NewSpacer(),
	)

	resultsPanel := container.NewBorder(
		container.NewVBox(resultsHeader, filterBar, widget.NewSeparator(), selectionBar, selectedInfoBar, widget.NewSeparator()),
		nil, nil, nil,
		sg.filesList,
	)

	return container.NewPadded(resultsPanel)
}

func (sg *ScannerGUI) createFileItem() fyne.CanvasObject {
	// Checkbox for selection
	checkbox := widget.NewCheck("", nil)

	// Severity icon
	severityIcon := canvas.NewRectangle(theme.ForegroundColor())
	severityIcon.CornerRadius = 6
	severityIcon.SetMinSize(fyne.NewSize(12, 12))

	fileName := widget.NewLabel("имя_файла.txt")
	fileName.TextStyle.Bold = true
	fileName.Truncation = fyne.TextTruncateEllipsis

	filePath := widget.NewLabel("/путь/к/файлу")
	filePath.Truncation = fyne.TextTruncateEllipsis

	findingsCount := widget.NewLabel("0 уязвимостей")

	iconContainer := container.NewCenter(severityIcon)

	return container.NewHBox(
		checkbox,
		iconContainer,
		container.NewVBox(fileName, filePath, findingsCount),
	)
}

func (sg *ScannerGUI) updateFileItem(id widget.ListItemID, obj fyne.CanvasObject) {
	sg.filesMutex.RLock()
	filtered := sg.getFilteredFiles()
	if id >= len(filtered) {
		sg.filesMutex.RUnlock()
		return
	}
	file := filtered[id]
	sg.filesMutex.RUnlock()

	hbox := obj.(*fyne.Container)
	checkbox := hbox.Objects[0].(*widget.Check)
	iconContainer := hbox.Objects[1].(*fyne.Container)
	rect := iconContainer.Objects[0].(*canvas.Rectangle)
	vbox := hbox.Objects[2].(*fyne.Container)
	fileNameLabel := vbox.Objects[0].(*widget.Label)
	filePathLabel := vbox.Objects[1].(*widget.Label)
	countLabel := vbox.Objects[2].(*widget.Label)

	// IMPORTANT: Disable callback before setting checked state to avoid the scrolling bug
	checkbox.OnChanged = nil
	checkbox.SetChecked(file.Selected)

	// Create a closure that captures the file path, not the index
	filePath := file.FilePath
	checkbox.OnChanged = func(checked bool) {
		sg.filesMutex.Lock()
		for _, f := range sg.filesData {
			if f.FilePath == filePath {
				f.Selected = checked
				break
			}
		}
		sg.filesMutex.Unlock()
		sg.updateSelectedCount()
		sg.updateEncryptButtonState()
	}

	// Set severity color based on max severity in file
	switch file.MaxSeverity {
	case searcher.Critical:
		rect.FillColor = colorCritical
	case searcher.High:
		rect.FillColor = colorHigh
	case searcher.Medium:
		rect.FillColor = colorMedium
	case searcher.Low:
		rect.FillColor = colorLow
	}
	rect.Refresh()

	// Count findings by severity
	var critical, high, medium, low int
	for _, f := range file.Findings {
		switch f.Severity {
		case searcher.Critical:
			critical++
		case searcher.High:
			high++
		case searcher.Medium:
			medium++
		case searcher.Low:
			low++
		}
	}

	// Show file name (can be long, so truncate if needed)
	fileName := filepath.Base(file.FilePath)
	if len(fileName) > 50 {
		fileName = truncatePath(fileName, 50)
	}
	fileNameLabel.SetText(fileName)

	// Show directory path (truncate to show beginning and end)
	dirPath := filepath.Dir(file.FilePath)
	if len(dirPath) > 60 {
		dirPath = truncatePath(dirPath, 60)
	}
	filePathLabel.SetText(dirPath)

	countParts := []string{}
	if critical > 0 {
		countParts = append(countParts, fmt.Sprintf("🔴%d", critical))
	}
	if high > 0 {
		countParts = append(countParts, fmt.Sprintf("🟠%d", high))
	}
	if medium > 0 {
		countParts = append(countParts, fmt.Sprintf("🟡%d", medium))
	}
	if low > 0 {
		countParts = append(countParts, fmt.Sprintf("🟢%d", low))
	}
	countLabel.SetText(fmt.Sprintf("%d уязвимостей: %s", len(file.Findings), strings.Join(countParts, " ")))
}

func (sg *ScannerGUI) severityToRussian(s searcher.Severity) string {
	switch s {
	case searcher.Critical:
		return "Критич."
	case searcher.High:
		return "Высокий"
	case searcher.Medium:
		return "Средний"
	case searcher.Low:
		return "Низкий"
	default:
		return string(s)
	}
}

func (sg *ScannerGUI) patternToRussian(p searcher.PatternType) string {
	switch p {
	case searcher.PatternPassword:
		return "Пароль"
	case searcher.PatternAPIKey:
		return "API-ключ"
	case searcher.PatternToken:
		return "Токен"
	case searcher.PatternPrivateKey:
		return "Приватный ключ"
	case searcher.PatternAWSKey:
		return "AWS ключ"
	case searcher.PatternGitHubToken:
		return "GitHub токен"
	case searcher.PatternEmail:
		return "Email"
	case searcher.PatternPhoneNumber:
		return "Телефон"
	case searcher.PatternSSN:
		return "SSN"
	case searcher.PatternCreditCard:
		return "Банк. карта"
	case searcher.PatternJSONSecret:
		return "JSON секрет"
	case searcher.PatternEnvVar:
		return "Перем. окружения"
	case searcher.PatternConnectionStr:
		return "Строка подключ."
	default:
		return string(p)
	}
}

func (sg *ScannerGUI) descriptionToRussian(desc string) string {
	translations := map[string]string{
		"Password assignment detected":             "Обнаружено присвоение пароля",
		"API Key detected":                         "Обнаружен API-ключ",
		"Authentication token detected":            "Обнаружен токен аутентификации",
		"Private key detected":                     "Обнаружен приватный ключ",
		"AWS Access Key detected":                  "Обнаружен AWS ключ доступа",
		"GitHub token detected":                    "Обнаружен GitHub токен",
		"Email address detected":                   "Обнаружен email адрес",
		"Phone number detected":                    "Обнаружен номер телефона",
		"Social Security Number detected":          "Обнаружен SSN",
		"Credit card number detected":              "Обнаружен номер банк. карты",
		"JSON secret detected":                     "Обнаружен секрет в JSON",
		"YAML secret detected":                     "Обнаружен секрет в YAML",
		"Environment variable assignment detected": "Обнаружена переменная окружения",
		"Connection string detected":               "Обнаружена строка подключения",
		"Hardcoded secret detected":                "Обнаружен захардкоженный секрет",
		"IBAN detected":                            "Обнаружен IBAN",
		"BIC code detected":                        "Обнаружен BIC код",
		"Passport number detected":                 "Обнаружен номер паспорта",
	}
	if ru, ok := translations[desc]; ok {
		return ru
	}
	return desc
}

// getFilteredFiles returns files matching current filters
func (sg *ScannerGUI) getFilteredFiles() []*FileWithFindings {
	var result []*FileWithFindings

	// Map filter names to severity values
	filterToSeverity := map[string]searcher.Severity{
		"Критический": searcher.Critical,
		"Высокий":     searcher.High,
		"Средний":     searcher.Medium,
		"Низкий":      searcher.Low,
	}

	for _, file := range sg.filesData {
		// Check ignore list
		if sg.ignoreList[file.FilePath] {
			continue
		}

		// Check severity filter
		if sg.filterSeverity != "" && sg.filterSeverity != "Все уровни" {
			targetSeverity, ok := filterToSeverity[sg.filterSeverity]
			if ok {
				hasMatchingSeverity := false
				for _, f := range file.Findings {
					if f.Severity == targetSeverity {
						hasMatchingSeverity = true
						break
					}
				}
				if !hasMatchingSeverity {
					continue
				}
			}
		}

		// Check text filter
		if sg.filterText != "" {
			searchLower := strings.ToLower(sg.filterText)
			// Search in file path and finding descriptions
			matchFound := strings.Contains(strings.ToLower(file.FilePath), searchLower)
			if !matchFound {
				for _, f := range file.Findings {
					if strings.Contains(strings.ToLower(f.Description), searchLower) ||
						strings.Contains(strings.ToLower(string(f.PatternType)), searchLower) {
						matchFound = true
						break
					}
				}
			}
			if !matchFound {
				continue
			}
		}

		result = append(result, file)
	}

	// Sort by max severity (Critical first)
	sort.Slice(result, func(i, j int) bool {
		return result[i].MaxSeverity.Score() > result[j].MaxSeverity.Score()
	})

	return result
}

// toggleSelectAll selects or deselects all visible files
func (sg *ScannerGUI) toggleSelectAll(checked bool) {
	sg.filesMutex.Lock()
	for _, file := range sg.filesData {
		file.Selected = checked
	}
	sg.filesMutex.Unlock()

	sg.refreshFilesList()
	sg.updateSelectedCount()
	sg.updateEncryptButtonState()
}

// selectBySeverity selects all files containing findings of a given severity
func (sg *ScannerGUI) selectBySeverity(severity searcher.Severity) {
	sg.filesMutex.Lock()
	for _, file := range sg.filesData {
		for _, f := range file.Findings {
			if f.Severity == severity {
				file.Selected = true
				break
			}
		}
	}
	sg.filesMutex.Unlock()

	sg.refreshFilesList()
	sg.updateSelectedCount()
	sg.updateEncryptButtonState()
}

// updateSelectedCount updates the label showing how many files are selected
func (sg *ScannerGUI) updateSelectedCount() {
	sg.filesMutex.RLock()
	selectedCount := 0
	totalFindings := 0
	for _, file := range sg.filesData {
		if file.Selected {
			selectedCount++
			totalFindings += len(file.Findings)
		}
	}
	sg.filesMutex.RUnlock()

	fyne.Do(func() {
		if sg.selectedCountLabel != nil {
			if selectedCount == 0 {
				sg.selectedCountLabel.SetText("0 файлов выбрано")
			} else {
				sg.selectedCountLabel.SetText(fmt.Sprintf("📁 %d файлов (%d уязвимостей)", selectedCount, totalFindings))
			}
		}
	})
}

// updateEncryptButtonState enables/disables the encrypt button based on selection
func (sg *ScannerGUI) updateEncryptButtonState() {
	if sg.encryptButton == nil {
		return
	}

	paths := sg.getSelectedFilePaths()
	canEncrypt := len(paths) > 0 && !sg.scanning.Load() && !sg.encrypting.Load()

	fyne.Do(func() {
		if canEncrypt {
			sg.encryptButton.Enable()
		} else {
			sg.encryptButton.Disable()
		}
	})
}

// getSelectedFilePaths returns selected file paths
func (sg *ScannerGUI) getSelectedFilePaths() []string {
	sg.filesMutex.RLock()
	defer sg.filesMutex.RUnlock()

	var paths []string
	for _, file := range sg.filesData {
		if file.Selected {
			paths = append(paths, file.FilePath)
		}
	}

	return paths
}

func (sg *ScannerGUI) refreshFilesList() {
	fyne.Do(func() {
		sg.filesList.Refresh()
	})
}

func (sg *ScannerGUI) buildDetailsPanel() fyne.CanvasObject {
	sg.detailContainer = container.NewVBox(
		widget.NewLabel("Выберите файл для просмотра уязвимостей"),
	)

	scroll := container.NewScroll(sg.detailContainer)

	detailsHeader := widget.NewLabelWithStyle("📋 Уязвимости в файле", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})

	return container.NewPadded(container.NewBorder(
		container.NewVBox(detailsHeader, widget.NewSeparator()),
		nil, nil, nil,
		scroll,
	))
}

// clearDetailsPanel clears the details panel
func (sg *ScannerGUI) clearDetailsPanel() {
	sg.selectedFile = nil
	fyne.Do(func() {
		sg.detailContainer.Objects = []fyne.CanvasObject{
			widget.NewLabel("Выберите файл для просмотра уязвимостей"),
		}
		sg.detailContainer.Refresh()
	})
}

func (sg *ScannerGUI) updateDetailsPanel() {
	if sg.selectedFile == nil {
		sg.detailContainer.Objects = []fyne.CanvasObject{
			widget.NewLabel("Выберите файл для просмотра уязвимостей"),
		}
		sg.detailContainer.Refresh()
		return
	}

	file := sg.selectedFile
	objects := []fyne.CanvasObject{}

	// File header
	fileHeader := widget.NewLabel(fmt.Sprintf("📁 %s", filepath.Base(file.FilePath)))
	fileHeader.TextStyle.Bold = true
	objects = append(objects, fileHeader)

	filePath := widget.NewLabel(file.FilePath)
	filePath.Wrapping = fyne.TextWrapWord
	objects = append(objects, filePath)

	// Action buttons for file
	openBtn := widget.NewButton("📂 Открыть в проводнике", func() {
		sg.openInExplorer(file.FilePath)
	})

	ignoreBtn := widget.NewButton("🚫 Игнорировать файл", func() {
		sg.ignoreMutex.Lock()
		sg.ignoreList[file.FilePath] = true
		sg.ignoreMutex.Unlock()
		sg.refreshFilesList()
		sg.updateStatsUI()
		sg.statusLabel.SetText(fmt.Sprintf("Игнорировано: %s", filepath.Base(file.FilePath)))
		sg.selectedFile = nil
		sg.updateDetailsPanel()
	})
	ignoreBtn.Importance = widget.LowImportance

	objects = append(objects, container.NewHBox(openBtn, ignoreBtn))
	objects = append(objects, widget.NewSeparator())

	// Findings summary
	summaryLabel := widget.NewLabel(fmt.Sprintf("🔍 Найдено уязвимостей: %d", len(file.Findings)))
	summaryLabel.TextStyle.Bold = true
	objects = append(objects, summaryLabel)
	objects = append(objects, widget.NewSeparator())

	// Sort findings by severity
	sortedFindings := make([]*searcher.Finding, len(file.Findings))
	copy(sortedFindings, file.Findings)
	sort.Slice(sortedFindings, func(i, j int) bool {
		return sortedFindings[i].Severity.Score() > sortedFindings[j].Severity.Score()
	})

	// List each finding
	for i, f := range sortedFindings {
		// Finding header with severity color
		var severityIcon string
		switch f.Severity {
		case searcher.Critical:
			severityIcon = "🔴"
		case searcher.High:
			severityIcon = "🟠"
		case searcher.Medium:
			severityIcon = "🟡"
		case searcher.Low:
			severityIcon = "🟢"
		}

		findingHeader := widget.NewLabel(fmt.Sprintf("%s #%d: %s [%s]",
			severityIcon, i+1, sg.patternToRussian(f.PatternType), sg.severityToRussian(f.Severity)))
		findingHeader.TextStyle.Bold = true
		objects = append(objects, findingHeader)

		// Location
		lineLabel := widget.NewLabel(fmt.Sprintf("   📍 Строка %d, Колонка %d-%d", f.LineNumber, f.ColumnStart, f.ColumnEnd))
		objects = append(objects, lineLabel)

		// Description
		descLabel := widget.NewLabel(fmt.Sprintf("   📝 %s", sg.descriptionToRussian(f.Description)))
		descLabel.Wrapping = fyne.TextWrapWord
		objects = append(objects, descLabel)

		// Risk score
		riskLabel := widget.NewLabel(fmt.Sprintf("   ⚠️ Риск: %.0f%% | Энтропия: %.2f", f.RiskScore, f.EntropyScore))
		objects = append(objects, riskLabel)

		// Context preview
		contextText := canvas.NewText(fmt.Sprintf("   %s", f.Context), color.NRGBA{R: 200, G: 200, B: 200, A: 255})
		contextText.TextSize = 12
		contextBg := canvas.NewRectangle(color.NRGBA{R: 40, G: 40, B: 45, A: 255})
		contextBg.CornerRadius = 4
		contextContainer := container.NewStack(contextBg, container.NewPadded(contextText))
		objects = append(objects, contextContainer)

		// Masked matched text
		maskedText := maskSensitiveText(f.MatchedText)
		matchLabel := widget.NewLabel(fmt.Sprintf("   🎯 Найдено: %s", maskedText))
		objects = append(objects, matchLabel)

		// Copy button for this finding
		copyBtn := widget.NewButton("📋 Копировать контекст", func() {
			sg.window.Clipboard().SetContent(f.Context)
			sg.statusLabel.SetText("✅ Скопировано в буфер обмена")
		})
		copyBtn.Importance = widget.LowImportance
		objects = append(objects, container.NewHBox(layout.NewSpacer(), copyBtn))

		if i < len(sortedFindings)-1 {
			objects = append(objects, widget.NewSeparator())
		}
	}

	sg.detailContainer.Objects = objects
	sg.detailContainer.Refresh()
}

func maskSensitiveText(text string) string {
	if len(text) <= 8 {
		return strings.Repeat("*", len(text))
	}
	return text[:4] + strings.Repeat("*", len(text)-8) + text[len(text)-4:]
}

// truncatePath truncates a long path to show beginning and end with ellipsis
func truncatePath(path string, maxLen int) string {
	if len(path) <= maxLen {
		return path
	}
	// Show first part and last part
	firstPart := maxLen / 3
	lastPart := maxLen - firstPart - 3 // -3 for "..."
	if lastPart < 10 {
		lastPart = 10
		firstPart = maxLen - lastPart - 3
	}
	return path[:firstPart] + "..." + path[len(path)-lastPart:]
}

func (sg *ScannerGUI) openInExplorer(filePath string) {
	dir := filepath.Dir(filePath)
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", "-R", filePath)
	case "windows":
		cmd = exec.Command("explorer", "/select,", filePath)
	default:
		cmd = exec.Command("xdg-open", dir)
	}
	if err := cmd.Start(); err != nil {
		sg.statusLabel.SetText("❌ Не удалось открыть проводник")
	}
}

func (sg *ScannerGUI) setupShortcuts() {
	// Ctrl+S or Cmd+S to start scan
	sg.window.Canvas().SetOnTypedKey(func(ke *fyne.KeyEvent) {
		if ke.Name == fyne.KeyS && (ke.Physical.ScanCode == 31) {
			if !sg.scanning.Load() {
				sg.onStartScan()
			}
		}
	})
}

func (sg *ScannerGUI) onStartScan() {
	if sg.scanning.Load() {
		return
	}

	scanDir := sg.scanDir.Text
	if scanDir == "" {
		dialog.ShowError(fmt.Errorf("пожалуйста, выберите директорию для сканирования"), sg.window)
		return
	}

	if _, err := os.Stat(scanDir); os.IsNotExist(err) {
		dialog.ShowError(fmt.Errorf("директория не существует: %s", scanDir), sg.window)
		return
	}

	// Check dependencies based on selected options
	scanDocs := sg.scanDocsCheck != nil && sg.scanDocsCheck.Checked
	scanArchives := sg.scanArchivesCheck != nil && sg.scanArchivesCheck.Checked
	enableOCR := sg.enableOCRCheck != nil && sg.enableOCRCheck.Checked
	enableAI := sg.enableAICheck != nil && sg.enableAICheck.Checked

	depChecker := searcher.NewDependencyChecker()
	depChecker.CheckAll()

	var warnings []string

	if enableOCR && !depChecker.IsTesseractAvailable() {
		missingDeps := depChecker.GetMissingDependencies()
		installHint := "brew install tesseract" // fallback
		if len(missingDeps) > 0 {
			installHint = missingDeps[0].InstallHint
		}
		warnings = append(warnings, "⚠️ Tesseract OCR не установлен!\n   OCR изображений будет недоступен.\n   Установите: "+installHint)
	}

	if scanDocs && !depChecker.IsPopplerAvailable() {
		for _, dep := range depChecker.GetMissingDependencies() {
			if dep.Name == "Poppler (PDF utils)" {
				warnings = append(warnings, "⚠️ Poppler не установлен!\n   OCR для сканированных PDF недоступен.\n   Установите: "+dep.InstallHint)
				break
			}
		}
	}

	if enableAI && !depChecker.IsOllamaAvailable() {
		for _, dep := range depChecker.GetMissingDependencies() {
			if dep.Name == "Ollama (AI)" {
				warnings = append(warnings, "⚠️ Ollama не установлен или не запущен!\n   AI-анализ будет использовать базовый режим.\n   Установите: "+dep.InstallHint)
				break
			}
		}
	}

	// Show warnings and ask to continue
	if len(warnings) > 0 {
		warningText := strings.Join(warnings, "\n\n")
		dialog.ShowConfirm("Предупреждение", warningText+"\n\nПродолжить сканирование?", func(confirm bool) {
			if confirm {
				sg.startScanWithOptions(scanDir, scanDocs, scanArchives, enableOCR, enableAI)
			}
		}, sg.window)
		return
	}

	// Start scan with current options
	sg.startScanWithOptions(scanDir, scanDocs, scanArchives, enableOCR, enableAI)
}

// startScanWithOptions starts the scan with the given options
func (sg *ScannerGUI) startScanWithOptions(scanDir string, scanDocs, scanArchives, enableOCR, enableAI bool) {
	// Reset state
	sg.scanning.Store(true)
	sg.paused.Store(false)
	sg.cancelled.Store(false)
	sg.startTime = time.Now()

	sg.filesMutex.Lock()
	sg.filesData = make([]*FileWithFindings, 0)
	sg.selectedFile = nil
	sg.filesMutex.Unlock()

	sg.filesQueued.Store(0)
	sg.filesProcessed.Store(0)
	sg.findingsCount.Store(0)

	// Update UI
	sg.scanButton.Disable()
	sg.pauseButton.Enable()
	sg.cancelButton.Enable()
	sg.exportButton.Disable()
	sg.progressBar.SetValue(0)
	sg.statusLabel.SetText("🔄 Сканирование...")
	sg.updateStatsUI()

	// Clear details panel
	sg.clearDetailsPanel()

	// Start progress updater
	go sg.updateProgressLoop()

	// Start scan with options
	go sg.runScanWithOptions(scanDir, scanDocs, scanArchives, enableOCR, enableAI)
}

func (sg *ScannerGUI) runScanWithOptions(scanDir string, scanDocs, scanArchives, enableOCR, enableAI bool) {
	defer func() {
		sg.scanning.Store(false)

		elapsed := time.Since(sg.startTime)
		findingsCount := sg.findingsCount.Load()
		cancelled := sg.cancelled.Load()

		// All UI updates must be on main thread
		fyne.Do(func() {
			sg.scanButton.Enable()
			sg.pauseButton.Disable()
			sg.pauseButton.SetText("⏸️ Пауза")
			sg.cancelButton.Disable()

			if findingsCount > 0 {
				sg.exportButton.Enable()
			}

			if cancelled {
				sg.statusLabel.SetText(fmt.Sprintf("⏹️ Сканирование отменено через %.2fс", elapsed.Seconds()))
			} else {
				sg.statusLabel.SetText(fmt.Sprintf("✅ Готово! Найдено %d проблем за %.2fс",
					findingsCount, elapsed.Seconds()))
			}

			sg.progressBar.SetValue(1)
			sg.updateStatsUI()
			sg.updateSelectedCount()
			sg.updateEncryptButtonState()
			sg.refreshFilesList()
			sg.clearDetailsPanel() // Clear details after scan completes
		})

		// Send notification
		sg.app.SendNotification(&fyne.Notification{
			Title:   "Сканирование завершено",
			Content: fmt.Sprintf("Найдено %d потенциальных проблем", findingsCount),
		})
	}()

	scanner := searcher.NewScanner()
	scanner.SetMaxFileSize(sg.settings.MaxFileSize)
	scanner.SetMaxConcurrentFiles(sg.settings.Concurrency)

	// Configure file type filter
	fileTypeFilter := sg.filterFileType
	if sg.fileTypeFilter != nil {
		fileTypeFilter = sg.fileTypeFilter.Selected
	}

	// Use parameters passed to function (already read in onStartScan)
	// Auto-adjust options based on file type filter
	switch fileTypeFilter {
	case "Только текст/код (.txt, .json, .env, .go, .py...)":
		scanner.SetOnlyExtensions([]string{
			".txt", ".json", ".yaml", ".yml", ".xml", ".csv", ".env", ".ini", ".cfg", ".conf",
			".go", ".py", ".js", ".ts", ".java", ".c", ".cpp", ".h", ".hpp", ".cs", ".rb",
			".php", ".sh", ".bash", ".zsh", ".ps1", ".sql", ".md", ".rst", ".log",
		})
		fyne.Do(func() {
			sg.statusLabel.SetText("🔍 Сканирую только текст/код...")
		})
	case "Только документы (.pdf, .docx, .xlsx...)":
		scanner.SetOnlyExtensions([]string{
			".pdf", ".docx", ".doc", ".xlsx", ".xls", ".pptx", ".ppt", ".odt", ".ods", ".odp",
		})
		// Auto-enable document extraction if user selected documents filter
		if !scanDocs {
			scanDocs = true
			fyne.Do(func() {
				sg.scanDocsCheck.SetChecked(true)
			})
		}
		fyne.Do(func() {
			sg.statusLabel.SetText("🔍 Сканирую только документы...")
		})
	case "Только изображения (.png, .jpg, .gif...)":
		scanner.SetOnlyExtensions([]string{
			".png", ".jpg", ".jpeg", ".gif", ".bmp", ".tiff", ".tif", ".webp",
		})
		// Auto-enable OCR if user selected images filter
		if !enableOCR {
			enableOCR = true
			fyne.Do(func() {
				sg.enableOCRCheck.SetChecked(true)
				sg.statusLabel.SetText("⚠️ OCR включён автоматически. Требуется Tesseract!")
			})
		} else {
			fyne.Do(func() {
				sg.statusLabel.SetText("🔍 Сканирую только изображения (OCR)...")
			})
		}
	case "Только архивы (.zip, .tar, .gz...)":
		scanner.SetOnlyExtensions([]string{
			".zip", ".tar", ".gz", ".tgz", ".rar", ".7z", ".bz2", ".xz",
		})
		// Auto-enable archive scanning
		if !scanArchives {
			scanArchives = true
			fyne.Do(func() {
				sg.scanArchivesCheck.SetChecked(true)
			})
		}
		fyne.Do(func() {
			sg.statusLabel.SetText("🔍 Сканирую только архивы...")
		})
	default:
		// All files - no filter
		scanner.ClearOnlyExtensions()
	}

	// Configure document extractor based on scan options
	if scanDocs || scanArchives || enableOCR {
		extractor := searcher.NewDocumentExtractor(enableOCR)
		scanner.SetDocumentExtractor(extractor)
		scanner.SetScanDocuments(scanDocs)
		scanner.SetScanArchives(scanArchives)

		fyne.Do(func() {
			var opts []string
			if scanDocs {
				opts = append(opts, "извлечение текста из документов")
			}
			if scanArchives {
				opts = append(opts, "сканирование архивов")
			}
			if enableOCR {
				opts = append(opts, "OCR")
			}
			sg.statusLabel.SetText(fmt.Sprintf("🔍 Доп. обработка: %s", strings.Join(opts, ", ")))
		})
	}

	// Configure ignore list - enable document/image/archive scanning if requested
	ignoreList := scanner.GetIgnoreList()
	if scanDocs {
		ignoreList.EnableDocumentScanning()
	}
	if enableOCR {
		ignoreList.EnableImageScanning()
	}
	if scanArchives {
		ignoreList.EnableArchiveScanning()
	}
	for _, dir := range sg.settings.ExcludeDirs {
		ignoreList.AddIgnoreDir(dir)
	}
	for _, ext := range sg.settings.ExcludeExts {
		ignoreList.AddIgnoreExtension(ext)
	}

	result, err := scanner.Scan(scanDir)
	if err != nil {
		fyne.Do(func() {
			sg.statusLabel.SetText(fmt.Sprintf("❌ Ошибка: %v", err))
		})
		return
	}

	sg.resultData = result

	// Group findings by file
	fileMap := make(map[string]*FileWithFindings)
	for _, f := range result.Findings {
		file, exists := fileMap[f.FilePath]
		if !exists {
			file = &FileWithFindings{
				FilePath:    f.FilePath,
				Findings:    make([]*searcher.Finding, 0),
				Selected:    false,
				MaxSeverity: f.Severity,
			}
			fileMap[f.FilePath] = file
		}
		file.Findings = append(file.Findings, f)
		// Update max severity
		if f.Severity.Score() > file.MaxSeverity.Score() {
			file.MaxSeverity = f.Severity
		}
	}

	// Convert map to slice
	sg.filesMutex.Lock()
	sg.filesData = make([]*FileWithFindings, 0, len(fileMap))
	for _, file := range fileMap {
		sg.filesData = append(sg.filesData, file)
	}
	// Sort by max severity
	sort.Slice(sg.filesData, func(i, j int) bool {
		return sg.filesData[i].MaxSeverity.Score() > sg.filesData[j].MaxSeverity.Score()
	})
	sg.filesMutex.Unlock()

	sg.filesProcessed.Store(int64(result.FilesScanned))
	sg.findingsCount.Store(int64(result.TotalFindings()))

	// AI Analysis if enabled
	if enableAI && result.TotalFindings() > 0 {
		analyzer := searcher.NewLocalAnalyzer()
		ollamaAvailable := analyzer.IsOllamaAvailable()

		if ollamaAvailable {
			fyne.Do(func() {
				sg.statusLabel.SetText("🤖 AI-анализ (Ollama)...")
			})
			analyzer.EnableAI(true)
		} else {
			fyne.Do(func() {
				sg.statusLabel.SetText("🤖 AI-анализ (базовый режим, Ollama недоступен)...")
			})
			analyzer.EnableAI(false)
		}

		analysis, err := analyzer.Analyze(result)
		if err == nil {
			// Show AI analysis dialog with Ollama status
			fyne.Do(func() {
				sg.showAIAnalysisDialogWithStatus(analysis, analyzer, ollamaAvailable)
			})
		}
	}

	// UI updates on main thread
	fyne.Do(func() {
		sg.refreshFilesList()
		sg.updateStatsUI()
	})
}

func (sg *ScannerGUI) updateProgressLoop() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for sg.scanning.Load() {
		<-ticker.C

		// Capture values outside of fyne.Do
		elapsed := time.Since(sg.startTime)
		processed := sg.filesProcessed.Load()
		queued := sg.filesQueued.Load()

		// Update UI on main thread
		fyne.Do(func() {
			sg.timeLabel.SetText(fmt.Sprintf("Время: %.1fс", elapsed.Seconds()))

			if queued > 0 {
				sg.progressBar.SetValue(float64(processed) / float64(queued))
			}

			sg.progressLabel.SetText(fmt.Sprintf("%d файлов обработано", processed))
		})
	}
}

func (sg *ScannerGUI) onPauseScan() {
	if sg.paused.Load() {
		sg.paused.Store(false)
		sg.pauseButton.SetText("⏸️ Пауза")
		sg.statusLabel.SetText("🔄 Сканирование возобновлено...")
	} else {
		sg.paused.Store(true)
		sg.pauseButton.SetText("▶️ Продолжить")
		sg.statusLabel.SetText("⏸️ Сканирование приостановлено")
	}
}

func (sg *ScannerGUI) onCancelScan() {
	dialog.ShowConfirm("Отмена сканирования", "Вы уверены, что хотите отменить сканирование?", func(confirm bool) {
		if confirm {
			sg.cancelled.Store(true)
			sg.scanning.Store(false)
		}
	}, sg.window)
}

func (sg *ScannerGUI) onExport() {
	if sg.resultData == nil {
		dialog.ShowError(fmt.Errorf("нет результатов для экспорта"), sg.window)
		return
	}

	outputDir := sg.outputDir.Text
	if outputDir == "" {
		outputDir = "./reports"
	}

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		dialog.ShowError(err, sg.window)
		return
	}

	reporter := searcher.NewReportGenerator(sg.resultData)
	if err := reporter.GenerateReport(outputDir); err != nil {
		dialog.ShowError(err, sg.window)
		return
	}

	sg.statusLabel.SetText(fmt.Sprintf("✅ Отчёты экспортированы в: %s", outputDir))

	dialog.ShowInformation("Экспорт завершён",
		fmt.Sprintf("Отчёты сохранены в:\n%s\n\n• JSON отчёт\n• CSV отчёт\n• Текстовый отчёт", outputDir),
		sg.window)
}

// updateStatsUI updates stats labels - must be called from main thread
func (sg *ScannerGUI) updateStatsUI() {
	sg.filesMutex.RLock()
	defer sg.filesMutex.RUnlock()

	var critical, high, medium, low int
	for _, file := range sg.filesData {
		if sg.ignoreList[file.FilePath] {
			continue
		}
		for _, f := range file.Findings {
			switch f.Severity {
			case searcher.Critical:
				critical++
			case searcher.High:
				high++
			case searcher.Medium:
				medium++
			case searcher.Low:
				low++
			}
		}
	}

	total := critical + high + medium + low

	sg.totalLabel.SetText(strconv.Itoa(total))
	sg.criticalLabel.SetText(strconv.Itoa(critical))
	sg.highLabel.SetText(strconv.Itoa(high))
	sg.mediumLabel.SetText(strconv.Itoa(medium))
	sg.lowLabel.SetText(strconv.Itoa(low))
	sg.filesLabel.SetText(strconv.Itoa(int(sg.filesProcessed.Load())))
}

// updateStats can be called from any thread - wraps UI call
func (sg *ScannerGUI) updateStats() {
	fyne.Do(func() {
		sg.updateStatsUI()
	})
}

func (sg *ScannerGUI) showSettings() {
	// Max file size
	maxSizeEntry := widget.NewEntry()
	maxSizeEntry.SetText(fmt.Sprintf("%d", sg.settings.MaxFileSize/(1024*1024)))

	// Concurrency
	concurrencyEntry := widget.NewEntry()
	concurrencyEntry.SetText(strconv.Itoa(sg.settings.Concurrency))

	// Follow symlinks
	followSymlinks := widget.NewCheck("Следовать по символьным ссылкам", nil)
	followSymlinks.SetChecked(sg.settings.FollowSymlinks)

	// Scan binaries
	scanBinaries := widget.NewCheck("Сканировать бинарные файлы", nil)
	scanBinaries.SetChecked(sg.settings.ScanBinaries)

	// Excluded directories
	excludeDirsEntry := widget.NewMultiLineEntry()
	excludeDirsEntry.SetText(strings.Join(sg.settings.ExcludeDirs, "\n"))
	excludeDirsEntry.SetMinRowsVisible(4)

	// Excluded extensions
	excludeExtsEntry := widget.NewMultiLineEntry()
	excludeExtsEntry.SetText(strings.Join(sg.settings.ExcludeExts, "\n"))
	excludeExtsEntry.SetMinRowsVisible(4)

	formItems := []*widget.FormItem{
		widget.NewFormItem("Макс. размер файла (МБ)", maxSizeEntry),
		widget.NewFormItem("Параллельность", concurrencyEntry),
		widget.NewFormItem("", followSymlinks),
		widget.NewFormItem("", scanBinaries),
		widget.NewFormItem("Исключить директории (по одной на строку)", excludeDirsEntry),
		widget.NewFormItem("Исключить расширения (по одному на строку)", excludeExtsEntry),
	}

	dialog.ShowForm("⚙️ Настройки", "Сохранить", "Отмена", formItems, func(confirm bool) {
		if !confirm {
			return
		}

		// Parse max size
		if size, err := strconv.ParseInt(maxSizeEntry.Text, 10, 64); err == nil && size > 0 {
			sg.settings.MaxFileSize = size * 1024 * 1024
		}

		// Parse concurrency
		if conc, err := strconv.Atoi(concurrencyEntry.Text); err == nil && conc > 0 {
			sg.settings.Concurrency = conc
		}

		sg.settings.FollowSymlinks = followSymlinks.Checked
		sg.settings.ScanBinaries = scanBinaries.Checked

		// Parse excluded dirs
		dirs := strings.Split(excludeDirsEntry.Text, "\n")
		sg.settings.ExcludeDirs = make([]string, 0)
		for _, d := range dirs {
			d = strings.TrimSpace(d)
			if d != "" {
				sg.settings.ExcludeDirs = append(sg.settings.ExcludeDirs, d)
			}
		}

		// Parse excluded extensions
		exts := strings.Split(excludeExtsEntry.Text, "\n")
		sg.settings.ExcludeExts = make([]string, 0)
		for _, e := range exts {
			e = strings.TrimSpace(e)
			if e != "" {
				sg.settings.ExcludeExts = append(sg.settings.ExcludeExts, e)
			}
		}

		sg.statusLabel.SetText("✅ Настройки сохранены")
	}, sg.window)
}

func (sg *ScannerGUI) showHelp() {
	helpText := `🔍 Поиск Утечек Данных - Сканер Безопасности

ВОЗМОЖНОСТИ:
• Сканирование директорий на наличие чувствительных данных
• Обнаружение паролей, API-ключей, токенов, банковских карт
• 📄 Сканирование документов (PDF, DOCX, XLSX)
• 📦 Сканирование архивов (ZIP, TAR)
• 🔍 OCR для изображений (требуется Tesseract)
• 🤖 AI-анализ (локальный, через Ollama)
• 🔐 Шифрование выбранных файлов (AES-256)

ОПЦИИ СКАНИРОВАНИЯ:
• Документы - извлекает текст из PDF, Word, Excel
• Архивы - сканирует содержимое ZIP/TAR файлов
• OCR - распознаёт текст на изображениях
• AI-анализ - даёт рекомендации по устранению

УРОВНИ СЕРЬЁЗНОСТИ:
🔴 Критический - Требуется немедленное действие
🟠 Высокий - Следует исправить в ближайшее время
🟡 Средний - Рекомендуется проверить
🟢 Низкий - Незначительная проблема`

	dialog.ShowInformation("Справка", helpText, sg.window)
}

// showAIAnalysisDialogWithStatus shows the AI analysis results with Ollama status
func (sg *ScannerGUI) showAIAnalysisDialogWithStatus(analysis *searcher.AnalysisResult, analyzer *searcher.LocalAnalyzer, ollamaAvailable bool) {
	// Create scrollable content
	var content []fyne.CanvasObject

	// Ollama status banner
	if !ollamaAvailable {
		warningCard := widget.NewCard("⚠️ Ollama недоступен",
			"Используется базовый правило-ориентированный анализ.\nДля полного AI-анализа установите Ollama:",
			widget.NewLabel("brew install ollama && ollama pull llama3.2"))
		content = append(content, warningCard, widget.NewSeparator())
	} else {
		statusLabel := widget.NewLabel("✅ Анализ выполнен с использованием Ollama AI")
		statusLabel.TextStyle.Bold = true
		content = append(content, statusLabel, widget.NewSeparator())
	}

	// Summary section
	summaryLabel := widget.NewLabelWithStyle("📊 СВОДКА", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	summaryText := widget.NewLabel(analysis.Summary)
	summaryText.Wrapping = fyne.TextWrapWord
	content = append(content, summaryLabel, summaryText, widget.NewSeparator())

	// Risk assessment
	riskLabel := widget.NewLabelWithStyle("⚠️ ОЦЕНКА РИСКА", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	riskText := widget.NewLabel(analysis.RiskAssessment)
	riskText.Wrapping = fyne.TextWrapWord
	content = append(content, riskLabel, riskText, widget.NewSeparator())

	// Recommendations
	recLabel := widget.NewLabelWithStyle("💡 РЕКОМЕНДАЦИИ", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	content = append(content, recLabel)
	for i, rec := range analysis.Recommendations {
		recText := widget.NewLabel(fmt.Sprintf("%d. %s", i+1, rec))
		recText.Wrapping = fyne.TextWrapWord
		content = append(content, recText)
	}
	content = append(content, widget.NewSeparator())

	// Critical findings (top 5)
	if len(analysis.CriticalFindings) > 0 {
		critLabel := widget.NewLabelWithStyle("🔴 КРИТИЧЕСКИЕ НАХОДКИ", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
		content = append(content, critLabel)

		maxShow := 5
		if len(analysis.CriticalFindings) < maxShow {
			maxShow = len(analysis.CriticalFindings)
		}

		for i := 0; i < maxShow; i++ {
			cf := analysis.CriticalFindings[i]
			cfText := widget.NewLabel(fmt.Sprintf("• %s\n  %s (Риск: %.0f%%)\n  💡 %s",
				filepath.Base(cf.FilePath), cf.Description, cf.RiskScore, cf.Suggestion))
			cfText.Wrapping = fyne.TextWrapWord
			content = append(content, cfText)
		}

		if len(analysis.CriticalFindings) > 5 {
			moreText := widget.NewLabel(fmt.Sprintf("... и ещё %d критических находок", len(analysis.CriticalFindings)-5))
			content = append(content, moreText)
		}
	}

	// AI insights if available
	if analysis.AIInsights != "" {
		content = append(content, widget.NewSeparator())
		aiLabel := widget.NewLabelWithStyle("🤖 AI-АНАЛИЗ (Ollama)", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
		aiText := widget.NewLabel(analysis.AIInsights)
		aiText.Wrapping = fyne.TextWrapWord
		content = append(content, aiLabel, aiText)
	}

	// Create scrollable container
	scrollContent := container.NewVBox(content...)
	scroll := container.NewScroll(scrollContent)
	scroll.SetMinSize(fyne.NewSize(600, 400))

	// Save button
	saveBtn := widget.NewButton("💾 Сохранить отчёт", func() {
		report := analyzer.FormatAnalysisReport(analysis)
		outputPath := filepath.Join(sg.outputDir.Text, "анализ-безопасности.txt")
		if err := os.WriteFile(outputPath, []byte(report), 0644); err != nil {
			dialog.ShowError(err, sg.window)
		} else {
			dialog.ShowInformation("Сохранено", fmt.Sprintf("Отчёт сохранён в:\n%s", outputPath), sg.window)
		}
	})

	dialogContent := container.NewBorder(nil, saveBtn, nil, nil, scroll)

	d := dialog.NewCustom("🤖 AI-Анализ Безопасности", "Закрыть", dialogContent, sg.window)
	d.Resize(fyne.NewSize(700, 500))
	d.Show()
}

// onEncrypt handles the encrypt button click
func (sg *ScannerGUI) onEncrypt() {
	selectedPaths := sg.getSelectedFilePaths()
	if len(selectedPaths) == 0 {
		dialog.ShowError(fmt.Errorf("не выбраны файлы для шифрования"), sg.window)
		return
	}

	// Password entry
	passwordEntry := widget.NewPasswordEntry()
	passwordEntry.SetPlaceHolder("Введите пароль...")

	confirmPasswordEntry := widget.NewPasswordEntry()
	confirmPasswordEntry.SetPlaceHolder("Подтвердите пароль...")

	showPassword := widget.NewCheck("Показать пароль", func(checked bool) {
		passwordEntry.Password = !checked
		confirmPasswordEntry.Password = !checked
		passwordEntry.Refresh()
		confirmPasswordEntry.Refresh()
	})

	// Generate password button
	generateBtn := widget.NewButton("🎲 Сгенерировать", func() {
		pwd, err := encryptor.GeneratePassword(16)
		if err != nil {
			dialog.ShowError(err, sg.window)
			return
		}
		passwordEntry.SetText(pwd)
		confirmPasswordEntry.SetText(pwd)
		showPassword.SetChecked(true)
	})
	generateBtn.Importance = widget.LowImportance

	// Delete originals option
	deleteOriginals := widget.NewCheck("Удалить оригиналы после шифрования (безопасное удаление)", nil)

	// Output location
	homeDir, _ := os.UserHomeDir()
	defaultOutput := filepath.Join(homeDir, "encrypted_files.zip")
	outputEntry := widget.NewEntry()
	outputEntry.SetText(defaultOutput)

	browseOutputBtn := widget.NewButton("📂 Обзор", func() {
		dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil || writer == nil {
				return
			}
			writer.Close()
			outputEntry.SetText(writer.URI().Path())
		}, sg.window)
	})

	// File count info
	fileCountLabel := widget.NewLabel(fmt.Sprintf("📁 Выбрано файлов: %d", len(selectedPaths)))

	formItems := []*widget.FormItem{
		widget.NewFormItem("Файлы", fileCountLabel),
		widget.NewFormItem("Пароль", container.NewBorder(nil, nil, nil, generateBtn, passwordEntry)),
		widget.NewFormItem("Подтверждение", confirmPasswordEntry),
		widget.NewFormItem("", showPassword),
		widget.NewFormItem("", widget.NewSeparator()),
		widget.NewFormItem("Сохранить в", container.NewBorder(nil, nil, nil, browseOutputBtn, outputEntry)),
		widget.NewFormItem("", deleteOriginals),
	}

	dialog.ShowForm("🔐 Зашифровать и экспортировать", "Зашифровать", "Отмена", formItems, func(confirm bool) {
		if !confirm {
			return
		}

		// Validate
		password := passwordEntry.Text
		confirmPwd := confirmPasswordEntry.Text

		if password != confirmPwd {
			dialog.ShowError(fmt.Errorf("пароли не совпадают"), sg.window)
			return
		}

		if err := encryptor.ValidatePassword(password); err != nil {
			dialog.ShowError(fmt.Errorf("слабый пароль: %v", err), sg.window)
			return
		}

		outputPath := outputEntry.Text
		if outputPath == "" {
			dialog.ShowError(fmt.Errorf("укажите путь для сохранения"), sg.window)
			return
		}

		// Ensure .zip extension
		if !strings.HasSuffix(strings.ToLower(outputPath), ".zip") {
			outputPath += ".zip"
		}

		// Confirm deletion if requested
		if deleteOriginals.Checked {
			dialog.ShowConfirm("Удалить оригиналы?",
				fmt.Sprintf("После шифрования %d файлов будут безопасно удалены. Это необратимо!", len(selectedPaths)),
				func(confirmed bool) {
					if confirmed {
						sg.runEncryption(selectedPaths, password, outputPath, true)
					}
				}, sg.window)
		} else {
			sg.runEncryption(selectedPaths, password, outputPath, false)
		}
	}, sg.window)
}

// runEncryption performs the encryption with progress
func (sg *ScannerGUI) runEncryption(filePaths []string, password, outputPath string, deleteOriginals bool) {
	sg.encrypting.Store(true)
	sg.encryptButton.Disable()

	// Progress dialog
	progressBar := widget.NewProgressBar()
	progressLabel := widget.NewLabel("Подготовка...")

	progressContent := container.NewVBox(progressLabel, progressBar)

	progressDialog := dialog.NewCustom("🔐 Шифрование...", "Отмена", progressContent, sg.window)
	progressDialog.Show()

	var cancelled bool
	progressDialog.SetOnClosed(func() {
		cancelled = true
	})

	go func() {
		defer func() {
			sg.encrypting.Store(false)
			sg.updateEncryptButtonState()
		}()

		// Build file entries
		var entries []encryptor.FileEntry
		for _, path := range filePaths {
			entries = append(entries, encryptor.FileEntry{SourcePath: path})
		}

		// Configure encryptor
		config := encryptor.DefaultConfig()
		config.Password = password
		config.OutputPath = outputPath
		config.CompressionLevel = 6

		config.OnProgress = func(processed, total int64, currentFile string) {
			if cancelled {
				return
			}
			var pct float64
			if total > 0 {
				pct = float64(processed) / float64(total)
			}
			fyne.Do(func() {
				progressBar.SetValue(pct)
				progressLabel.SetText(fmt.Sprintf("Шифрование: %s (%.0f%%)", filepath.Base(currentFile), pct*100))
			})
		}

		enc, err := encryptor.NewEncryptor(config)
		if err != nil {
			fyne.Do(func() {
				progressDialog.Hide()
				dialog.ShowError(fmt.Errorf("ошибка создания шифровальщика: %v", err), sg.window)
			})
			return
		}

		result, err := enc.EncryptFilesWithResult(entries)
		if err != nil {
			if !cancelled {
				fyne.Do(func() {
					progressDialog.Hide()
					dialog.ShowError(fmt.Errorf("ошибка шифрования: %v", err), sg.window)
				})
			}
			return
		}

		// Secure delete if requested
		var filesDeleted int
		if deleteOriginals {
			fyne.Do(func() {
				progressLabel.SetText("Безопасное удаление оригиналов...")
			})

			err := encryptor.SecureDeleteMultiple(filePaths, 3, func(current, total int, path string) {
				if !cancelled {
					fyne.Do(func() {
						progressBar.SetValue(float64(current) / float64(total))
						progressLabel.SetText(fmt.Sprintf("Удаление: %s (%d/%d)", filepath.Base(path), current, total))
					})
				}
			})
			if err == nil {
				filesDeleted = len(filePaths)
			}
		}

		fyne.Do(func() {
			progressDialog.Hide()

			// Format file sizes
			formatSize := func(b int64) string {
				const unit = 1024
				if b < unit {
					return fmt.Sprintf("%d B", b)
				}
				div, exp := int64(unit), 0
				for n := b / unit; n >= unit; n /= unit {
					div *= unit
					exp++
				}
				return fmt.Sprintf("%.1f %s", float64(b)/float64(div), []string{"KB", "MB", "GB"}[exp])
			}

			successMsg := fmt.Sprintf(
				"✅ Шифрование завершено!\n\n"+
					"📦 Архив: %s\n"+
					"📁 Файлов: %d\n"+
					"📊 Исходный размер: %s\n"+
					"📊 Размер архива: %s\n"+
					"📈 Сжатие: %.1f%%",
				filepath.Base(result.OutputPath),
				result.FilesEncrypted,
				formatSize(result.TotalSize),
				formatSize(result.ArchiveSize),
				result.CompressionRatio*100,
			)

			if filesDeleted > 0 {
				successMsg += fmt.Sprintf("\n\n🗑️ Удалено оригиналов: %d", filesDeleted)
			}

			dialog.ShowInformation("Шифрование завершено", successMsg, sg.window)

			sg.statusLabel.SetText(fmt.Sprintf("✅ Зашифровано %d файлов", result.FilesEncrypted))

			// Send notification
			sg.app.SendNotification(&fyne.Notification{
				Title:   "Шифрование завершено",
				Content: fmt.Sprintf("Зашифровано %d файлов в %s", result.FilesEncrypted, filepath.Base(result.OutputPath)),
			})

			// Clear selection if files were deleted
			if filesDeleted > 0 {
				sg.toggleSelectAll(false)
				sg.selectAllCheck.SetChecked(false)
			}
		})
	}()
}

func (sg *ScannerGUI) Run() {
	sg.window.ShowAndRun()
}

func main() {
	gui := NewScannerGUI()
	gui.Run()
}
