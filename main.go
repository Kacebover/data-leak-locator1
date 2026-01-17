package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kacebover/password-finder/encryptor"
	"github.com/kacebover/password-finder/searcher"
)

func main() {
	// Проверка подкоманд
	if len(os.Args) >= 2 {
		switch os.Args[1] {
		case "encrypt", "шифровать":
			runEncryptCommand(os.Args[2:])
			return
		case "scan", "сканировать":
			runScanCommand(os.Args[2:])
			return
		case "help", "--help", "-h", "помощь":
			printMainHelp()
			return
		}
	}

	// По умолчанию: запуск сканирования с устаревшими флагами для обратной совместимости
	runScanCommandLegacy()
}

func printMainHelp() {
	fmt.Println("🔍 Поиск Утечек Данных - Сканер и Шифровальщик")
	fmt.Println("================================================")
	fmt.Println()
	fmt.Println("Команды:")
	fmt.Println("  scan (сканировать)    Сканировать директорию на наличие чувствительных данных")
	fmt.Println("  encrypt (шифровать)   Зашифровать файлы в защищённый паролем ZIP-архив")
	fmt.Println("  help (помощь)         Показать эту справку")
	fmt.Println()
	fmt.Println("Использование:")
	fmt.Println("  data-leak-locator scan [опции]")
	fmt.Println("  data-leak-locator encrypt [опции] <файлы...>")
	fmt.Println()
	fmt.Println("Примеры:")
	fmt.Println("  data-leak-locator scan -dir /путь/к/проекту")
	fmt.Println("  data-leak-locator encrypt -output secrets.zip file1.txt file2.env")
	fmt.Println("  data-leak-locator encrypt -dir /sensitive/data -password mypass")
	fmt.Println()
	fmt.Println("Запустите 'data-leak-locator <команда> -h' для подробной информации.")
}

// ═══════════════════════════════════════════════════════════════════════════
// КОМАНДА ШИФРОВАНИЯ
// ═══════════════════════════════════════════════════════════════════════════

func runEncryptCommand(args []string) {
	encryptCmd := flag.NewFlagSet("encrypt", flag.ExitOnError)

	outputPath := encryptCmd.String("output", "", "Путь к выходному ZIP-файлу (обязательно)")
	password := encryptCmd.String("password", "", "Пароль для шифрования (будет запрошен, если не указан)")
	dirPath := encryptCmd.String("dir", "", "Директория для шифрования (альтернатива указанию файлов)")
	deleteOriginals := encryptCmd.Bool("delete", false, "Безопасно удалить оригиналы после шифрования")
	deletePasses := encryptCmd.Int("delete-passes", 3, "Количество проходов перезаписи для безопасного удаления")
	generatePwd := encryptCmd.Bool("generate-password", false, "Сгенерировать случайный безопасный пароль")
	pwdLength := encryptCmd.Int("password-length", 16, "Длина генерируемого пароля")
	verbose := encryptCmd.Bool("verbose", false, "Подробный вывод")

	encryptCmd.Usage = func() {
		fmt.Println("🔐 Шифрование и Экспорт Файлов")
		fmt.Println("==============================")
		fmt.Println()
		fmt.Println("Шифрует файлы в защищённый паролем ZIP-архив с использованием AES-256.")
		fmt.Println()
		fmt.Println("Использование:")
		fmt.Println("  data-leak-locator encrypt [опции] <файлы...>")
		fmt.Println("  data-leak-locator encrypt -dir <директория> [опции]")
		fmt.Println()
		fmt.Println("Опции:")
		fmt.Println("  -output string")
		fmt.Println("        Путь к выходному ZIP-файлу (обязательно)")
		fmt.Println("  -password string")
		fmt.Println("        Пароль для шифрования (будет запрошен, если не указан)")
		fmt.Println("  -dir string")
		fmt.Println("        Директория для шифрования (альтернатива указанию файлов)")
		fmt.Println("  -delete")
		fmt.Println("        Безопасно удалить оригиналы после шифрования")
		fmt.Println("  -delete-passes int")
		fmt.Println("        Количество проходов перезаписи (по умолчанию: 3)")
		fmt.Println("  -generate-password")
		fmt.Println("        Сгенерировать случайный безопасный пароль")
		fmt.Println("  -password-length int")
		fmt.Println("        Длина генерируемого пароля (по умолчанию: 16)")
		fmt.Println("  -verbose")
		fmt.Println("        Подробный вывод")
		fmt.Println()
		fmt.Println("Примеры:")
		fmt.Println("  # Зашифровать файлы с запросом пароля")
		fmt.Println("  data-leak-locator encrypt -output secrets.zip config.env api_keys.txt")
		fmt.Println()
		fmt.Println("  # Зашифровать директорию с генерацией пароля")
		fmt.Println("  data-leak-locator encrypt -dir ./sensitive -output backup.zip -generate-password")
		fmt.Println()
		fmt.Println("  # Зашифровать и безопасно удалить оригиналы")
		fmt.Println("  data-leak-locator encrypt -output secure.zip -delete -password myP@ss123 file.txt")
		fmt.Println()
		fmt.Println("Безопасность:")
		fmt.Println("  • Используется шифрование AES-256 (совместимо с WinZip)")
		fmt.Println("  • Пароли не сохраняются и не логируются")
		fmt.Println("  • Безопасное удаление использует многократную перезапись")
	}

	if err := encryptCmd.Parse(args); err != nil {
		os.Exit(1)
	}

	// Сбор файлов для шифрования
	var files []string

	if *dirPath != "" {
		// Проверка директории
		info, err := os.Stat(*dirPath)
		if err != nil {
			fmt.Printf("❌ Ошибка: Директория не найдена: %s\n", *dirPath)
			os.Exit(1)
		}
		if !info.IsDir() {
			fmt.Printf("❌ Ошибка: Это не директория: %s\n", *dirPath)
			os.Exit(1)
		}
		files = append(files, *dirPath)
	}

	// Добавление файлов из оставшихся аргументов
	files = append(files, encryptCmd.Args()...)

	if len(files) == 0 {
		fmt.Println("❌ Ошибка: Не указаны файлы для шифрования")
		fmt.Println("Используйте -dir для указания директории или укажите пути к файлам")
		encryptCmd.Usage()
		os.Exit(1)
	}

	// Проверка пути вывода
	if *outputPath == "" {
		fmt.Println("❌ Ошибка: Необходимо указать путь вывода (-output)")
		os.Exit(1)
	}

	// Добавление расширения .zip
	if !strings.HasSuffix(strings.ToLower(*outputPath), ".zip") {
		*outputPath += ".zip"
	}

	// Обработка пароля
	pwd := *password

	if *generatePwd {
		generatedPwd, err := encryptor.GeneratePassword(*pwdLength)
		if err != nil {
			fmt.Printf("❌ Ошибка генерации пароля: %v\n", err)
			os.Exit(1)
		}
		pwd = generatedPwd
		fmt.Println("🔑 Сгенерированный пароль:")
		fmt.Println()
		fmt.Printf("   %s\n", pwd)
		fmt.Println()
		fmt.Println("⚠️  ВАЖНО: Сохраните этот пароль! Его невозможно восстановить.")
		fmt.Println()
	} else if pwd == "" {
		// Запрос пароля
		pwd = promptPassword("Введите пароль для шифрования: ")
		confirmPwd := promptPassword("Подтвердите пароль: ")

		if pwd != confirmPwd {
			fmt.Println("❌ Ошибка: Пароли не совпадают")
			os.Exit(1)
		}
	}

	// Проверка пароля
	if err := encryptor.ValidatePassword(pwd); err != nil {
		fmt.Printf("❌ Ошибка: %v\n", err)
		os.Exit(1)
	}

	// Проверка существования файлов
	var fileEntries []encryptor.FileEntry
	for _, f := range files {
		absPath, err := filepath.Abs(f)
		if err != nil {
			fmt.Printf("❌ Ошибка определения пути %s: %v\n", f, err)
			os.Exit(1)
		}

		if _, err := os.Stat(absPath); err != nil {
			fmt.Printf("❌ Ошибка: Файл не найден: %s\n", absPath)
			os.Exit(1)
		}

		fileEntries = append(fileEntries, encryptor.FileEntry{SourcePath: absPath})
	}

	// Настройка шифровальщика
	config := encryptor.DefaultConfig()
	config.Password = pwd
	config.OutputPath = *outputPath
	config.CompressionLevel = 6

	if *verbose {
		config.OnProgress = func(processed, total int64, currentFile string) {
			pct := float64(processed) / float64(total) * 100
			fmt.Printf("\r🔄 Шифрование: %s (%.1f%%)     ", filepath.Base(currentFile), pct)
		}
	}

	enc, err := encryptor.NewEncryptor(config)
	if err != nil {
		fmt.Printf("❌ Ошибка: %v\n", err)
		os.Exit(1)
	}

	if *verbose {
		fmt.Printf("🔐 Шифрование %d элементов в %s...\n", len(fileEntries), *outputPath)
	}

	// Запуск шифрования
	result, err := enc.EncryptFilesWithResult(fileEntries)
	if err != nil {
		fmt.Printf("\n❌ Ошибка шифрования: %v\n", err)
		os.Exit(1)
	}

	if *verbose {
		fmt.Println() // новая строка после прогресса
	}

	// Вывод результата
	fmt.Println()
	fmt.Println("✅ Шифрование завершено!")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("📦 Архив:             %s\n", result.OutputPath)
	fmt.Printf("📁 Файлов:            %d\n", result.FilesEncrypted)
	fmt.Printf("📊 Исходный размер:   %s\n", formatBytes(result.TotalSize))
	fmt.Printf("📊 Размер архива:     %s\n", formatBytes(result.ArchiveSize))
	fmt.Printf("📈 Сжатие:            %.1f%%\n", result.CompressionRatio*100)
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")

	// Безопасное удаление, если запрошено
	if *deleteOriginals {
		fmt.Println()
		fmt.Printf("🗑️  Безопасное удаление %d оригинальных файлов (%d проходов)...\n", len(files), *deletePasses)

		// Сбор путей к файлам (развёртывание директорий)
		var filesToDelete []string
		for _, f := range files {
			info, _ := os.Stat(f)
			if info.IsDir() {
				filepath.Walk(f, func(path string, info os.FileInfo, err error) error {
					if err == nil && !info.IsDir() {
						filesToDelete = append(filesToDelete, path)
					}
					return nil
				})
			} else {
				filesToDelete = append(filesToDelete, f)
			}
		}

		err := encryptor.SecureDeleteMultiple(filesToDelete, *deletePasses, func(current, total int, path string) {
			if *verbose {
				fmt.Printf("   Удаление: %s (%d/%d)\n", filepath.Base(path), current, total)
			}
		})

		if err != nil {
			fmt.Printf("⚠️  Предупреждение: Некоторые файлы не удалось удалить: %v\n", err)
		} else {
			fmt.Printf("✅ Безопасно удалено %d файлов\n", len(filesToDelete))
		}
	}
}

func promptPassword(prompt string) string {
	fmt.Print(prompt)
	reader := bufio.NewReader(os.Stdin)
	password, _ := reader.ReadString('\n')
	return strings.TrimSpace(password)
}

func formatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d Б", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %s", float64(bytes)/float64(div), []string{"КБ", "МБ", "ГБ", "ТБ"}[exp])
}

// ═══════════════════════════════════════════════════════════════════════════
// КОМАНДА СКАНИРОВАНИЯ
// ═══════════════════════════════════════════════════════════════════════════

func runScanCommand(args []string) {
	scanCmd := flag.NewFlagSet("scan", flag.ExitOnError)

	scanDir := scanCmd.String("dir", "", "Директория для сканирования (обязательно)")
	outputDir := scanCmd.String("output", ".", "Директория для сохранения отчётов")
	maxSize := scanCmd.Int64("max-size", 100*1024*1024, "Максимальный размер файла для сканирования в байтах")
	verbose := scanCmd.Bool("verbose", false, "Подробный вывод")
	enableOCR := scanCmd.Bool("ocr", false, "Включить OCR для изображений (требуется Tesseract)")
	scanDocs := scanCmd.Bool("docs", false, "Сканировать документы (PDF, DOCX, XLSX)")
	scanArchives := scanCmd.Bool("archives", false, "Сканировать содержимое архивов (ZIP, TAR)")
	enableAI := scanCmd.Bool("ai", false, "Включить AI-анализ (требуется Ollama)")
	aiModel := scanCmd.String("ai-model", "llama3.2", "Модель Ollama для AI-анализа")

	scanCmd.Usage = func() {
		fmt.Println("🔍 Сканирование на Чувствительные Данные")
		fmt.Println("========================================")
		fmt.Println()
		fmt.Println("Сканирует директорию на наличие чувствительных данных:")
		fmt.Println("паролей, API-ключей, токенов, банковских карт и т.д.")
		fmt.Println()
		fmt.Println("Использование:")
		fmt.Println("  data-leak-locator scan -dir <директория> [опции]")
		fmt.Println()
		fmt.Println("Основные опции:")
		fmt.Println("  -dir string")
		fmt.Println("        Директория для сканирования (обязательно)")
		fmt.Println("  -output string")
		fmt.Println("        Директория для сохранения отчётов (по умолчанию: .)")
		fmt.Println("  -max-size int")
		fmt.Println("        Максимальный размер файла в байтах (по умолчанию: 100МБ)")
		fmt.Println("  -verbose")
		fmt.Println("        Подробный вывод")
		fmt.Println()
		fmt.Println("Расширенные опции:")
		fmt.Println("  -ocr")
		fmt.Println("        Включить OCR для извлечения текста из изображений (требуется Tesseract)")
		fmt.Println("  -docs")
		fmt.Println("        Сканировать документы: PDF, DOCX, DOC, XLSX, XLS")
		fmt.Println("  -archives")
		fmt.Println("        Сканировать содержимое архивов: ZIP, TAR, GZ")
		fmt.Println()
		fmt.Println("AI-анализ (локальный, без внешних запросов):")
		fmt.Println("  -ai")
		fmt.Println("        Включить AI-анализ с использованием Ollama")
		fmt.Println("  -ai-model string")
		fmt.Println("        Модель Ollama (по умолчанию: llama3.2)")
		fmt.Println()
		fmt.Println("Примеры:")
		fmt.Println("  data-leak-locator scan -dir /путь/к/проекту")
		fmt.Println("  data-leak-locator scan -dir ./src -docs -archives -verbose")
		fmt.Println("  data-leak-locator scan -dir ./data -ocr -ai -ai-model mistral")
	}

	if err := scanCmd.Parse(args); err != nil {
		os.Exit(1)
	}

	if *scanDir == "" {
		scanCmd.Usage()
		os.Exit(1)
	}

	runScan(*scanDir, *outputDir, *maxSize, *verbose, *enableOCR, *scanDocs, *scanArchives, *enableAI, *aiModel)
}

// Устаревшая команда для обратной совместимости
func runScanCommandLegacy() {
	scanDir := flag.String("scan", "", "Директория для сканирования")
	outputDir := flag.String("output", ".", "Директория для сохранения отчётов")
	maxSize := flag.Int64("max-size", 100*1024*1024, "Максимальный размер файла в байтах")
	verbose := flag.Bool("verbose", false, "Подробный вывод")

	flag.Parse()

	if *scanDir == "" {
		printMainHelp()
		os.Exit(1)
	}

	runScan(*scanDir, *outputDir, *maxSize, *verbose, false, false, false, false, "")
}

func runScan(scanDir, outputDir string, maxSize int64, verbose, enableOCR, scanDocs, scanArchives, enableAI bool, aiModel string) {
	// Проверка существования директории
	if _, err := os.Stat(scanDir); err != nil {
		fmt.Printf("❌ Ошибка: Директория не существует: %s\n", scanDir)
		os.Exit(1)
	}

	// Проверка зависимостей
	depChecker := searcher.NewDependencyChecker()
	depChecker.CheckAll()

	// Проверка необходимых зависимостей для выбранных опций
	if enableOCR && !depChecker.IsTesseractAvailable() {
		fmt.Println("⚠️  Tesseract OCR не установлен!")
		missingDeps := depChecker.GetMissingDependencies()
		if len(missingDeps) > 0 {
			fmt.Printf("   📝 Установите: %s\n", missingDeps[0].InstallHint)
		}
		fmt.Println("   OCR изображений будет недоступен.")
		fmt.Println()
	}

	if scanDocs && !depChecker.IsPopplerAvailable() {
		fmt.Println("⚠️  Poppler не установлен!")
		fmt.Println("   Сканированные PDF будут недоступны для OCR.")
		for _, dep := range depChecker.GetMissingDependencies() {
			if dep.Name == "Poppler (PDF utils)" {
				fmt.Printf("   📝 Установите: %s\n", dep.InstallHint)
				break
			}
		}
		fmt.Println()
	}

	if enableAI && !depChecker.IsOllamaAvailable() {
		fmt.Println("⚠️  Ollama не установлен или не запущен!")
		for _, dep := range depChecker.GetMissingDependencies() {
			if dep.Name == "Ollama (AI)" {
				fmt.Printf("   📝 Установите: %s\n", dep.InstallHint)
				break
			}
		}
		fmt.Println("   AI-анализ будет использовать правило-ориентированный режим.")
		fmt.Println()
	}

	// Создание сканера
	scanner := searcher.NewScanner()
	scanner.SetMaxFileSize(maxSize)

	// Настройка документ-экстрактора
	if scanDocs || scanArchives || enableOCR {
		extractor := searcher.NewDocumentExtractor(enableOCR)
		scanner.SetDocumentExtractor(extractor)
		scanner.SetScanDocuments(scanDocs)
		scanner.SetScanArchives(scanArchives)

		// Разрешить сканирование документов/изображений/архивов в ignore-листе
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

		if verbose {
			fmt.Println("📄 Расширенное сканирование включено:")
			if scanDocs {
				fmt.Println("   • Документы (PDF, DOCX, XLSX)")
			}
			if scanArchives {
				fmt.Println("   • Архивы (ZIP, TAR, GZ)")
			}
			if enableOCR {
				fmt.Println("   • OCR для изображений")
				// Проверяем Tesseract
				if extractor.IsTesseractAvailable() {
					fmt.Println("   ✅ Tesseract найден")
				} else {
					fmt.Println("   ⚠️  Tesseract НЕ установлен! OCR не будет работать.")
					fmt.Println("   📝 Установите: brew install tesseract (macOS)")
				}
			}
		}
	}

	if verbose {
		fmt.Printf("🔍 Начинаю сканирование: %s\n", scanDir)
	}

	// Выполнение сканирования
	result, err := scanner.Scan(scanDir)
	if err != nil {
		fmt.Printf("❌ Ошибка сканирования: %v\n", err)
		os.Exit(1)
	}

	// Вывод сводки
	printSummary(result)

	// AI-анализ
	if enableAI {
		fmt.Println("\n🤖 Выполняю AI-анализ...")
		analyzer := searcher.NewLocalAnalyzer()
		analyzer.EnableAI(true)
		if aiModel != "" {
			analyzer.SetModel(aiModel)
		}

		if !analyzer.IsOllamaAvailable() {
			fmt.Println("⚠️  Ollama недоступен. Используется правило-ориентированный анализ.")
			analyzer.EnableAI(false)
		} else if verbose {
			models, _ := analyzer.GetAvailableModels()
			fmt.Printf("   Доступные модели: %v\n", models)
			fmt.Printf("   Используется: %s\n", aiModel)
		}

		analysis, err := analyzer.Analyze(result)
		if err != nil {
			fmt.Printf("⚠️  Ошибка анализа: %v\n", err)
		} else {
			fmt.Println(analyzer.FormatAnalysisReport(analysis))

			// Сохранить анализ в файл
			analysisPath := outputDir + "/анализ-безопасности_" +
				strings.ReplaceAll(result.GeneratedAt().Format("20060102_150405"), " ", "_") + ".txt"
			os.WriteFile(analysisPath, []byte(analyzer.FormatAnalysisReport(analysis)), 0644)
			if verbose {
				fmt.Printf("📊 Отчёт анализа сохранён: %s\n", analysisPath)
			}
		}
	}

	// Генерация отчётов
	if err := generateReports(result, outputDir); err != nil {
		fmt.Printf("❌ Ошибка генерации отчётов: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("\n📁 Отчёты сохранены в: %s\n", outputDir)
	}
}

// printSummary выводит сводку результатов сканирования
func printSummary(result *searcher.ScanResult) {
	fmt.Println("\n========== РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ ==========")
	fmt.Printf("Просканировано файлов: %d\n", result.FilesScanned)
	fmt.Printf("Пропущено файлов:      %d\n", result.FilesSkipped)
	fmt.Printf("Всего находок:         %d\n", result.TotalFindings())
	fmt.Printf("Ошибок:                %d\n", result.ErrorCount)
	fmt.Println("\nПо уровням серьёзности:")
	fmt.Printf("  🔴 Критический: %d\n", result.GetSeverityCount(searcher.Critical))
	fmt.Printf("  🟠 Высокий:     %d\n", result.GetSeverityCount(searcher.High))
	fmt.Printf("  🟡 Средний:     %d\n", result.GetSeverityCount(searcher.Medium))
	fmt.Printf("  🟢 Низкий:      %d\n", result.GetSeverityCount(searcher.Low))

	// Показать причины пропуска файлов (если есть)
	if len(result.SkipReasons) > 0 {
		fmt.Println("\n⚠️  Пропущенные файлы:")
		count := 0
		for file, reason := range result.SkipReasons {
			if count >= 10 {
				fmt.Printf("   ... и ещё %d файлов\n", len(result.SkipReasons)-10)
				break
			}
			fmt.Printf("   • %s: %s\n", file, reason)
			count++
		}
	}

	if result.TotalFindings() > 0 {
		fmt.Println("\nТоп находок (по уровню риска):")
		// Показать топ-10 находок
		shown := 0
		for _, finding := range result.Findings {
			if shown >= 10 {
				break
			}
			severityRu := severityToRussian(finding.Severity)
			fmt.Printf("  [%s] %s:%d - %s (Риск: %.1f)\n",
				severityRu,
				finding.FilePath,
				finding.LineNumber,
				descriptionToRussian(finding.Description),
				finding.RiskScore)
			shown++
		}
	}

	fmt.Println("\n==============================================")
}

func severityToRussian(s searcher.Severity) string {
	switch s {
	case searcher.Critical:
		return "Крит."
	case searcher.High:
		return "Высок."
	case searcher.Medium:
		return "Сред."
	case searcher.Low:
		return "Низк."
	default:
		return string(s)
	}
}

func descriptionToRussian(desc string) string {
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

// generateReports создаёт отчёты в JSON, CSV и текстовом формате
func generateReports(result *searcher.ScanResult, outputDir string) error {
	// Создание директории вывода, если не существует
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("не удалось создать директорию вывода: %v", err)
	}

	reporter := searcher.NewReportGenerator(result)

	// Экспорт во все форматы
	if err := reporter.GenerateReport(outputDir); err != nil {
		return err
	}

	// Вывод информации о файлах отчётов
	fmt.Printf("✅ Отчёты сгенерированы в: %s\n", outputDir)
	return nil
}
