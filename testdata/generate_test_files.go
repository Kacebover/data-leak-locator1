//go:build ignore
// +build ignore

package main

import (
	"archive/zip"
	"encoding/base64"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"os"
	"path/filepath"
)

func main() {
	baseDir := filepath.Dir(os.Args[0])
	if len(os.Args) > 1 {
		baseDir = os.Args[1]
	}

	// Create directories
	dirs := []string{"docs", "images", "archives", "office"}
	for _, dir := range dirs {
		os.MkdirAll(filepath.Join(baseDir, dir), 0755)
	}

	fmt.Println("📁 Создание тестовых файлов...")

	// Create text files with secrets
	createTextFiles(baseDir)

	// Create DOCX file (it's actually a ZIP with XML)
	createDocx(baseDir)

	// Create XLSX file (it's actually a ZIP with XML)
	createXlsx(baseDir)

	// Create PNG image with text
	createImage(baseDir)

	// Create ZIP archive with secrets
	createZipArchive(baseDir)

	fmt.Println("✅ Все тестовые файлы созданы!")
}

func createTextFiles(baseDir string) {
	files := map[string]string{
		"docs/config.env": `# Конфигурация продакшена
DATABASE_URL=postgres://admin:SuperSecret123!@db.prod.com:5432/production
REDIS_PASSWORD=redis_pass_abc123
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
`,
		"docs/personal.csv": `Имя,Фамилия,Паспорт,Телефон,Карта
Иван,Иванов,4512 345678,+79991234567,4111111111111111
Пётр,Петров,4613 654321,+79997654321,5500000000000004
`,
		"docs/secrets.json": `{
  "api_key": "sk_live_51H7hJ2KZvJgA1BcDeFgHiJkLmNoPqRsTuVwXyZ",
  "jwt_secret": "super-secret-jwt-key-12345",
  "db_password": "Pr0duct10n_P@ssw0rd!"
}
`,
	}

	for name, content := range files {
		path := filepath.Join(baseDir, name)
		os.WriteFile(path, []byte(content), 0644)
		fmt.Printf("  ✓ %s\n", name)
	}
}

func createDocx(baseDir string) {
	// DOCX is a ZIP file with specific structure
	docxPath := filepath.Join(baseDir, "office", "secret_document.docx")
	docx, err := os.Create(docxPath)
	if err != nil {
		fmt.Printf("  ✗ Ошибка создания DOCX: %v\n", err)
		return
	}
	defer docx.Close()

	zipWriter := zip.NewWriter(docx)
	defer zipWriter.Close()

	// Content Types
	contentTypes := `<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
</Types>`
	w, _ := zipWriter.Create("[Content_Types].xml")
	w.Write([]byte(contentTypes))

	// Relationships
	os.MkdirAll(filepath.Join(baseDir, "_rels"), 0755)
	rels := `<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`
	w, _ = zipWriter.Create("_rels/.rels")
	w.Write([]byte(rels))

	// Document content with secrets
	document := `<?xml version="1.0" encoding="UTF-8"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:body>
    <w:p><w:r><w:t>КОНФИДЕНЦИАЛЬНЫЙ ДОКУМЕНТ</w:t></w:r></w:p>
    <w:p><w:r><w:t>API ключ: sk_live_51H7hJ2KZvJgA1BcDeFgHiJkLmNoPqRsTuVwXyZ</w:t></w:r></w:p>
    <w:p><w:r><w:t>Пароль БД: SuperSecretPassword123!</w:t></w:r></w:p>
    <w:p><w:r><w:t>AWS ключ: AKIAIOSFODNN7EXAMPLE</w:t></w:r></w:p>
    <w:p><w:r><w:t>Номер карты: 4111111111111111</w:t></w:r></w:p>
    <w:p><w:r><w:t>Паспорт: 45 12 345678</w:t></w:r></w:p>
  </w:body>
</w:document>`
	w, _ = zipWriter.Create("word/document.xml")
	w.Write([]byte(document))

	fmt.Println("  ✓ office/secret_document.docx")
}

func createXlsx(baseDir string) {
	// XLSX is also a ZIP file
	xlsxPath := filepath.Join(baseDir, "office", "employees.xlsx")
	xlsx, err := os.Create(xlsxPath)
	if err != nil {
		fmt.Printf("  ✗ Ошибка создания XLSX: %v\n", err)
		return
	}
	defer xlsx.Close()

	zipWriter := zip.NewWriter(xlsx)
	defer zipWriter.Close()

	// Content Types
	contentTypes := `<?xml version="1.0" encoding="UTF-8"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>
  <Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>
  <Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>
</Types>`
	w, _ := zipWriter.Create("[Content_Types].xml")
	w.Write([]byte(contentTypes))

	// Relationships
	rels := `<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/>
</Relationships>`
	w, _ = zipWriter.Create("_rels/.rels")
	w.Write([]byte(rels))

	// Workbook
	workbook := `<?xml version="1.0" encoding="UTF-8"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">
  <sheets><sheet name="Сотрудники" sheetId="1" r:id="rId1"/></sheets>
</workbook>`
	w, _ = zipWriter.Create("xl/workbook.xml")
	w.Write([]byte(workbook))

	// Workbook rels
	wbRels := `<?xml version="1.0" encoding="UTF-8"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/>
</Relationships>`
	w, _ = zipWriter.Create("xl/_rels/workbook.xml.rels")
	w.Write([]byte(wbRels))

	// Shared strings with secrets
	sharedStrings := `<?xml version="1.0" encoding="UTF-8"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="12" uniqueCount="12">
  <si><t>Имя</t></si>
  <si><t>Паспорт</t></si>
  <si><t>Карта</t></si>
  <si><t>Пароль</t></si>
  <si><t>Иванов Иван</t></si>
  <si><t>4512 345678</t></si>
  <si><t>4111111111111111</t></si>
  <si><t>password123</t></si>
  <si><t>Петров Пётр</t></si>
  <si><t>4613 654321</t></si>
  <si><t>5500000000000004</t></si>
  <si><t>secret456!</t></si>
</sst>`
	w, _ = zipWriter.Create("xl/sharedStrings.xml")
	w.Write([]byte(sharedStrings))

	// Worksheet
	sheet := `<?xml version="1.0" encoding="UTF-8"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">
  <sheetData>
    <row r="1"><c r="A1" t="s"><v>0</v></c><c r="B1" t="s"><v>1</v></c><c r="C1" t="s"><v>2</v></c><c r="D1" t="s"><v>3</v></c></row>
    <row r="2"><c r="A2" t="s"><v>4</v></c><c r="B2" t="s"><v>5</v></c><c r="C2" t="s"><v>6</v></c><c r="D2" t="s"><v>7</v></c></row>
    <row r="3"><c r="A3" t="s"><v>8</v></c><c r="B3" t="s"><v>9</v></c><c r="C3" t="s"><v>10</v></c><c r="D3" t="s"><v>11</v></c></row>
  </sheetData>
</worksheet>`
	w, _ = zipWriter.Create("xl/worksheets/sheet1.xml")
	w.Write([]byte(sheet))

	fmt.Println("  ✓ office/employees.xlsx")
}

func createImage(baseDir string) {
	// Create a simple PNG with text-like pattern
	imgPath := filepath.Join(baseDir, "images", "screenshot_secrets.png")

	img := image.NewRGBA(image.Rect(0, 0, 400, 200))
	// Fill with white
	draw.Draw(img, img.Bounds(), &image.Uniform{color.White}, image.Point{}, draw.Src)

	// Add some colored rectangles to simulate text areas
	// This is a placeholder - real OCR would need actual text rendered
	for y := 20; y < 180; y += 25 {
		for x := 20; x < 380; x++ {
			if (x%50 < 40) {
				img.Set(x, y, color.RGBA{0, 0, 0, 255})
				img.Set(x, y+1, color.RGBA{0, 0, 0, 255})
			}
		}
	}

	file, err := os.Create(imgPath)
	if err != nil {
		fmt.Printf("  ✗ Ошибка создания PNG: %v\n", err)
		return
	}
	defer file.Close()
	png.Encode(file, img)

	fmt.Println("  ✓ images/screenshot_secrets.png")

	// Also create a text file describing what would be in the image
	textPath := filepath.Join(baseDir, "images", "screenshot_secrets_ocr.txt")
	ocrContent := `[OCR извлечённый текст из screenshot_secrets.png]

Окно консоли:
$ export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
$ export DATABASE_PASSWORD=SuperSecretDB123!
$ mysql -u admin -pP@ssw0rd123 production

Заметки:
API Key: sk_live_51H7hJ2KZvJgA1BcDeFgHiJkLmNoPqRsTuVwXyZ
GitHub Token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
`
	os.WriteFile(textPath, []byte(ocrContent), 0644)
	fmt.Println("  ✓ images/screenshot_secrets_ocr.txt")
}

func createZipArchive(baseDir string) {
	archivePath := filepath.Join(baseDir, "archives", "backup_secrets.zip")
	archive, err := os.Create(archivePath)
	if err != nil {
		fmt.Printf("  ✗ Ошибка создания ZIP: %v\n", err)
		return
	}
	defer archive.Close()

	zipWriter := zip.NewWriter(archive)
	defer zipWriter.Close()

	files := map[string]string{
		"config/.env": `DATABASE_URL=postgres://admin:secret@localhost:5432/db
API_KEY=sk_live_XXXXXXXXXXXXXXXXXXXXXXXX
JWT_SECRET=my-super-secret-jwt-key
`,
		"data/users.csv": `id,name,password_hash,credit_card
1,admin,$2b$12$XXXXXX,4111111111111111
2,user,$2b$12$YYYYYY,5500000000000004
`,
		"keys/id_rsa": `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z0BN9yLmNdPQjq
PRIVATEKEY
-----END RSA PRIVATE KEY-----
`,
	}

	for name, content := range files {
		w, _ := zipWriter.Create(name)
		w.Write([]byte(content))
	}

	fmt.Println("  ✓ archives/backup_secrets.zip")
}

// Helper to encode base64
func encodeBase64(data string) string {
	return base64.StdEncoding.EncodeToString([]byte(data))
}

