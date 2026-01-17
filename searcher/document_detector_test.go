package searcher

import (
	"testing"
)

func TestDocumentDetector_DetectPassport(t *testing.T) {
	dd := NewDocumentDetector()

	tests := []struct {
		name     string
		text     string
		wantType DocumentType
		wantFind bool
	}{
		{
			name:     "Russian passport with series and number",
			text:     "Паспорт серия 45 12 номер 345678",
			wantType: DocTypePassport,
			wantFind: true,
		},
		{
			name:     "Passport number format",
			text:     "Документ: 4512 345678 выдан УФМС",
			wantType: DocTypePassport,
			wantFind: true,
		},
		{
			name:     "MRZ line",
			text:     "P<RUSIVANOV<<IVAN<<IVANOVICH<<<<<<<<<<<<<<<<<<",
			wantType: DocTypePassport,
			wantFind: true,
		},
		{
			name:     "No passport data",
			text:     "Просто обычный текст без паспортных данных",
			wantFind: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			docs := dd.DetectInText(tt.text, "test.txt")
			
			found := false
			for _, doc := range docs {
				if doc.Type == tt.wantType {
					found = true
					break
				}
			}

			if found != tt.wantFind {
				t.Errorf("DetectInText() found=%v, want=%v", found, tt.wantFind)
			}
		})
	}
}

func TestDocumentDetector_DetectDriverLicense(t *testing.T) {
	dd := NewDocumentDetector()

	tests := []struct {
		name     string
		text     string
		wantFind bool
	}{
		{
			name:     "Russian driver license",
			text:     "Водительское удостоверение номер 78 22 123456",
			wantFind: true,
		},
		{
			name:     "English driver license",
			text:     "Driver's License: DL12345678",
			wantFind: true,
		},
		{
			name:     "German license",
			text:     "Führerschein Nummer: ABC123456",
			wantFind: true,
		},
		{
			name:     "No license data",
			text:     "Обычный текст",
			wantFind: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			docs := dd.DetectInText(tt.text, "test.txt")
			
			found := false
			for _, doc := range docs {
				if doc.Type == DocTypeDriverLicense {
					found = true
					break
				}
			}

			if found != tt.wantFind {
				t.Errorf("DetectInText() driver license found=%v, want=%v", found, tt.wantFind)
			}
		})
	}
}

func TestDocumentDetector_DetectSNILS(t *testing.T) {
	dd := NewDocumentDetector()

	tests := []struct {
		name     string
		text     string
		wantFind bool
	}{
		{
			name:     "Valid SNILS format",
			text:     "СНИЛС: 123-456-789 01",
			wantFind: true,
		},
		{
			name:     "SNILS without dashes is detected as INN",
			text:     "Номер СНИЛС 12345678901",
			wantFind: true, // 11 digits still matches INN pattern
		},
		{
			name:     "INN 12 digits",
			text:     "ИНН физлица: 123456789012",
			wantFind: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			docs := dd.DetectInText(tt.text, "test.txt")
			
			found := false
			for _, doc := range docs {
				if doc.Type == DocTypeIDCard {
					found = true
					break
				}
			}

			if found != tt.wantFind {
				t.Errorf("DetectInText() ID card found=%v, want=%v", found, tt.wantFind)
			}
		})
	}
}

func TestDocumentDetector_DetectCreditCard(t *testing.T) {
	dd := NewDocumentDetector()

	tests := []struct {
		name     string
		text     string
		wantFind bool
	}{
		{
			name:     "Visa card number",
			text:     "Карта Visa: 4111 1111 1111 1111",
			wantFind: true,
		},
		{
			name:     "MasterCard with dashes",
			text:     "MasterCard: 5500-0000-0000-0004",
			wantFind: true,
		},
		{
			name:     "Card with CVV",
			text:     "Card: 4111111111111111 CVV: 123",
			wantFind: true,
		},
		{
			name:     "No card data",
			text:     "Просто текст без карт",
			wantFind: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			docs := dd.DetectInText(tt.text, "test.txt")
			
			found := false
			for _, doc := range docs {
				if doc.Type == DocTypeCreditCard {
					found = true
					break
				}
			}

			if found != tt.wantFind {
				t.Errorf("DetectInText() credit card found=%v, want=%v", found, tt.wantFind)
			}
		})
	}
}

func TestDocumentDetector_DetectBankDocument(t *testing.T) {
	dd := NewDocumentDetector()

	tests := []struct {
		name     string
		text     string
		wantFind bool
	}{
		{
			name:     "IBAN with bank context",
			text:     "Банковская выписка\nIBAN: DE89370400440532013000\nБаланс: 1000 EUR",
			wantFind: true,
		},
		{
			name:     "IBAN and BIC together",
			text:     "Реквизиты счёта:\nIBAN: DE89370400440532013000\nBIC: COBADEFFXXX",
			wantFind: true,
		},
		{
			name:     "Bank statement with IBAN",
			text:     "ВЫПИСКА ПО СЧЁТУ\nIBAN: RU89123400440532013000\nБаланс: 50000.00\nОперация: перевод",
			wantFind: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			docs := dd.DetectInText(tt.text, "test.txt")
			
			found := false
			for _, doc := range docs {
				if doc.Type == DocTypeBankStatement {
					found = true
					break
				}
			}

			if found != tt.wantFind {
				t.Errorf("DetectInText() bank doc found=%v, want=%v", found, tt.wantFind)
			}
		})
	}
}

func TestDocumentDetector_DetectMedicalRecord(t *testing.T) {
	dd := NewDocumentDetector()

	tests := []struct {
		name     string
		text     string
		wantFind bool
	}{
		{
			name:     "OMS policy number",
			text:     "Полис ОМС: 1234567890123456",
			wantFind: true,
		},
		{
			name:     "Medical keywords",
			text:     "Медицинская карта пациента. Диагноз: ОРВИ",
			wantFind: true,
		},
		{
			name:     "Prescription",
			text:     "Рецепт на лекарство выписан врачом",
			wantFind: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			docs := dd.DetectInText(tt.text, "test.txt")
			
			found := false
			for _, doc := range docs {
				if doc.Type == DocTypeMedicalRecord {
					found = true
					break
				}
			}

			if found != tt.wantFind {
				t.Errorf("DetectInText() medical record found=%v, want=%v", found, tt.wantFind)
			}
		})
	}
}

func TestDocumentDetector_MultipleDocuments(t *testing.T) {
	dd := NewDocumentDetector()

	text := `
	Персональные данные:
	Паспорт: 45 12 345678
	СНИЛС: 123-456-789 01
	Карта Visa: 4111 1111 1111 1111
	Полис ОМС: 1234567890123456
	`

	docs := dd.DetectInText(text, "test.txt")

	expectedTypes := map[DocumentType]bool{
		DocTypePassport:      true,
		DocTypeIDCard:        true,
		DocTypeCreditCard:    true,
		DocTypeMedicalRecord: true,
	}

	foundTypes := make(map[DocumentType]bool)
	for _, doc := range docs {
		foundTypes[doc.Type] = true
	}

	for expType := range expectedTypes {
		if !foundTypes[expType] {
			t.Errorf("Expected to find document type %s but didn't", expType)
		}
	}
}

func TestGetDocumentTypeDescription(t *testing.T) {
	tests := []struct {
		docType DocumentType
		wantRu  string
	}{
		{DocTypePassport, "Паспорт (внутренний или заграничный)"},
		{DocTypeDriverLicense, "Водительское удостоверение"},
		{DocTypeCreditCard, "Банковская карта"},
	}

	for _, tt := range tests {
		t.Run(string(tt.docType), func(t *testing.T) {
			got := GetDocumentTypeDescription(tt.docType)
			if got != tt.wantRu {
				t.Errorf("GetDocumentTypeDescription(%s) = %s, want %s", tt.docType, got, tt.wantRu)
			}
		})
	}
}

