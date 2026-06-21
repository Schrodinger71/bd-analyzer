package report

import (
	"bytes"
	"testing"
	"time"

	"bd-scan/internal/model"
)

func TestRenderPDFProducesValidDocumentWithEmbeddedCyrillicFont(t *testing.T) {
	result := model.AnalysisResult{
		Target:      "Кириллица",
		Class:       model.Class4,
		GeneratedAt: time.Now(),
		Score:       87,
		Summary:     model.Summary{Passed: 10, Warnings: 2, Failed: 1},
		Findings: []model.Finding{
			{
				ID:             "AUD-001",
				Title:          "Механизмы регистрации событий безопасности",
				Category:       "Регистрация событий безопасности",
				Status:         model.StatusFail,
				Severity:       model.SeverityCritical,
				Requirement:    "Пункт 10.1 приказа №64",
				Risk:           "Без аудита сложно расследовать инциденты.",
				Recommendation: "Подключить pgAudit.",
				Evidence:       []string{"Не подтверждена подсистема аудита."},
			},
		},
	}

	data, err := renderPDF(result)
	if err != nil {
		t.Fatalf("renderPDF returned error: %v", err)
	}

	if !bytes.HasPrefix(data, []byte("%PDF-")) {
		t.Fatalf("output does not look like a PDF file, got prefix: %q", data[:minInt(20, len(data))])
	}
	if len(data) < 500 {
		t.Fatalf("PDF output suspiciously small: %d bytes", len(data))
	}

	// A bare standard /BaseFont /Helvetica (WinAnsi-only) cannot render Cyrillic
	// at all; that was the root cause of the garbled-character bug. The fpdf
	// UTF-8 font embedding path produces a composite Type0 font instead.
	if bytes.Contains(data, []byte("/BaseFont /Helvetica")) {
		t.Fatalf("PDF still uses the non-Cyrillic standard Helvetica font")
	}
	if !bytes.Contains(data, []byte("/Type0")) {
		t.Fatalf("expected an embedded Type0 composite font (Cyrillic-capable), got none")
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
