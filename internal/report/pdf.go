package report

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/go-pdf/fpdf"

	"bd-scan/internal/assets"
	"bd-scan/internal/model"
)

const (
	pdfFontFamily    = "NotoSans"
	pdfTitleFontSize = 14.0
	pdfBodyFontSize  = 10.0
	pdfLineHeight    = 5.0
)

// renderPDF builds the PDF report from the same plain-text content as the TXT
// report, using an embedded Unicode TrueType font (Noto Sans) so Cyrillic
// text renders correctly. The standard 14 PDF fonts (e.g. Helvetica) only
// cover Latin/WinAnsi glyphs and cannot represent Cyrillic at all, which is
// why earlier output showed garbled characters.
func renderPDF(result model.AnalysisResult) ([]byte, error) {
	text := string(renderText(result))
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")

	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 15)
	pdf.SetMargins(15, 15, 15)
	pdf.AddUTF8FontFromBytes(pdfFontFamily, "", assets.NotoSansRegular)
	pdf.AddUTF8FontFromBytes(pdfFontFamily, "B", assets.NotoSansBold)
	pdf.AddPage()

	for index, line := range lines {
		if line == "" {
			pdf.Ln(pdfLineHeight)
			continue
		}

		if index == 0 {
			pdf.SetFont(pdfFontFamily, "B", pdfTitleFontSize)
		} else {
			pdf.SetFont(pdfFontFamily, "", pdfBodyFontSize)
		}
		pdf.MultiCell(0, pdfLineHeight, line, "", "L", false)
	}

	var buffer bytes.Buffer
	if err := pdf.Output(&buffer); err != nil {
		return nil, fmt.Errorf("не удалось сформировать PDF-отчет: %w", err)
	}

	return buffer.Bytes(), nil
}
