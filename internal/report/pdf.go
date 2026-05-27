package report

import (
	"bytes"
	"fmt"
	"strings"

	"bd-scan/internal/model"
)

func renderPDF(result model.AnalysisResult) ([]byte, error) {
	text := string(renderText(result))
	lines := wrapLines(strings.Split(text, "\n"), 92)
	if len(lines) == 0 {
		lines = []string{"BD Analyzer"}
	}

	pages := chunk(lines, 44)
	if len(pages) == 0 {
		pages = [][]string{{"BD Analyzer"}}
	}

	objects := map[int]string{
		1: "<< /Type /Catalog /Pages 2 0 R >>",
		3: "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}

	kids := make([]string, 0, len(pages))
	nextID := 4
	for _, pageLines := range pages {
		pageID := nextID
		contentID := nextID + 1
		nextID += 2

		kids = append(kids, fmt.Sprintf("%d 0 R", pageID))
		objects[pageID] = fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents %d 0 R >>", contentID)

		content := buildPDFContent(pageLines)
		objects[contentID] = fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content)
	}

	objects[2] = fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(kids))

	var buffer bytes.Buffer
	buffer.WriteString("%PDF-1.4\n")

	offsets := make([]int, nextID)
	for id := 1; id < nextID; id++ {
		offsets[id] = buffer.Len()
		buffer.WriteString(fmt.Sprintf("%d 0 obj\n%s\nendobj\n", id, objects[id]))
	}

	xrefOffset := buffer.Len()
	buffer.WriteString(fmt.Sprintf("xref\n0 %d\n", nextID))
	buffer.WriteString("0000000000 65535 f \n")
	for id := 1; id < nextID; id++ {
		buffer.WriteString(fmt.Sprintf("%010d 00000 n \n", offsets[id]))
	}
	buffer.WriteString(fmt.Sprintf("trailer << /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF", nextID, xrefOffset))

	return buffer.Bytes(), nil
}

func buildPDFContent(lines []string) string {
	var builder strings.Builder
	builder.WriteString("BT\n/F1 10 Tf\n14 TL\n50 790 Td\n")
	for index, line := range lines {
		if index > 0 {
			builder.WriteString("T*\n")
		}
		builder.WriteString(fmt.Sprintf("(%s) Tj\n", escapePDFText(line)))
	}
	builder.WriteString("ET")
	return builder.String()
}

func escapePDFText(value string) string {
	replacer := strings.NewReplacer("\\", "\\\\", "(", "\\(", ")", "\\)")
	return replacer.Replace(value)
}

func wrapLines(lines []string, width int) []string {
	var wrapped []string
	for _, line := range lines {
		remaining := strings.TrimRight(line, "\r")
		if remaining == "" {
			wrapped = append(wrapped, "")
			continue
		}

		for len(remaining) > width {
			split := strings.LastIndex(remaining[:width], " ")
			if split <= 0 {
				split = width
			}
			wrapped = append(wrapped, strings.TrimSpace(remaining[:split]))
			remaining = strings.TrimSpace(remaining[split:])
		}
		wrapped = append(wrapped, remaining)
	}
	return wrapped
}

func chunk(lines []string, size int) [][]string {
	var pages [][]string
	for len(lines) > 0 {
		if len(lines) < size {
			pages = append(pages, append([]string{}, lines...))
			break
		}
		pages = append(pages, append([]string{}, lines[:size]...))
		lines = lines[size:]
	}
	return pages
}
