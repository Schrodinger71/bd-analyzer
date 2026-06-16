package report

import (
	"encoding/json"
	"fmt"
	"strings"

	"bd-scan/internal/model"
	"bd-scan/internal/remediation"
)

type Format string

const (
	FormatText Format = "txt"
	FormatHTML Format = "html"
	FormatJSON Format = "json"
	FormatPDF  Format = "pdf"
)

type Input struct {
	Analysis       model.AnalysisResult
	Snapshot       *model.ConfigSnapshot
	Proposals      []remediation.Proposal
	AutoApplicable []remediation.Proposal
}

func ParseFormat(raw string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "txt", "text":
		return FormatText, nil
	case "html":
		return FormatHTML, nil
	case "json":
		return FormatJSON, nil
	case "pdf":
		return FormatPDF, nil
	default:
		return "", fmt.Errorf("неподдерживаемый формат отчета: %q", raw)
	}
}

func (f Format) Extension() string {
	return string(f)
}

func Render(result model.AnalysisResult, format Format) ([]byte, error) {
	return RenderDetailed(Input{Analysis: result}, format)
}

func RenderDetailed(input Input, format Format) ([]byte, error) {
	switch format {
	case FormatText:
		return renderText(input.Analysis), nil
	case FormatHTML:
		return renderHTML(input)
	case FormatJSON:
		return renderJSON(input.Analysis)
	case FormatPDF:
		return renderPDF(input.Analysis)
	default:
		return nil, fmt.Errorf("неподдерживаемый формат отчета: %s", format)
	}
}

func renderText(result model.AnalysisResult) []byte {
	var builder strings.Builder

	builder.WriteString("ОТЧЕТ ОБ АНАЛИЗЕ ЗАЩИЩЕННОСТИ КОНФИГУРАЦИИ СУБД\n")
	builder.WriteString("================================================\n")
	builder.WriteString(fmt.Sprintf("Цель анализа: %s\n", result.Target))
	builder.WriteString(fmt.Sprintf("Профиль контроля: %s\n", result.Class.Label()))
	builder.WriteString(fmt.Sprintf("Сформирован: %s\n", result.GeneratedAt.Format("2006-01-02 15:04:05")))
	builder.WriteString(fmt.Sprintf("Итоговый балл защищенности: %d/100\n", result.Score))
	builder.WriteString(fmt.Sprintf("Результаты: успешно %d, предупреждений %d, несоответствий %d\n\n", result.Summary.Passed, result.Summary.Warnings, result.Summary.Failed))

	builder.WriteString("КЛЮЧЕВЫЕ НЕСООТВЕТСТВИЯ\n")
	builder.WriteString("-----------------------\n")
	issues := result.NonPassingFindings()
	if len(issues) == 0 {
		builder.WriteString("Существенных несоответствий не выявлено.\n")
	} else {
		for index, finding := range issues {
			builder.WriteString(fmt.Sprintf("%d. [%s/%s] %s\n", index+1, strings.ToUpper(string(finding.Status)), strings.ToUpper(string(finding.Severity)), finding.Title))
			builder.WriteString(fmt.Sprintf("   Категория: %s\n", finding.Category))
			builder.WriteString(fmt.Sprintf("   Требование: %s\n", finding.Requirement))
			builder.WriteString(fmt.Sprintf("   Риск: %s\n", finding.Risk))
			builder.WriteString(fmt.Sprintf("   Рекомендация: %s\n", finding.Recommendation))
			if len(finding.Evidence) > 0 {
				builder.WriteString("   Подтверждающие данные:\n")
				for _, evidence := range finding.Evidence {
					builder.WriteString(fmt.Sprintf("   - %s\n", evidence))
				}
			}
			builder.WriteString("\n")
		}
	}

	if len(result.Notes) > 0 {
		builder.WriteString("ПРИМЕЧАНИЯ СБОРА ДАННЫХ\n")
		builder.WriteString("----------------------\n")
		for _, note := range result.Notes {
			builder.WriteString(fmt.Sprintf("- %s\n", note))
		}
	}

	return []byte(builder.String())
}

func renderJSON(result model.AnalysisResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}
