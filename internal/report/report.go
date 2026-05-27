package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"strings"

	"bd-scan/internal/model"
)

type Format string

const (
	FormatText Format = "txt"
	FormatHTML Format = "html"
	FormatJSON Format = "json"
	FormatPDF  Format = "pdf"
)

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
	switch format {
	case FormatText:
		return renderText(result), nil
	case FormatHTML:
		return renderHTML(result)
	case FormatJSON:
		return renderJSON(result)
	case FormatPDF:
		return renderPDF(result)
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

func renderHTML(result model.AnalysisResult) ([]byte, error) {
	const page = `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>Отчет BD Analyzer</title>
<style>
:root {
  color-scheme: light;
  --bg: #f4f1e8;
  --panel: #fffdf8;
  --text: #1f2430;
  --muted: #576074;
  --warn: #b45f06;
  --fail: #9b2226;
  --border: #d8d1c5;
}
body {
  margin: 0;
  font-family: "Segoe UI", sans-serif;
  background: linear-gradient(135deg, #f4f1e8 0%, #f9f6ef 50%, #e8efe9 100%);
  color: var(--text);
}
.wrap {
  max-width: 1080px;
  margin: 0 auto;
  padding: 32px;
}
.hero, .card {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 18px;
  box-shadow: 0 14px 40px rgba(31, 36, 48, 0.08);
}
.hero {
  padding: 28px;
  margin-bottom: 24px;
}
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 16px;
  margin-top: 20px;
}
.metric {
  padding: 16px;
  background: #f7fbfb;
  border-radius: 14px;
  border: 1px solid #dce9e9;
}
.label {
  color: var(--muted);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.08em;
}
.value {
  font-size: 28px;
  margin-top: 8px;
  font-weight: 700;
}
.card {
  padding: 24px;
  margin-bottom: 18px;
}
.status-pass { color: #2a9d8f; }
.status-warn { color: var(--warn); }
.status-fail { color: var(--fail); }
ul {
  margin: 12px 0 0;
}
li {
  margin-bottom: 8px;
}
</style>
</head>
<body>
<div class="wrap">
  <section class="hero">
    <h1>Анализ защищенности конфигурации СУБД</h1>
    <p>Цель анализа: {{ .Target }}</p>
    <p>Профиль контроля: {{ .Class.Label }}</p>
    <p>Время формирования: {{ .GeneratedAt.Format "2006-01-02 15:04:05" }}</p>
    <div class="grid">
      <div class="metric"><div class="label">Итоговый балл</div><div class="value">{{ .Score }}/100</div></div>
      <div class="metric"><div class="label">Успешно</div><div class="value status-pass">{{ .Summary.Passed }}</div></div>
      <div class="metric"><div class="label">Предупреждения</div><div class="value status-warn">{{ .Summary.Warnings }}</div></div>
      <div class="metric"><div class="label">Несоответствия</div><div class="value status-fail">{{ .Summary.Failed }}</div></div>
    </div>
  </section>
  {{ range .NonPassingFindings }}
  <section class="card">
    <h2 class="status-{{ .Status }}">{{ .Title }}</h2>
    <p><strong>Категория:</strong> {{ .Category }}</p>
    <p><strong>Требование:</strong> {{ .Requirement }}</p>
    <p><strong>Риск:</strong> {{ .Risk }}</p>
    <p><strong>Рекомендация:</strong> {{ .Recommendation }}</p>
    {{ if .Evidence }}
    <ul>
      {{ range .Evidence }}
      <li>{{ . }}</li>
      {{ end }}
    </ul>
    {{ end }}
  </section>
  {{ end }}
  {{ if .Notes }}
  <section class="card">
    <h2>Примечания к сбору данных</h2>
    <ul>
      {{ range .Notes }}
      <li>{{ . }}</li>
      {{ end }}
    </ul>
  </section>
  {{ end }}
</div>
</body>
</html>`

	tpl, err := template.New("report").Parse(page)
	if err != nil {
		return nil, err
	}

	var buffer bytes.Buffer
	if err := tpl.Execute(&buffer, result); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func renderJSON(result model.AnalysisResult) ([]byte, error) {
	return json.MarshalIndent(result, "", "  ")
}
