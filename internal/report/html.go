package report

import (
	"bytes"
	"fmt"
	"html/template"
	"strings"

	"bd-scan/internal/model"
)

type htmlMetric struct {
	Label string
	Value string
	Class string
}

type htmlKV struct {
	Label string
	Value string
}

type htmlFinding struct {
	ID             string
	Title          string
	Category       string
	Status         string
	StatusClass    string
	StatusLabel    string
	Severity       string
	SeverityLabel  string
	Requirement    string
	Risk           string
	Recommendation string
	Evidence       []string
}

type htmlProposal struct {
	Title       string
	Priority    string
	ApplyMode   string
	Target      string
	ControlRefs []string
	Rationale   string
	FindingID   string
	FindingName string
	AutoApply   bool
	Steps       []string
	Snippet     string
}

type htmlReportView struct {
	Target             string
	ClassLabel         string
	GeneratedAt        string
	Score              int
	Metrics            []htmlMetric
	Connection         string
	HasConnection      bool
	Sources            []htmlKV
	CollectionWarnings []string
	AnalysisNotes      []string
	Findings           []htmlFinding
	Passed             []htmlFinding
	Warnings           []htmlFinding
	Failed             []htmlFinding
	Proposals          []htmlProposal
	AutoCount          int
}

func renderHTML(input Input) ([]byte, error) {
	view := buildHTMLView(input)
	const page = `<!doctype html>
<html lang="ru">
<head>
<meta charset="utf-8">
<title>Отчет BD Analyzer</title>
<style>
:root {
  color-scheme: light;
  --bg: #f3eee4;
  --panel: rgba(255, 252, 245, 0.96);
  --panel-strong: #fffdfa;
  --text: #1f2933;
  --muted: #5e6c84;
  --border: #d8cfbe;
  --pass: #2f7d4a;
  --pass-bg: #edf8f0;
  --warn: #a65c00;
  --warn-bg: #fff3df;
  --fail: #a33232;
  --fail-bg: #fff0ef;
  --accent: #214e7a;
  --shadow: 0 18px 42px rgba(31, 41, 51, 0.09);
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: "Segoe UI", "DejaVu Sans", sans-serif;
  color: var(--text);
  background:
    radial-gradient(circle at top left, rgba(33, 78, 122, 0.10), transparent 34%),
    radial-gradient(circle at top right, rgba(47, 125, 74, 0.10), transparent 30%),
    linear-gradient(135deg, #efe7d8 0%, #f8f5ee 48%, #e6efe8 100%);
}
.wrap {
  max-width: 1180px;
  margin: 0 auto;
  padding: 28px;
}
.panel {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 20px;
  box-shadow: var(--shadow);
}
.hero {
  padding: 28px;
  margin-bottom: 20px;
}
.hero h1 {
  margin: 0 0 10px;
  font-size: 34px;
}
.hero p {
  margin: 6px 0;
  color: var(--muted);
}
.metrics {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 14px;
  margin-top: 22px;
}
.metric {
  padding: 16px;
  background: var(--panel-strong);
  border-radius: 16px;
  border: 1px solid #e4dccf;
}
.metric .label {
  font-size: 12px;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: var(--muted);
}
.metric .value {
  margin-top: 8px;
  font-size: 28px;
  font-weight: 700;
}
.status-pass, .badge-pass { color: var(--pass); }
.status-warn, .badge-warn { color: var(--warn); }
.status-fail, .badge-fail { color: var(--fail); }
.section {
  padding: 22px;
  margin-bottom: 18px;
}
.section h2 {
  margin: 0 0 14px;
  font-size: 22px;
}
.section h3 {
  margin: 0 0 12px;
  font-size: 18px;
}
.info-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 16px;
}
.kv-list {
  display: grid;
  gap: 10px;
}
.kv {
  padding: 12px 14px;
  border-radius: 14px;
  border: 1px solid #e6ddcf;
  background: var(--panel-strong);
}
.kv strong {
  display: block;
  margin-bottom: 4px;
}
.findings-group {
  margin-top: 18px;
}
.findings-group + .findings-group {
  margin-top: 22px;
}
.finding {
  padding: 18px;
  border-radius: 18px;
  border: 1px solid var(--border);
  background: var(--panel-strong);
  margin-bottom: 14px;
}
.finding.pass { background: var(--pass-bg); }
.finding.warn { background: var(--warn-bg); }
.finding.fail { background: var(--fail-bg); }
.finding-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 12px;
  margin-bottom: 10px;
}
.finding-header h4 {
  margin: 0;
  font-size: 19px;
}
.badges {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
.badge {
  display: inline-flex;
  padding: 6px 10px;
  border-radius: 999px;
  font-size: 12px;
  font-weight: 700;
  letter-spacing: 0.03em;
  background: rgba(255,255,255,0.72);
  border: 1px solid rgba(31,41,51,0.10);
}
.finding p {
  margin: 8px 0;
}
.finding ul {
  margin: 8px 0 0;
  padding-left: 18px;
}
.finding li {
  margin-bottom: 6px;
}
.proposal {
  padding: 18px;
  border-radius: 18px;
  border: 1px solid #dfd6c7;
  background: var(--panel-strong);
  margin-bottom: 14px;
}
.proposal-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 12px;
}
.proposal-header h4 {
  margin: 0;
  font-size: 18px;
}
.snippet {
  margin-top: 10px;
  padding: 12px;
  border-radius: 14px;
  background: #f2efe8;
  border: 1px solid #ded6c8;
  white-space: pre-wrap;
  overflow-wrap: anywhere;
  font-family: Consolas, "Courier New", monospace;
  font-size: 13px;
}
.empty {
  padding: 14px 16px;
  border-radius: 14px;
  background: var(--panel-strong);
  border: 1px dashed #d9cfbf;
  color: var(--muted);
}
</style>
</head>
<body>
<div class="wrap">
  <section class="panel hero">
    <h1>Анализ защищенности конфигурации СУБД</h1>
    <p>Цель анализа: {{ .Target }}</p>
    <p>Профиль контроля: {{ .ClassLabel }}</p>
    <p>Время формирования: {{ .GeneratedAt }}</p>
    {{ if .HasConnection }}<p>Live-БД: {{ .Connection }}</p>{{ end }}
    <div class="metrics">
      {{ range .Metrics }}
      <div class="metric">
        <div class="label">{{ .Label }}</div>
        <div class="value {{ .Class }}">{{ .Value }}</div>
      </div>
      {{ end }}
    </div>
  </section>

  <section class="panel section">
    <h2>Источники и контекст</h2>
    <div class="info-grid">
      <div>
        <h3>Источники данных</h3>
        {{ if .Sources }}
        <div class="kv-list">
          {{ range .Sources }}
          <div class="kv">
            <strong>{{ .Label }}</strong>
            <span>{{ .Value }}</span>
          </div>
          {{ end }}
        </div>
        {{ else }}
        <div class="empty">Источники файлов не были переданы.</div>
        {{ end }}
      </div>
      <div>
        <h3>Предупреждения и заметки</h3>
        {{ if .CollectionWarnings }}
        <div class="kv-list">
          {{ range .CollectionWarnings }}
          <div class="kv"><span>{{ . }}</span></div>
          {{ end }}
        </div>
        {{ else if .AnalysisNotes }}
        <div class="kv-list">
          {{ range .AnalysisNotes }}
          <div class="kv"><span>{{ . }}</span></div>
          {{ end }}
        </div>
        {{ else }}
        <div class="empty">Дополнительных предупреждений и заметок нет.</div>
        {{ end }}
      </div>
    </div>
  </section>

  <section class="panel section">
    <h2>Статус по проверкам</h2>

    <div class="findings-group">
      <h3 class="status-fail">Красные несоответствия</h3>
      {{ if .Failed }}
        {{ range .Failed }}
        <article class="finding fail">
          <div class="finding-header">
            <h4>{{ .Title }}</h4>
            <div class="badges">
              <span class="badge badge-fail">{{ .StatusLabel }}</span>
              <span class="badge badge-fail">{{ .SeverityLabel }}</span>
              <span class="badge">{{ .ID }}</span>
            </div>
          </div>
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
        </article>
        {{ end }}
      {{ else }}
      <div class="empty">Критичных несоответствий не выявлено.</div>
      {{ end }}
    </div>

    <div class="findings-group">
      <h3 class="status-warn">Желтые предупреждения</h3>
      {{ if .Warnings }}
        {{ range .Warnings }}
        <article class="finding warn">
          <div class="finding-header">
            <h4>{{ .Title }}</h4>
            <div class="badges">
              <span class="badge badge-warn">{{ .StatusLabel }}</span>
              <span class="badge badge-warn">{{ .SeverityLabel }}</span>
              <span class="badge">{{ .ID }}</span>
            </div>
          </div>
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
        </article>
        {{ end }}
      {{ else }}
      <div class="empty">Предупреждений нет.</div>
      {{ end }}
    </div>

    <div class="findings-group">
      <h3 class="status-pass">Зеленые совпадения</h3>
      {{ if .Passed }}
        {{ range .Passed }}
        <article class="finding pass">
          <div class="finding-header">
            <h4>{{ .Title }}</h4>
            <div class="badges">
              <span class="badge badge-pass">{{ .StatusLabel }}</span>
              <span class="badge">{{ .SeverityLabel }}</span>
              <span class="badge">{{ .ID }}</span>
            </div>
          </div>
          <p><strong>Категория:</strong> {{ .Category }}</p>
          <p><strong>Требование:</strong> {{ .Requirement }}</p>
          {{ if .Evidence }}
          <ul>
            {{ range .Evidence }}
            <li>{{ . }}</li>
            {{ end }}
          </ul>
          {{ end }}
        </article>
        {{ end }}
      {{ else }}
      <div class="empty">Зеленые совпадения не были зафиксированы.</div>
      {{ end }}
    </div>
  </section>

  <section class="panel section">
    <h2>План усиления по рекомендациям ФСТЭК</h2>
    <p>Автоприменимых безопасных изменений: <strong>{{ .AutoCount }}</strong></p>
    {{ if .Proposals }}
      {{ range .Proposals }}
      <article class="proposal">
        <div class="proposal-header">
          <h4>{{ .Title }}</h4>
          <div class="badges">
            <span class="badge">{{ .Priority }}</span>
            <span class="badge">{{ .ApplyMode }}</span>
            {{ if .AutoApply }}<span class="badge badge-pass">авто</span>{{ else }}<span class="badge">вручную</span>{{ end }}
          </div>
        </div>
        {{ if .Target }}<p><strong>Цель изменения:</strong> {{ .Target }}</p>{{ end }}
        {{ if .ControlRefs }}<p><strong>ФСТЭК:</strong> {{ range $idx, $ref := .ControlRefs }}{{ if $idx }}, {{ end }}{{ $ref }}{{ end }}</p>{{ end }}
        <p><strong>Основание:</strong> {{ .FindingName }} ({{ .FindingID }})</p>
        <p><strong>Почему:</strong> {{ .Rationale }}</p>
        {{ if .Steps }}
        <ul>
          {{ range .Steps }}
          <li>{{ . }}</li>
          {{ end }}
        </ul>
        {{ end }}
        {{ if .Snippet }}
        <div class="snippet">{{ .Snippet }}</div>
        {{ end }}
      </article>
      {{ end }}
    {{ else }}
    <div class="empty">Дополнительных шагов усиления не требуется.</div>
    {{ end }}
  </section>
</div>
</body>
</html>`

	tpl, err := template.New("report").Parse(page)
	if err != nil {
		return nil, err
	}

	var buffer bytes.Buffer
	if err := tpl.Execute(&buffer, view); err != nil {
		return nil, err
	}

	return buffer.Bytes(), nil
}

func buildHTMLView(input Input) htmlReportView {
	view := htmlReportView{
		Target:      input.Analysis.Target,
		ClassLabel:  input.Analysis.Class.Label(),
		GeneratedAt: input.Analysis.GeneratedAt.Format("2006-01-02 15:04:05"),
		Score:       input.Analysis.Score,
		AutoCount:   len(input.AutoApplicable),
		Metrics: []htmlMetric{
			{Label: "Итоговый балл", Value: fmt.Sprintf("%d/100", input.Analysis.Score), Class: ""},
			{Label: "Успешно", Value: fmt.Sprintf("%d", input.Analysis.Summary.Passed), Class: "status-pass"},
			{Label: "Предупреждения", Value: fmt.Sprintf("%d", input.Analysis.Summary.Warnings), Class: "status-warn"},
			{Label: "Несоответствия", Value: fmt.Sprintf("%d", input.Analysis.Summary.Failed), Class: "status-fail"},
			{Label: "Рекомендации", Value: fmt.Sprintf("%d", len(input.Proposals)), Class: ""},
			{Label: "Автоизменения", Value: fmt.Sprintf("%d", len(input.AutoApplicable)), Class: "status-pass"},
		},
	}

	if input.Snapshot != nil {
		view.CollectionWarnings = append(view.CollectionWarnings, input.Snapshot.CollectionWarnings...)
		view.AnalysisNotes = append(view.AnalysisNotes, input.Analysis.Notes...)
		view.AnalysisNotes = append(view.AnalysisNotes, input.Snapshot.Notes...)
		if input.Snapshot.Connection != nil {
			view.HasConnection = true
			view.Connection = fmt.Sprintf("%s:%d/%s (%s)", strings.TrimSpace(input.Snapshot.Connection.Host), input.Snapshot.Connection.Port, strings.TrimSpace(input.Snapshot.Connection.Database), strings.TrimSpace(input.Snapshot.Connection.User))
		}
		view.Sources = buildSourceList(input.Snapshot)
	} else {
		view.AnalysisNotes = append(view.AnalysisNotes, input.Analysis.Notes...)
	}

	for _, finding := range input.Analysis.Findings {
		item := htmlFinding{
			ID:             finding.ID,
			Title:          finding.Title,
			Category:       finding.Category,
			Status:         string(finding.Status),
			StatusClass:    string(finding.Status),
			StatusLabel:    statusLabel(finding.Status),
			Severity:       string(finding.Severity),
			SeverityLabel:  severityLabel(finding.Severity),
			Requirement:    finding.Requirement,
			Risk:           finding.Risk,
			Recommendation: finding.Recommendation,
			Evidence:       append([]string{}, finding.Evidence...),
		}
		view.Findings = append(view.Findings, item)
		switch finding.Status {
		case model.StatusPass:
			view.Passed = append(view.Passed, item)
		case model.StatusWarn:
			view.Warnings = append(view.Warnings, item)
		case model.StatusFail:
			view.Failed = append(view.Failed, item)
		}
	}

	for _, proposal := range input.Proposals {
		view.Proposals = append(view.Proposals, htmlProposal{
			Title:       proposal.Title,
			Priority:    proposal.Priority,
			ApplyMode:   proposal.ApplyMode,
			Target:      proposal.Target,
			ControlRefs: append([]string{}, proposal.ControlRefs...),
			Rationale:   proposal.Rationale,
			FindingID:   proposal.FindingID,
			FindingName: proposal.FindingName,
			AutoApply:   proposal.AutoApply,
			Steps:       append([]string{}, proposal.Steps...),
			Snippet:     proposal.Snippet,
		})
	}

	return view
}

func buildSourceList(snapshot *model.ConfigSnapshot) []htmlKV {
	if snapshot == nil {
		return nil
	}

	var out []htmlKV
	appendIf := func(label, value string) {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, htmlKV{Label: label, Value: value})
		}
	}

	appendIf("postgresql.conf", snapshot.Sources.PostgreSQLConf)
	appendIf("pg_hba.conf", snapshot.Sources.HBAConf)
	appendIf("pg_ident.conf", snapshot.Sources.IdentConf)
	appendIf("metadata JSON", snapshot.Sources.MetadataJSON)
	return out
}

func statusLabel(status model.FindingStatus) string {
	switch status {
	case model.StatusPass:
		return "совпало"
	case model.StatusWarn:
		return "предупреждение"
	case model.StatusFail:
		return "несоответствие"
	default:
		return string(status)
	}
}

func severityLabel(severity model.Severity) string {
	switch severity {
	case model.SeverityCritical:
		return "критический"
	case model.SeverityHigh:
		return "высокий"
	case model.SeverityMedium:
		return "средний"
	default:
		return "низкий"
	}
}
