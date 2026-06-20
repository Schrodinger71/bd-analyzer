package ui

import (
	"fmt"
	"image/color"
	"strings"

	"bd-scan/internal/model"
	"bd-scan/internal/remediation"

	"fyne.io/fyne"
	"fyne.io/fyne/canvas"
	"fyne.io/fyne/container"
	"fyne.io/fyne/theme"
	"fyne.io/fyne/widget"
)

func statusSymbol(status model.FindingStatus) string {
	switch status {
	case model.StatusPass:
		return "✓"
	case model.StatusWarn:
		return "⚠"
	default:
		return "✗"
	}
}

func statusLabel(status model.FindingStatus) string {
	switch status {
	case model.StatusPass:
		return "Соответствует"
	case model.StatusWarn:
		return "Предупреждение"
	default:
		return "Не соответствует"
	}
}

func statusColor(status model.FindingStatus) color.Color {
	switch status {
	case model.StatusPass:
		return theme.PrimaryColorNamed(theme.ColorGreen)
	case model.StatusWarn:
		return theme.PrimaryColorNamed(theme.ColorOrange)
	default:
		return theme.PrimaryColorNamed(theme.ColorRed)
	}
}

func priorityColor(priority string) color.Color {
	switch strings.ToLower(strings.TrimSpace(priority)) {
	case "критический":
		return theme.PrimaryColorNamed(theme.ColorRed)
	case "высокий":
		return theme.PrimaryColorNamed(theme.ColorOrange)
	case "средний":
		return theme.PrimaryColorNamed(theme.ColorBlue)
	default:
		return theme.PrimaryColorNamed(theme.ColorGray)
	}
}

func scoreColor(score int) color.Color {
	switch {
	case score >= 80:
		return theme.PrimaryColorNamed(theme.ColorGreen)
	case score >= 50:
		return theme.PrimaryColorNamed(theme.ColorOrange)
	default:
		return theme.PrimaryColorNamed(theme.ColorRed)
	}
}

func coloredText(text string, size int, bold bool, col color.Color) *canvas.Text {
	t := canvas.NewText(text, col)
	t.TextSize = size
	t.TextStyle = fyne.TextStyle{Bold: bold}
	return t
}

func statChip(label string, value int, col color.Color) fyne.CanvasObject {
	return container.NewHBox(
		coloredText("●", 16, true, col),
		widget.NewLabel(fmt.Sprintf("%s: %d", label, value)),
	)
}

// buildScoreCard renders a compact, color-coded overview of the analysis score
// and pass/warn/fail counts instead of a flat text block.
func buildScoreCard(score int, summary model.Summary) fyne.CanvasObject {
	scoreText := coloredText(fmt.Sprintf("Балл: %d/100", score), 22, true, scoreColor(score))
	chips := container.NewHBox(
		statChip("Успешно", summary.Passed, theme.PrimaryColorNamed(theme.ColorGreen)),
		statChip("Предупреждения", summary.Warnings, theme.PrimaryColorNamed(theme.ColorOrange)),
		statChip("Несоответствия", summary.Failed, theme.PrimaryColorNamed(theme.ColorRed)),
	)
	return container.NewVBox(scoreText, chips)
}

// buildDashboardChips renders the remediation dashboard counters as colored chips.
func buildDashboardChips(dashboard remediation.Dashboard) fyne.CanvasObject {
	return container.NewHBox(
		statChip("Критично", dashboard.CriticalFindings, theme.PrimaryColorNamed(theme.ColorRed)),
		statChip("Высоко", dashboard.HighFindings, theme.PrimaryColorNamed(theme.ColorOrange)),
		statChip("Авто", dashboard.AutoApplicable, theme.PrimaryColorNamed(theme.ColorGreen)),
		statChip("Вручную", dashboard.ManualActions, theme.PrimaryColorNamed(theme.ColorBlue)),
	)
}

// buildFindingsAccordion renders findings as a collapsible list, failing items first,
// with a colored status symbol so the user can scan results without reading a wall of text.
func buildFindingsAccordion(findings []model.Finding) *widget.Accordion {
	ordered := make([]model.Finding, 0, len(findings))
	var passing []model.Finding
	for _, f := range findings {
		if f.Status == model.StatusPass {
			passing = append(passing, f)
			continue
		}
		ordered = append(ordered, f)
	}
	ordered = append(ordered, passing...)

	accordion := widget.NewAccordion()
	accordion.MultiOpen = true

	for _, finding := range ordered {
		title := fmt.Sprintf("%s  %s — %s", statusSymbol(finding.Status), finding.Title, finding.Category)

		detail := container.NewVBox(coloredText(statusLabel(finding.Status), 14, true, statusColor(finding.Status)))
		if finding.Requirement != "" {
			detail.Add(wrappedLabel("Требование: " + finding.Requirement))
		}
		for _, evidence := range finding.Evidence {
			detail.Add(wrappedLabel("• " + evidence))
		}
		if finding.Status != model.StatusPass && finding.Recommendation != "" {
			detail.Add(wrappedLabel("Рекомендация: " + finding.Recommendation))
		}

		accordion.Append(widget.NewAccordionItem(title, detail))
	}

	return accordion
}

// buildProposalRows renders a short, color-coded list of remediation proposals
// (priority dot + title) instead of a long text dump, capped at limit items.
func buildProposalRows(proposals []remediation.Proposal, limit int, emptyText string) fyne.CanvasObject {
	if len(proposals) == 0 {
		return wrappedLabel(emptyText)
	}

	rows := make([]fyne.CanvasObject, 0, limit+1)
	shown := 0
	for _, proposal := range proposals {
		if limit > 0 && shown >= limit {
			break
		}
		shown++
		rows = append(rows, container.NewHBox(
			coloredText("●", 14, true, priorityColor(proposal.Priority)),
			wrappedLabel(proposal.Title),
		))
	}
	if limit > 0 && len(proposals) > shown {
		rows = append(rows, widget.NewLabel(fmt.Sprintf("... ещё %d", len(proposals)-shown)))
	}
	return container.NewVBox(rows...)
}
