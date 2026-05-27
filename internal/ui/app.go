package ui

import (
	"fmt"
	"strings"

	"bd-scan/internal/collector"
	"bd-scan/internal/model"
	"bd-scan/internal/normalize"
	"bd-scan/internal/report"
	"bd-scan/internal/service"
	"fyne.io/fyne"
	"fyne.io/fyne/app"
	"fyne.io/fyne/container"
	"fyne.io/fyne/dialog"
	"fyne.io/fyne/layout"
	"fyne.io/fyne/storage"
	"fyne.io/fyne/theme"
	"fyne.io/fyne/widget"
)

type guiState struct {
	runner  service.Service
	class   model.ProtectionClass
	lastRun *service.RunResult
}

func modernGuiInit() {
	a := app.New()
	a.Settings().SetTheme(theme.LightTheme())

	window := a.NewWindow("BD Analyzer - Анализ защищенности конфигураций СУБД")
	window.Resize(fyne.NewSize(1080, 720))
	window.SetMaster()
	window.CenterOnScreen()

	icon, err := fyne.LoadResourceFromPath("internal/assets/icon.png")
	if err == nil {
		window.SetIcon(icon)
	}

	state := &guiState{
		runner: service.Service{},
		class:  model.Class6,
	}

	targetEntry := widget.NewEntry()
	targetEntry.SetText("PostgreSQL target")
	confEntry := widget.NewEntry()
	hbaEntry := widget.NewEntry()
	identEntry := widget.NewEntry()
	metaEntry := widget.NewEntry()

	collectionPreview := widget.NewMultiLineEntry()
	collectionPreview.Disable()
	collectionPreview.SetText("После проверки здесь появится сводка по собранной конфигурации.")

	analysisLog := widget.NewMultiLineEntry()
	analysisLog.Disable()
	analysisLog.SetText("Журнал анализа появится после запуска проверки.")

	reportPreview := widget.NewMultiLineEntry()
	reportPreview.Disable()
	reportPreview.SetText("После завершения анализа здесь появится текстовый отчет.")

	statusLabel := widget.NewLabel("Ожидание запуска.")
	progress := widget.NewProgressBarInfinite()
	progress.Hide()

	classOptions := make([]string, 0, len(model.AvailableProtectionClasses()))
	classByLabel := make(map[string]model.ProtectionClass)
	for _, class := range model.AvailableProtectionClasses() {
		label := class.Label()
		classOptions = append(classOptions, label)
		classByLabel[label] = class
	}

	classSelect := widget.NewSelect(classOptions, func(selected string) {
		if class, ok := classByLabel[selected]; ok {
			state.class = class
		}
	})
	classSelect.SetSelected(model.Class6.Label())

	formatSelect := widget.NewSelect([]string{"TXT", "HTML", "JSON", "PDF"}, nil)
	formatSelect.SetSelected("TXT")

	collectRequest := func() collector.Request {
		return collector.Request{
			Target:         strings.TrimSpace(targetEntry.Text),
			PostgreSQLConf: strings.TrimSpace(confEntry.Text),
			HBAConf:        strings.TrimSpace(hbaEntry.Text),
			IdentConf:      strings.TrimSpace(identEntry.Text),
			MetadataJSON:   strings.TrimSpace(metaEntry.Text),
		}
	}

	inspectConfiguration := func() {
		progress.Show()
		progress.Start()
		statusLabel.SetText("Выполняется сбор и нормализация конфигурации...")

		snapshot, err := collector.Collect(collectRequest())
		progress.Stop()
		progress.Hide()
		if err != nil {
			statusLabel.SetText("Сбор конфигурации завершился ошибкой.")
			dialog.ShowError(err, window)
			return
		}

		normalized := normalize.Build(snapshot)
		collectionPreview.SetText(buildCollectionSummary(snapshot, normalized))
		statusLabel.SetText(fmt.Sprintf("Сбор конфигурации выполнен: параметров %d, правил HBA %d, ролей %d.", len(snapshot.Parameters), len(snapshot.HBARules), len(snapshot.Roles)))
	}

	runAnalysis := func() {
		progress.Show()
		progress.Start()
		statusLabel.SetText("Выполняется анализ защищенности...")

		result, err := state.runner.Run(service.RunRequest{
			CollectRequest: collectRequest(),
			Class:          state.class,
		})

		progress.Stop()
		progress.Hide()
		if err != nil {
			statusLabel.SetText("Анализ завершился ошибкой.")
			dialog.ShowError(err, window)
			return
		}

		state.lastRun = &result
		collectionPreview.SetText(buildCollectionSummary(result.Snapshot, result.Normalized))
		analysisLog.SetText(buildAnalysisLog(result.Analysis))
		reportPreview.SetText(state.runner.Preview(result.Analysis))
		statusLabel.SetText(fmt.Sprintf("Анализ завершен: итоговый балл %d/100, предупреждений %d, несоответствий %d.", result.Analysis.Score, result.Analysis.Summary.Warnings, result.Analysis.Summary.Failed))
	}

	exportReport := func() {
		if state.lastRun == nil {
			dialog.ShowInformation("Экспорт отчета", "Сначала запустите анализ конфигурации.", window)
			return
		}

		format, err := report.ParseFormat(strings.ToLower(strings.TrimSpace(formatSelect.Selected)))
		if err != nil {
			dialog.ShowError(err, window)
			return
		}

		data, err := state.runner.Export(state.lastRun.Analysis, format)
		if err != nil {
			dialog.ShowError(err, window)
			return
		}

		saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, saveErr error) {
			if saveErr != nil {
				dialog.ShowError(saveErr, window)
				return
			}
			if writer == nil {
				return
			}
			defer writer.Close()

			if _, writeErr := writer.Write(data); writeErr != nil {
				dialog.ShowError(writeErr, window)
				return
			}

			path := ""
			if writer.URI() != nil {
				path = writer.URI().String()
			}
			dialog.ShowInformation("Экспорт отчета", fmt.Sprintf("Отчет сохранен: %s", path), window)
		}, window)
		saveDialog.SetFilter(storage.NewExtensionFileFilter([]string{"." + format.Extension()}))
		saveDialog.Show()
	}

	collectionTab := container.NewVScroll(container.NewVBox(
		widget.NewLabelWithStyle("Модуль сбора конфигурации", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Укажите пути к конфигурационным файлам PostgreSQL и, при необходимости, к metadata JSON со сведениями о ролях, аудите и резервном копировании."),
		widget.NewForm(
			&widget.FormItem{Text: "Цель анализа", Widget: targetEntry},
			&widget.FormItem{Text: "postgresql.conf", Widget: newPathPicker(window, confEntry, []string{".conf"})},
			&widget.FormItem{Text: "pg_hba.conf", Widget: newPathPicker(window, hbaEntry, []string{".conf"})},
			&widget.FormItem{Text: "pg_ident.conf", Widget: newPathPicker(window, identEntry, []string{".conf"})},
			&widget.FormItem{Text: "metadata JSON", Widget: newPathPicker(window, metaEntry, []string{".json"})},
		),
		widget.NewButtonWithIcon("Проверить сбор данных", theme.ViewRefreshIcon(), inspectConfiguration),
		widget.NewSeparator(),
		widget.NewLabel("Сводка по собранной конфигурации:"),
		collectionPreview,
	))

	analysisTab := container.NewVScroll(container.NewVBox(
		widget.NewLabelWithStyle("Модуль анализа защищенности", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("Выберите контрольный профиль и запустите набор правил по аутентификации, доступу, аудиту, резервированию и контролю целостности."),
		widget.NewForm(
			&widget.FormItem{Text: "Профиль контроля", Widget: classSelect},
		),
		widget.NewButtonWithIcon("Запустить анализ защищенности", theme.MediaPlayIcon(), runAnalysis),
		progress,
		widget.NewSeparator(),
		widget.NewLabel("Журнал выполнения:"),
		analysisLog,
	))

	reportTab := container.NewVScroll(container.NewVBox(
		widget.NewLabelWithStyle("Модуль формирования отчетности", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		widget.NewLabel("После завершения анализа можно экспортировать отчет в текстовый, HTML, JSON или PDF-формат."),
		widget.NewForm(
			&widget.FormItem{Text: "Формат экспорта", Widget: formatSelect},
		),
		widget.NewButtonWithIcon("Сохранить отчет", theme.DocumentSaveIcon(), exportReport),
		widget.NewSeparator(),
		widget.NewLabel("Текстовый предварительный просмотр:"),
		reportPreview,
	))

	aboutText := widget.NewLabel(
		"BD Analyzer реализует архитектуру из статьи о контроле защищенности конфигураций СУБД:\n\n" +
			"1. Сбор конфигурации из postgresql.conf, pg_hba.conf, pg_ident.conf и дополнительного metadata JSON.\n" +
			"2. Нормализация параметров в единую модель конфигурации.\n" +
			"3. Анализ защищенности по формализованным правилам контрольного профиля.\n" +
			"4. Формирование отчетов с перечнем рисков и рекомендаций.\n\n" +
			"Проект ориентирован на PostgreSQL и готов к расширению базы правил под более точные нормативные матрицы.",
	)
	aboutText.Wrapping = fyne.TextWrapWord

	aboutTab := container.NewVScroll(container.NewVBox(
		widget.NewLabelWithStyle("О проекте", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
		aboutText,
	))

	tabs := container.NewAppTabs(
		container.NewTabItem("Сбор", collectionTab),
		container.NewTabItem("Анализ", analysisTab),
		container.NewTabItem("Отчет", reportTab),
		container.NewTabItem("О проекте", aboutTab),
	)

	footer := container.NewHBox(
		statusLabel,
		layout.NewSpacer(),
		widget.NewLabel("BD Analyzer v1.0"),
	)

	window.SetContent(container.NewBorder(nil, footer, nil, nil, tabs))
	window.ShowAndRun()
}

func newPathPicker(window fyne.Window, entry *widget.Entry, extensions []string) fyne.CanvasObject {
	button := widget.NewButton("Обзор...", func() {
		fileDialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, window)
				return
			}
			if reader == nil {
				return
			}
			defer reader.Close()
			entry.SetText(reader.URI().String())
		}, window)
		fileDialog.SetFilter(storage.NewExtensionFileFilter(extensions))
		fileDialog.Show()
	})

	return container.NewBorder(nil, nil, nil, button, entry)
}

func buildCollectionSummary(snapshot model.ConfigSnapshot, normalized model.NormalizedConfig) string {
	var builder strings.Builder

	builder.WriteString("СВОДКА ПО СБОРУ И НОРМАЛИЗАЦИИ КОНФИГУРАЦИИ\n")
	builder.WriteString("=========================================\n")
	builder.WriteString(fmt.Sprintf("Цель анализа: %s\n", snapshot.Target))
	builder.WriteString(fmt.Sprintf("Параметров конфигурации: %d\n", len(snapshot.Parameters)))
	builder.WriteString(fmt.Sprintf("Правил pg_hba.conf: %d\n", len(snapshot.HBARules)))
	builder.WriteString(fmt.Sprintf("Правил pg_ident.conf: %d\n", len(snapshot.IdentMaps)))
	builder.WriteString(fmt.Sprintf("Ролей из metadata JSON: %d\n", len(snapshot.Roles)))
	builder.WriteString(fmt.Sprintf("Выявлено слабых HBA-правил: %d\n", len(normalized.WeakHBARules)))
	builder.WriteString(fmt.Sprintf("Выявлено широких HBA-правил: %d\n", len(normalized.OpenHBARules)))
	builder.WriteString(fmt.Sprintf("Наличие pgAudit: %t\n", normalized.HasPgAudit))

	if snapshot.Sources.PostgreSQLConf != "" {
		builder.WriteString(fmt.Sprintf("Источник postgresql.conf: %s\n", shortenUIString(snapshot.Sources.PostgreSQLConf, 80)))
	}
	if snapshot.Sources.HBAConf != "" {
		builder.WriteString(fmt.Sprintf("Источник pg_hba.conf: %s\n", shortenUIString(snapshot.Sources.HBAConf, 80)))
	}
	if snapshot.Sources.IdentConf != "" {
		builder.WriteString(fmt.Sprintf("Источник pg_ident.conf: %s\n", shortenUIString(snapshot.Sources.IdentConf, 80)))
	}
	if snapshot.Sources.MetadataJSON != "" {
		builder.WriteString(fmt.Sprintf("Источник metadata JSON: %s\n", shortenUIString(snapshot.Sources.MetadataJSON, 80)))
	}

	if len(snapshot.CollectionWarnings) > 0 {
		builder.WriteString("\nПРЕДУПРЕЖДЕНИЯ СБОРА\n")
		builder.WriteString("-------------------\n")
		for _, warning := range snapshot.CollectionWarnings {
			builder.WriteString("- " + shortenUIString(warning, 100) + "\n")
		}
	}

	return builder.String()
}

func buildAnalysisLog(result model.AnalysisResult) string {
	var builder strings.Builder

	builder.WriteString("ЖУРНАЛ АНАЛИЗА\n")
	builder.WriteString("=============\n")
	builder.WriteString(fmt.Sprintf("Профиль контроля: %s\n", result.Class.Label()))
	builder.WriteString(fmt.Sprintf("Итоговый балл: %d/100\n", result.Score))
	builder.WriteString(fmt.Sprintf("Успешно: %d | Предупреждения: %d | Несоответствия: %d\n\n", result.Summary.Passed, result.Summary.Warnings, result.Summary.Failed))

	for _, finding := range result.Findings {
		builder.WriteString(fmt.Sprintf("[%s] %s (%s)\n", strings.ToUpper(string(finding.Status)), finding.Title, finding.Category))
		for _, evidence := range finding.Evidence {
			builder.WriteString("  - " + shortenUIString(evidence, 100) + "\n")
		}
	}

	if len(result.Notes) > 0 {
		builder.WriteString("\nПримечания:\n")
		for _, note := range result.Notes {
			builder.WriteString("  - " + shortenUIString(note, 100) + "\n")
		}
	}

	return builder.String()
}

func shortenUIString(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 3 || len(value) <= limit {
		return value
	}
	return value[:limit-3] + "..."
}
