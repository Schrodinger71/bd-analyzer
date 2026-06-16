package ui

import (
	"bd-scan/internal/remediation"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"

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

func GuiInit() {
	a := app.New()
	a.Settings().SetTheme(theme.DarkTheme())

	window := a.NewWindow("BD Scan - Анализ защищенности СУБД")
	window.Resize(fyne.NewSize(920, 560))
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
	liveCollectCheck := widget.NewCheck("Дополнительно собрать данные из живой PostgreSQL", nil)
	hostEntry := widget.NewEntry()
	hostEntry.SetText("localhost")
	portEntry := widget.NewEntry()
	portEntry.SetText("5432")
	dbEntry := widget.NewEntry()
	dbEntry.SetText("postgres")
	userEntry := widget.NewEntry()
	passwordEntry := widget.NewPasswordEntry()
	sslModeSelect := widget.NewSelect([]string{"prefer", "disable", "require", "verify-ca", "verify-full"}, nil)
	sslModeSelect.SetSelected("prefer")

	confEntry := widget.NewEntry()
	hbaEntry := widget.NewEntry()
	identEntry := widget.NewEntry()
	metaEntry := widget.NewEntry()

	collectionPreview := newReadOnlyPreview("Здесь появится результат сбора конфигурации из живой PostgreSQL и доступных файлов.")
	analysisLog := newReadOnlyPreview("Журнал анализа пока пуст.")
	reportPreview := newReadOnlyPreview("После анализа здесь появится текстовый отчет.")
	statusLabel := widget.NewLabel("Ожидание запуска.")
	progress := widget.NewProgressBarInfinite()
	progress.Hide()
	var busy atomic.Bool

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

	parsePort := func() int {
		value, err := strconv.Atoi(strings.TrimSpace(portEntry.Text))
		if err != nil || value <= 0 {
			return 5432
		}
		return value
	}

	buildRequest := func() collector.Request {
		request := collector.Request{
			PostgreSQLConf: sanitizeOptionalPath(confEntry.Text),
			HBAConf:        sanitizeOptionalPath(hbaEntry.Text),
			IdentConf:      sanitizeOptionalPath(identEntry.Text),
			MetadataJSON:   sanitizeOptionalPath(metaEntry.Text),
			Target:         strings.TrimSpace(targetEntry.Text),
		}

		if liveCollectCheck.Checked {
			request.Host = strings.TrimSpace(hostEntry.Text)
			request.Port = parsePort()
			request.Database = strings.TrimSpace(dbEntry.Text)
			request.User = strings.TrimSpace(userEntry.Text)
			request.Password = passwordEntry.Text
			request.SSLMode = strings.TrimSpace(sslModeSelect.Selected)
			if request.Target == "" {
				request.Target = request.Database
			}
		}

		return request
	}

	showCollection := func(snapshot model.ConfigSnapshot, normalized model.NormalizedConfig) {
		collectionPreview.SetText(compactUIText(buildCollectionSummary(snapshot, normalized), 120, 140))
	}

	updateConnectionState := func(enabled bool) {
		if enabled {
			hostEntry.Enable()
			portEntry.Enable()
			dbEntry.Enable()
			userEntry.Enable()
			passwordEntry.Enable()
			sslModeSelect.Enable()
			return
		}
		hostEntry.Disable()
		portEntry.Disable()
		dbEntry.Disable()
		userEntry.Disable()
		passwordEntry.Disable()
		sslModeSelect.Disable()
	}
	liveCollectCheck.OnChanged = updateConnectionState
	updateConnectionState(false)

	hardeningPreview := newReadOnlyPreview("После анализа здесь появится план усиления.")
	autoApplyPreview := newReadOnlyPreview("Безопасные автоизменения станут доступны после анализа live-БД.")
	var hardeningPlanText string

	var btnConfig, btnAnalyze, btnReport, btnHarden, btnAbout *widget.Button
	var collectButton, analyzeButton, exportButton, hardenButton, saveHardeningButton, applyHardeningButton *widget.Button

	setBusy := func(active bool, message string) {
		busy.Store(active)
		statusLabel.SetText(message)
		if active {
			progress.Show()
			progress.Start()
		} else {
			progress.Stop()
			progress.Hide()
		}
		for _, button := range []*widget.Button{collectButton, analyzeButton, exportButton, hardenButton, saveHardeningButton, applyHardeningButton} {
			if button == nil {
				continue
			}
			if active {
				button.Disable()
			} else {
				button.Enable()
			}
		}
	}

	collectAction := func() {
		if busy.Load() {
			return
		}
		request := buildRequest()
		setBusy(true, "Выполняется сбор конфигурации...")
		collectionPreview.SetText("Выполняется сбор конфигурации. Пожалуйста, подождите...")
		analysisLog.SetText("Сбор конфигурации запущен.")

		snapshot, err := collector.CollectWithTimeout(request, collector.DefaultLiveCollectionTimeout)
		if err != nil {
			collectionPreview.SetText(compactUIText("Ошибка сбора конфигурации:\n"+err.Error(), 40, 140))
			analysisLog.SetText(compactUIText("Сбор конфигурации завершился ошибкой.\n"+err.Error(), 40, 140))
			setBusy(false, "Сбор конфигурации завершился ошибкой.")
			return
		}

		normalized := normalize.Build(snapshot)
		completionMessage := fmt.Sprintf("Сбор завершен: параметров %d, HBA-правил %d, ролей %d.", len(snapshot.Parameters), len(snapshot.HBARules), len(snapshot.Roles))
		showCollection(snapshot, normalized)
		analysisLog.SetText(compactUIText(completionMessage, 20, 140))
		setBusy(false, completionMessage)
	}

	// Легковесная функция — не генерирует полный план, только сохраняет ссылку
	buildHardeningPlan := func() string {
		if state.lastRun == nil {
			return ""
		}
		return remediation.RenderText(state.lastRun.Analysis, state.lastRun.Snapshot)
	}

	refreshHardeningPlan := func() {
		if state.lastRun == nil {
			hardeningPreview.SetText("Сначала выполните анализ защищенности.")
			autoApplyPreview.SetText("Безопасные автоизменения станут доступны после анализа live-БД.")
			return
		}
		// Только базовая информация, без тяжёлых вычислений
		proposals := remediation.Build(state.lastRun.Analysis, state.lastRun.Snapshot)
		_ = proposals
		autoApplicable := remediation.AutoApplicable(state.lastRun.Analysis, state.lastRun.Snapshot)
		hardeningPlanText = ""
		hardeningPreview.SetText(fmt.Sprintf(
			"Профиль: %s | Балл: %d/100 | Предупреждений: %d | Несоответствий: %d\n\nПлан усиления сформирован. Нажмите \"Сохранить план усиления\" для экспорта.",
			state.lastRun.Analysis.Class.Label(),
			state.lastRun.Analysis.Score,
			state.lastRun.Analysis.Summary.Warnings,
			state.lastRun.Analysis.Summary.Failed,
		))
		autoApplyPreview.SetText(fmt.Sprintf(
			"Безопасных автоизменений: %d\nНажмите \"Применить безопасные изменения\" для запуска.",
			len(autoApplicable),
		))
	}

	applyAnalysisResult := func(request collector.Request, result service.RunResult) string {
		state.lastRun = &result

		// Обновляем сводку сбора
		showCollection(result.Snapshot, result.Normalized)

		// Легковесный вывод в журнал анализа
		summaryText := fmt.Sprintf(
			"АНАЛИЗ ЗАВЕРШЕН\nПрофиль: %s\nБалл: %d/100\nУспешно: %d | Предупреждений: %d | Несоответствий: %d",
			result.Analysis.Class.Label(),
			result.Analysis.Score,
			result.Analysis.Summary.Passed,
			result.Analysis.Summary.Warnings,
			result.Analysis.Summary.Failed,
		)
		analysisLog.SetText(compactUIText(summaryText, 80, 140))

		// Заглушка для превью отчёта
		reportPreview.SetText(fmt.Sprintf(
			"Анализ завершен (балл: %d/100).\n\nПредпросмотр отключен для производительности.\nПерейдите к сохранению отчета — будет сформирован полный документ.",
			result.Analysis.Score,
		))

		// Базовая информация об усилении
		hardeningPlanText = ""
		hardeningPreview.SetText("План усиления доступен. Нажмите \"Обновить план усиления\" на вкладке Усиление.")
		autoApplyPreview.SetText("Автоусиление доступно после анализа live-БД.")

		completionMessage := fmt.Sprintf("Анализ завершен: балл %d/100, предупреждений %d, несоответствий %d.",
			result.Analysis.Score, result.Analysis.Summary.Warnings, result.Analysis.Summary.Failed)
		return completionMessage
	}

	runAnalysis := func() {
		if busy.Load() {
			return
		}
		request := buildRequest()
		class := state.class
		setBusy(true, "Выполняется анализ защищенности...")
		analysisLog.SetText("Выполняется анализ защищенности. Пожалуйста, подождите...")
		reportPreview.SetText("Подготавливается отчет по результатам анализа...")

		result, err := state.runner.Run(service.RunRequest{
			CollectRequest: request,
			Class:          class,
		})
		if err != nil {
			analysisLog.SetText(compactUIText("Ошибка анализа защищенности:\n"+err.Error(), 40, 140))
			reportPreview.SetText(compactUIText("Отчет не сформирован из-за ошибки анализа.\n\n"+err.Error(), 40, 140))
			setBusy(false, "Анализ защищенности завершился ошибкой.")
			return
		}

		completionMessage := applyAnalysisResult(request, result)
		setBusy(false, completionMessage)
	}

	applySafeHardening := func() {
		if busy.Load() {
			return
		}
		if state.lastRun == nil {
			dialog.ShowInformation("Усиление", "Сначала запустите анализ защищенности.", window)
			return
		}
		if state.lastRun.Snapshot.Connection == nil {
			dialog.ShowInformation("Усиление", "Автоприменение доступно только после анализа живой PostgreSQL.", window)
			return
		}

		request := buildRequest()
		if !request.UsesLiveConnection() {
			dialog.ShowInformation("Усиление", "Для автоприменения оставьте заполненным live-подключение к PostgreSQL.", window)
			return
		}
		if !matchesLiveTarget(request, *state.lastRun.Snapshot.Connection) {
			dialog.ShowInformation("Усиление", fmt.Sprintf("Параметры подключения изменились. Автоприменение разрешено только для той же БД, что была проанализирована: %s.", formatConnection(*state.lastRun.Snapshot.Connection)), window)
			return
		}

		autoApplicable := remediation.AutoApplicable(state.lastRun.Analysis, state.lastRun.Snapshot)
		summary := remediation.RenderAutoApplySummary(state.lastRun.Analysis, state.lastRun.Snapshot)

		if len(autoApplicable) == 0 {
			dialog.ShowInformation("Усиление", summary, window)
			return
		}

		dialog.ShowConfirm("Подтвердите автоприменение", summary, func(confirm bool) {
			if !confirm {
				return
			}

			setBusy(true, "Применяются безопасные изменения к живой PostgreSQL...")
			autoApplyPreview.SetText("Выполняется автоприменение...")

			previousAnalysis := state.lastRun.Analysis
			func() {
				applyResult, err := remediation.ApplySafeWithProgress(request, previousAnalysis, state.lastRun.Snapshot, func(update remediation.ProgressUpdate) {
					statusText := fmt.Sprintf("Автоусиление: шаг %d из %d. %s", update.Current, update.Total, update.Message)
					statusLabel.SetText(statusText)
					autoApplyPreview.SetText(statusText)
				})
				if err != nil {
					autoApplyPreview.SetText("Ошибка автоприменения: " + err.Error())
					setBusy(false, "Автоприменение завершилось ошибкой.")
					dialog.ShowError(err, window)
					return
				}

				// Проверяем были ли изменения
				changesApplied := false
				for _, change := range applyResult.Changes {
					if change.Applied {
						changesApplied = true
						break
					}
				}

				if !changesApplied {
					autoApplyPreview.SetText("Безопасные автоизменения не потребовались.")
					setBusy(false, "Безопасные автоизменения не потребовались.")
					dialog.ShowInformation("Усиление", applyResult.Summary(), window)
					return
				}

				// Повторный анализ
				statusLabel.SetText("Автоизменения применены. Запускается повторная проверка...")
				autoApplyPreview.SetText("Выполняется повторный анализ...")

				result, rerunErr := state.runner.Run(service.RunRequest{
					CollectRequest: request,
					Class:          state.class,
				})
				if rerunErr != nil {
					autoApplyPreview.SetText("Автоприменение выполнено, но повторный анализ завершился ошибкой.")
					setBusy(false, "Автоприменение завершено, но повторный анализ завершился ошибкой.")
					dialog.ShowInformation("Усиление", applyResult.Summary()+"\n\nПовторный анализ не удался: "+rerunErr.Error(), window)
					return
				}

				// Обновляем состояние
				state.lastRun = &result
				verificationSummary := fmt.Sprintf(
					"ПРОВЕРКА РЕЗУЛЬТАТА\nБаллы: %d -> %d/100\nПредупреждений: %d -> %d\nНесоответствий: %d -> %d",
					previousAnalysis.Score, result.Analysis.Score,
					previousAnalysis.Summary.Warnings, result.Analysis.Summary.Warnings,
					previousAnalysis.Summary.Failed, result.Analysis.Summary.Failed,
				)
				autoApplyPreview.SetText(applyResult.Summary() + "\n\n" + verificationSummary)
				setBusy(false, "Автоприменение завершено.")
				dialog.ShowInformation("Усиление", applyResult.Summary()+"\n\n"+verificationSummary, window)
			}()
		}, window)
	}

	exportReport := func() {
		if state.lastRun == nil {
			dialog.ShowInformation("Отчетность", "Сначала запустите анализ защищенности.", window)
			return
		}

		format, err := report.ParseFormat(strings.ToLower(strings.TrimSpace(formatSelect.Selected)))
		if err != nil {
			dialog.ShowError(err, window)
			return
		}

		data, err := state.runner.ExportRun(*state.lastRun, format)
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
			if _, writeErr := writer.Write(data); writeErr != nil {
				dialog.ShowError(writeErr, window)
				return
			}
			path := ""
			if writer.URI() != nil {
				path = pathFromURI(writer.URI())
			}
			if closeErr := writer.Close(); closeErr != nil {
				dialog.ShowError(closeErr, window)
				return
			}
			dialog.ShowInformation("Отчетность", fmt.Sprintf("Отчет сохранен: %s", path), window)
		}, window)
		saveDialog.SetFilter(storage.NewExtensionFileFilter([]string{"." + format.Extension()}))
		saveDialog.Show()
	}

	exportHardeningPlan := func() {
		if strings.TrimSpace(hardeningPlanText) == "" {
			// Генерируем при необходимости
			hardeningPlanText = buildHardeningPlan()
		}
		if strings.TrimSpace(hardeningPlanText) == "" {
			dialog.ShowInformation("Усиление", "Сначала нажмите \"Обновить план усиления\", затем сохраните результат.", window)
			return
		}
		if state.lastRun == nil {
			dialog.ShowInformation("Усиление", "Сначала запустите анализ защищенности.", window)
			return
		}

		data := []byte(hardeningPlanText)
		saveDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, saveErr error) {
			if saveErr != nil {
				dialog.ShowError(saveErr, window)
				return
			}
			if writer == nil {
				return
			}
			if _, writeErr := writer.Write(data); writeErr != nil {
				dialog.ShowError(writeErr, window)
				return
			}
			path := ""
			if writer.URI() != nil {
				path = pathFromURI(writer.URI())
			}
			if closeErr := writer.Close(); closeErr != nil {
				dialog.ShowError(closeErr, window)
				return
			}
			dialog.ShowInformation("Усиление", fmt.Sprintf("План усиления сохранен: %s", path), window)
		}, window)
		saveDialog.SetFilter(storage.NewExtensionFileFilter([]string{".txt"}))
		saveDialog.Show()
	}

	rightScroller := container.NewVScroll(widget.NewLabel(""))

	highlightSelected := func(index int) {
		btnConfig.Importance = widget.MediumImportance
		btnAnalyze.Importance = widget.MediumImportance
		btnReport.Importance = widget.MediumImportance
		btnHarden.Importance = widget.MediumImportance
		btnAbout.Importance = widget.MediumImportance

		switch index {
		case 0:
			btnConfig.Importance = widget.HighImportance
		case 1:
			btnAnalyze.Importance = widget.HighImportance
		case 2:
			btnReport.Importance = widget.HighImportance
		case 3:
			btnHarden.Importance = widget.HighImportance
		case 4:
			btnAbout.Importance = widget.HighImportance
		}

		btnConfig.Refresh()
		btnAnalyze.Refresh()
		btnReport.Refresh()
		btnHarden.Refresh()
		btnAbout.Refresh()
	}

	var setContent func(index int)
	setContent = func(index int) {
		switch index {
		case 0:
			collectButton = widget.NewButtonWithIcon("Начать сбор конфигурации", theme.ViewRefreshIcon(), collectAction)
			box := container.NewVBox(
				widget.NewLabelWithStyle("Модуль сбора конфигурации", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
				widget.NewSeparator(),
				wrappedLabel("Можно анализировать только локальные конфигурационные файлы или дополнительно дочитать сведения из живой PostgreSQL."),
				compactField("Цель анализа", targetEntry),
				liveCollectCheck,
				widget.NewLabelWithStyle("Подключение", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
				compactField("Хост", hostEntry),
				compactField("Порт", portEntry),
				compactField("База данных", dbEntry),
				compactField("Пользователь", userEntry),
				compactField("Пароль", passwordEntry),
				compactField("SSL mode", sslModeSelect),
				widget.NewLabelWithStyle("Дополнительные источники", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
				compactField("postgresql.conf", newPathPicker(window, confEntry, []string{".conf"})),
				compactField("pg_hba.conf", newPathPicker(window, hbaEntry, []string{".conf"})),
				compactField("pg_ident.conf", newPathPicker(window, identEntry, []string{".conf"})),
				compactField("metadata JSON", newPathPicker(window, metaEntry, []string{".json"})),
				collectButton,
				collectionPreview,
			)
			rightScroller.Content = container.NewPadded(box)

		case 1:
			analyzeButton = widget.NewButtonWithIcon("Запустить анализ защищенности", theme.MediaPlayIcon(), runAnalysis)
			box := container.NewVBox(
				widget.NewLabelWithStyle("Модуль анализа защищенности", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
				widget.NewSeparator(),
				wrappedLabel("Выберите профиль контроля и запустите анализ собранной конфигурации."),
				classSelect,
				analyzeButton,
				widget.NewLabel("Журнал выполнения:"),
				analysisLog,
			)
			rightScroller.Content = container.NewPadded(box)

		case 2:
			exportButton = widget.NewButtonWithIcon("Сохранить отчет", theme.DocumentSaveIcon(), exportReport)
			if state.lastRun != nil {
				reportPreview.SetText(fmt.Sprintf(
					"Последний анализ: %s | Балл: %d/100 | Несоответствий: %d\n\nПредпросмотр отключен. Нажмите \"Сохранить отчет\" для экспорта полного документа.",
					state.lastRun.Analysis.Class.Label(),
					state.lastRun.Analysis.Score,
					state.lastRun.Analysis.Summary.Failed,
				))
			}
			box := container.NewVBox(
				widget.NewLabelWithStyle("Модуль формирования отчетности", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
				widget.NewSeparator(),
				wrappedLabel("Сформируйте и сохраните отчет по результатам последнего анализа."),
				formatSelect,
				exportButton,
				widget.NewSeparator(),
				widget.NewLabel("Информация:"),
				reportPreview,
			)
			rightScroller.Content = container.NewPadded(box)

		case 3:
			hardenButton = widget.NewButtonWithIcon("Обновить план усиления", theme.ViewRefreshIcon(), refreshHardeningPlan)
			applyHardeningButton = widget.NewButtonWithIcon("Применить безопасные изменения", theme.MediaPlayIcon(), applySafeHardening)
			saveHardeningButton = widget.NewButtonWithIcon("Сохранить план усиления", theme.DocumentSaveIcon(), exportHardeningPlan)
			box := container.NewVBox(
				widget.NewLabelWithStyle("Модуль усиления защищенности", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
				widget.NewSeparator(),
				wrappedLabel("Здесь формируется безопасный план изменений для живой PostgreSQL."),
				hardenButton,
				applyHardeningButton,
				saveHardeningButton,
				widget.NewSeparator(),
				widget.NewLabel("Безопасные автоизменения:"),
				autoApplyPreview,
				widget.NewSeparator(),
				widget.NewLabel("План изменений:"),
				hardeningPreview,
			)
			rightScroller.Content = container.NewPadded(box)

		case 4:
			infoText := widget.NewLabelWithStyle(
				"BD Scan v1.0\n\n"+
					"Программное средство контроля защищенности конфигураций СУБД PostgreSQL.\n\n"+
					"Поддерживаются два источника данных:\n"+
					"1. Подключение к существующей PostgreSQL по host/port/login/password.\n"+
					"2. Дополнительные локальные конфигурационные файлы и metadata JSON.",
				fyne.TextAlignCenter,
				fyne.TextStyle{},
			)
			infoText.Wrapping = fyne.TextWrapWord
			box := container.NewVBox(
				widget.NewLabelWithStyle("О приложении", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
				widget.NewSeparator(),
				infoText,
			)
			rightScroller.Content = container.NewPadded(box)
		}

		rightScroller.Refresh()
		highlightSelected(index)
	}

	btnConfig = widget.NewButtonWithIcon("Сбор", theme.ComputerIcon(), func() { setContent(0) })
	btnAnalyze = widget.NewButtonWithIcon("Анализ", theme.SearchIcon(), func() { setContent(1) })
	btnReport = widget.NewButtonWithIcon("Отчет", theme.DocumentIcon(), func() { setContent(2) })
	btnHarden = widget.NewButtonWithIcon("Усиление", theme.SettingsIcon(), func() { setContent(3) })
	btnAbout = widget.NewButtonWithIcon("О программе", theme.InfoIcon(), func() { setContent(4) })

	topButtons := widget.NewVBox(btnConfig, btnAnalyze, btnReport, btnHarden)
	leftPanel := container.NewBorder(nil, btnAbout, nil, nil, topButtons)

	footer := container.NewHBox(progress, layout.NewSpacer(), statusLabel, layout.NewSpacer(), widget.NewLabel("BD Scan v1.0"))

	setContent(0)

	content := container.NewBorder(
		nil,
		footer,
		container.NewPadded(leftPanel),
		nil,
		rightScroller,
	)

	window.SetContent(content)
	window.ShowAndRun()
}

func compactField(title string, field fyne.CanvasObject) fyne.CanvasObject {
	return container.NewVBox(widget.NewLabel(title), field)
}

func wrappedLabel(text string) *widget.Label {
	label := widget.NewLabel(text)
	label.Wrapping = fyne.TextWrapWord
	return label
}

func newReadOnlyPreview(text string) *widget.Label {
	label := widget.NewLabel(text)
	label.Wrapping = fyne.TextWrapWord
	return label
}

func compactUIText(text string, maxLines, maxLineLen int) string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	lines := strings.Split(text, "\n")
	if maxLineLen > 0 {
		for i, line := range lines {
			lines[i] = shortenUIString(line, maxLineLen)
		}
	}
	if maxLines > 0 && len(lines) > maxLines {
		hidden := len(lines) - maxLines
		lines = append(lines[:maxLines], fmt.Sprintf("... сокращено строк: %d", hidden))
	}
	return strings.Join(lines, "\n")
}

func hasAppliedChanges(result remediation.ApplyResult) bool {
	for _, change := range result.Changes {
		if change.Applied {
			return true
		}
	}
	return false
}

func matchesLiveTarget(request collector.Request, conn model.ConnectionInfo) bool {
	return strings.EqualFold(strings.TrimSpace(request.Host), strings.TrimSpace(conn.Host)) &&
		request.Port == conn.Port &&
		strings.TrimSpace(request.Database) == strings.TrimSpace(conn.Database) &&
		strings.TrimSpace(request.User) == strings.TrimSpace(conn.User)
}

func formatConnection(conn model.ConnectionInfo) string {
	return fmt.Sprintf("%s:%d/%s (%s)", strings.TrimSpace(conn.Host), conn.Port, strings.TrimSpace(conn.Database), strings.TrimSpace(conn.User))
}

func sanitizeOptionalPath(value string) string {
	return normalizeOptionalPath(value)
}
