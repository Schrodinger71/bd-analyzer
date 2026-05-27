package ui

import (
	"fmt"
	"runtime"
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

	collectionPreview := widget.NewMultiLineEntry()
	collectionPreview.Disable()
	collectionPreview.Wrapping = fyne.TextWrapBreak
	collectionPreview.SetText("Здесь появится результат сбора конфигурации из живой PostgreSQL и доступных файлов.")

	analysisLog := widget.NewMultiLineEntry()
	analysisLog.Disable()
	analysisLog.Wrapping = fyne.TextWrapBreak
	analysisLog.SetText("Журнал анализа пока пуст.")

	reportPreview := widget.NewMultiLineEntry()
	reportPreview.Disable()
	reportPreview.Wrapping = fyne.TextWrapBreak
	reportPreview.SetText("После анализа здесь появится текстовый отчет.")

	statusLabel := widget.NewLabel("Ожидание запуска.")
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
		return collector.Request{
			Host:           strings.TrimSpace(hostEntry.Text),
			Port:           parsePort(),
			Database:       strings.TrimSpace(dbEntry.Text),
			User:           strings.TrimSpace(userEntry.Text),
			Password:       passwordEntry.Text,
			SSLMode:        strings.TrimSpace(sslModeSelect.Selected),
			PostgreSQLConf: sanitizeOptionalPath(confEntry.Text),
			HBAConf:        sanitizeOptionalPath(hbaEntry.Text),
			IdentConf:      sanitizeOptionalPath(identEntry.Text),
			MetadataJSON:   sanitizeOptionalPath(metaEntry.Text),
			Target:         strings.TrimSpace(dbEntry.Text),
		}
	}

	showCollection := func(snapshot model.ConfigSnapshot, normalized model.NormalizedConfig) {
		collectionPreview.SetText(buildCollectionSummary(snapshot, normalized))
	}

	var btnConfig, btnAnalyze, btnReport, btnAbout *widget.Button
	setBusy := func(active bool, message string) {
		busy.Store(active)
		statusLabel.SetText(message)
	}

	collectAction := func() {
		if busy.Load() {
			return
		}
		request := buildRequest()
		setBusy(true, "Выполняется сбор конфигурации...")
		collectionPreview.SetText("Выполняется сбор конфигурации. Пожалуйста, подождите...")

		go func() {
			defer busy.Store(false)

			snapshot, err := collector.Collect(request)
			if err != nil {
				collectionPreview.SetText("Ошибка сбора конфигурации:\n" + err.Error())
				analysisLog.SetText("Сбор конфигурации завершился ошибкой.\n" + err.Error())
				return
			}

			normalized := normalize.Build(snapshot)
			showCollection(snapshot, normalized)
			analysisLog.SetText(fmt.Sprintf("Сбор завершен: параметров %d, HBA-правил %d, ролей %d.", len(snapshot.Parameters), len(snapshot.HBARules), len(snapshot.Roles)))
		}()
	}

	runAnalysis := func() {
		if busy.Load() {
			return
		}
		request := buildRequest()
		class := state.class
		setBusy(true, "Выполняется анализ защищенности...")
		analysisLog.SetText("Выполняется анализ защищенности. Пожалуйста, подождите...")

		go func() {
			defer busy.Store(false)

			result, err := state.runner.Run(service.RunRequest{
				CollectRequest: request,
				Class:          class,
			})
			if err != nil {
				analysisLog.SetText("Ошибка анализа защищенности:\n" + err.Error())
				reportPreview.SetText("Отчет не сформирован из-за ошибки анализа.\n\n" + err.Error())
				return
			}

			state.lastRun = &result
			showCollection(result.Snapshot, result.Normalized)
			analysisLog.SetText(buildAnalysisLog(result.Analysis))
			reportPreview.SetText(state.runner.Preview(result.Analysis))
		}()
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
			dialog.ShowInformation("Отчетность", fmt.Sprintf("Отчет сохранен: %s", path), window)
		}, window)
		saveDialog.SetFilter(storage.NewExtensionFileFilter([]string{"." + format.Extension()}))
		saveDialog.Show()
	}

	rightScroller := container.NewVScroll(widget.NewLabel(""))

	highlightSelected := func(index int) {
		btnConfig.Importance = widget.MediumImportance
		btnAnalyze.Importance = widget.MediumImportance
		btnReport.Importance = widget.MediumImportance
		btnAbout.Importance = widget.MediumImportance

		switch index {
		case 0:
			btnConfig.Importance = widget.HighImportance
		case 1:
			btnAnalyze.Importance = widget.HighImportance
		case 2:
			btnReport.Importance = widget.HighImportance
		case 3:
			btnAbout.Importance = widget.HighImportance
		}

		btnConfig.Refresh()
		btnAnalyze.Refresh()
		btnReport.Refresh()
		btnAbout.Refresh()
	}

	var setContent func(index int)
	setContent = func(index int) {
		switch index {
		case 0:
			box := container.NewVBox(
				widget.NewLabelWithStyle("Модуль сбора конфигурации", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
				widget.NewSeparator(),
				wrappedLabel("Подключитесь к существующей PostgreSQL по host/port/login/password. При наличии доступа к локальным путям приложение дополнительно дочитает postgresql.conf, pg_hba.conf и pg_ident.conf."),
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
				widget.NewButtonWithIcon("Начать сбор конфигурации", theme.ViewRefreshIcon(), collectAction),
				collectionPreview,
			)
			rightScroller.Content = container.NewPadded(box)

		case 1:
			box := container.NewVBox(
				widget.NewLabelWithStyle("Модуль анализа защищенности", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
				widget.NewSeparator(),
				wrappedLabel("Выберите профиль контроля и запустите анализ собранной конфигурации."),
				classSelect,
				widget.NewButtonWithIcon("Запустить анализ защищенности", theme.MediaPlayIcon(), runAnalysis),
				widget.NewLabel("Журнал выполнения:"),
				analysisLog,
			)
			rightScroller.Content = container.NewPadded(box)

		case 2:
			box := container.NewVBox(
				widget.NewLabelWithStyle("Модуль формирования отчетности", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
				widget.NewSeparator(),
				wrappedLabel("Сформируйте и сохраните отчет по результатам последнего анализа."),
				formatSelect,
				widget.NewButtonWithIcon("Сохранить отчет", theme.DocumentSaveIcon(), exportReport),
				widget.NewSeparator(),
				widget.NewLabel("Предварительный просмотр:"),
				reportPreview,
			)
			rightScroller.Content = container.NewPadded(box)

		case 3:
			infoText := widget.NewLabelWithStyle(
				"BD Scan v1.0\n\n"+
					"Программное средство контроля защищенности конфигураций СУБД PostgreSQL.\n"+
					"Интерфейс возвращен к исходной структуре с левой навигацией и темной темой,\n"+
					"при этом внутри уже работает реальный сбор конфигурации из живой базы,\n"+
					"движок правил анализа и экспорт отчетов.\n\n"+
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
	btnAbout = widget.NewButtonWithIcon("О программе", theme.InfoIcon(), func() { setContent(3) })

	topButtons := widget.NewVBox(btnConfig, btnAnalyze, btnReport)
	leftPanel := container.NewBorder(nil, btnAbout, nil, nil, topButtons)

	footer := container.NewHBox(layout.NewSpacer(), statusLabel, layout.NewSpacer(), widget.NewLabel("BD Scan v1.0"))

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
	return container.NewVBox(
		widget.NewLabel(title),
		field,
	)
}

func wrappedLabel(text string) *widget.Label {
	label := widget.NewLabel(text)
	label.Wrapping = fyne.TextWrapWord
	return label
}

func sanitizeOptionalPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}

	if runtime.GOOS == "windows" && strings.HasPrefix(value, "/") {
		return ""
	}

	return value
}
