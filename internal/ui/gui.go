package ui

import (
	"fyne.io/fyne"
	"fyne.io/fyne/app"
	"fyne.io/fyne/container"
	"fyne.io/fyne/layout"
	"fyne.io/fyne/theme"
	"fyne.io/fyne/widget"
)

func GuiInit() {
	a := app.New()
	a.Settings().SetTheme(theme.DarkTheme()) // ← теперь тёмная тема всегда включена

	window_root := a.NewWindow("BD Scan - Анализ защищённости СУБД")
	window_root.Resize(fyne.NewSize(900, 500))
	window_root.SetMaster()
	window_root.CenterOnScreen()

	// Правая панель с прокруткой
	rightScroller := container.NewVScroll(widget.NewLabel(""))

	// ====================== КНОПКИ ЛЕВОЙ ПАНЕЛИ ======================
	var btnConfig, btnAnalyze, btnReport, btnAbout *widget.Button

	// Функция подсветки выбранной вкладки
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
	// ============================================================

	// Функция переключения контента
	var setContent func(index int)
	setContent = func(index int) {
		switch index {
		case 0: // Сбор конфигурации
			form := &widget.Form{
				Items: []*widget.FormItem{
					{Text: "Хост", Widget: widget.NewEntry()},
					{Text: "Порт", Widget: widget.NewEntry()},
					{Text: "База данных", Widget: widget.NewEntry()},
					{Text: "Пользователь", Widget: widget.NewEntry()},
					{Text: "Пароль", Widget: widget.NewPasswordEntry()},
				},
				OnSubmit:   func() {},
				SubmitText: "Начать сбор конфигурации",
			}
			box := container.NewVBox(
				widget.NewLabelWithStyle("Модуль сбора конфигурации", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
				widget.NewSeparator(),
				widget.NewLabel("Укажите параметры подключения к экземпляру PostgreSQL:"),
				form,
				widget.NewLabel("Будут прочитаны: postgresql.conf, pg_hba.conf, pg_ident.conf"),
			)
			rightScroller.Content = container.NewPadded(box)

		case 1: // Анализ защищённости
			classSelect := widget.NewSelect([]string{
				"6 класс (минимальный)",
				"5 класс",
				"4 класс",
				"3 класс",
				"2 класс",
				"1 класс (максимальный)",
			}, func(s string) {})
			classSelect.SetSelected("6 класс (минимальный)")

			progress := widget.NewProgressBar()
			logText := widget.NewMultiLineEntry()
			logText.Disable()
			logText.SetText("[ГОТОВ] Ожидание запуска анализа...")

			startBtn := widget.NewButtonWithIcon("Запустить анализ защищённости", theme.MediaPlayIcon(), func() {
				progress.SetValue(0.1)
				logText.SetText("[СТАРТ] Запуск модуля анализа...\n")
				logText.SetText(logText.Text + "[ПРОВЕРКА] Проверка требований Приказа ФСТЭК №64...\n")
				logText.SetText(logText.Text + "[ПРОВЕРКА] Анализ параметров аутентификации...\n")
				logText.SetText(logText.Text + "[ПРОВЕРКА] Анализ разграничения доступа...\n")
				logText.SetText(logText.Text + "[ПРОВЕРКА] Контроль целостности и аудита...\n")
				progress.SetValue(1.0)
				logText.SetText(logText.Text + "[ГОТОВ] Анализ завершён. Обнаружено 3 несоответствия.\n")
			})

			box := container.NewVBox(
				widget.NewLabelWithStyle("Модуль анализа защищённости", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
				widget.NewSeparator(),
				widget.NewLabel("Выберите требуемый класс защиты СУБД:"),
				classSelect,
				startBtn,
				progress,
				widget.NewLabel("Журнал выполнения:"),
				logText,
			)
			rightScroller.Content = container.NewPadded(box)

		case 2: // Отчётность
			formatSelect := widget.NewSelect([]string{"HTML", "JSON", "PDF"}, nil)
			formatSelect.SetSelected("HTML")
			reportPreview := widget.NewMultiLineEntry()
			reportPreview.Disable()
			reportPreview.SetText("=== ОТЧЁТ О СООТВЕТСТВИИ ФСТЭК №64 ===\n\n[!] Уровень защищённости: СРЕДНИЙ (65%)\n\n[НАРУШЕНИЯ]:\n1. Парольная политика: длина пароля менее 8 символов.\n2. Аудит: не включена регистрация событий уровня ERROR.\n3. Доступ: роль 'public' имеет права CONNECT на базу.\n\n[РЕКОМЕНДАЦИИ]:\n- Увеличьте параметр password_encryption.\n- Настройте pgAudit.\n- Отзовите лишние привилегии.")

			box := container.NewVBox(
				widget.NewLabelWithStyle("Модуль формирования отчётности", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
				widget.NewSeparator(),
				widget.NewLabel("Формат экспорта:"),
				formatSelect,
				widget.NewButtonWithIcon("Сформировать отчёт", theme.DocumentSaveIcon(), func() {}),
				widget.NewSeparator(),
				widget.NewLabel("Предварительный просмотр:"),
				reportPreview,
			)
			rightScroller.Content = container.NewPadded(box)

		case 3: // О приложении
			infoText := widget.NewLabelWithStyle(
				"BD Scan v1.0\n\n"+
					"Программное средство контроля защищённости конфигураций СУБД\n"+
					"на основе требований Приказа ФСТЭК России №64.\n\n"+
					"Разработано в рамках научно-исследовательской работы:\n"+
					"«Анализ защищённости конфигураций СУБД на основе нормативных\n"+
					"требований и разработка программного средства контроля»\n\n"+
					"Авторы:\n"+
					"ФГБОУ ВО Тульский государственный университет, ИПМКН\n"+
					"Кафедра «Информационная безопасность»\n\n"+
					"Тула, 2026",
				fyne.TextAlignCenter,
				fyne.TextStyle{},
			)
			infoText.Wrapping = fyne.TextWrapWord

			box := container.NewVBox(
				widget.NewLabelWithStyle("О программном средстве", fyne.TextAlignCenter, fyne.TextStyle{Bold: true}),
				widget.NewSeparator(),
				infoText,
			)
			rightScroller.Content = container.NewPadded(box)
		}

		rightScroller.Refresh()
		highlightSelected(index)
	}

	// Создаём кнопки
	btnConfig = widget.NewButtonWithIcon("Сбор конфигурации", theme.ComputerIcon(), func() { setContent(0) })
	btnAnalyze = widget.NewButtonWithIcon("Анализ защищённости", theme.SearchIcon(), func() { setContent(1) })
	btnReport = widget.NewButtonWithIcon("Отчётность", theme.DocumentIcon(), func() { setContent(2) })
	btnAbout = widget.NewButtonWithIcon("О приложении", theme.InfoIcon(), func() { setContent(3) })

	// Левая панель
	topButtons := widget.NewVBox(btnConfig, btnAnalyze, btnReport)
	leftPanel := container.NewBorder(nil, btnAbout, nil, nil, topButtons)

	// Футер в правом нижнем углу
	footerLabel := widget.NewLabel("BD Scan v1.0")
	footer := container.NewHBox(layout.NewSpacer(), footerLabel)

	// Показываем первую вкладку
	setContent(0)

	// Основной layout
	content := container.NewBorder(
		nil,
		footer,
		container.NewPadded(leftPanel),
		nil,
		rightScroller,
	)

	window_root.SetContent(content)
	window_root.ShowAndRun()
}
