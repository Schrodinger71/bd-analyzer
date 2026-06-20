package ui

import (
	"fmt"
	"strings"

	"bd-scan/internal/model"
	"bd-scan/internal/service"

	"fyne.io/fyne"
	"fyne.io/fyne/container"
	"fyne.io/fyne/dialog"
	"fyne.io/fyne/storage"
	"fyne.io/fyne/widget"
)

type guiState struct {
	runner  service.Service
	class   model.ProtectionClass
	lastRun *service.RunResult
}

func newPathPicker(window fyne.Window, entry *widget.Entry, extensions []string) fyne.CanvasObject {
	button := widget.NewButton("Обзор...", func() {
		if path, handled, pickErr := tryPickOpenPath(extensions); handled {
			if pickErr != nil {
				dialog.ShowError(pickErr, window)
				return
			}
			if path != "" {
				entry.SetText(path)
			}
			return
		}

		fileDialog := dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, window)
				return
			}
			if reader == nil {
				return
			}
			path := pathFromURI(reader.URI())
			if closeErr := reader.Close(); closeErr != nil {
				dialog.ShowError(closeErr, window)
				return
			}
			entry.SetText(path)
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

func shortenUIString(value string, limit int) string {
	value = strings.TrimSpace(value)
	if limit <= 3 || len(value) <= limit {
		return value
	}
	return value[:limit-3] + "..."
}
