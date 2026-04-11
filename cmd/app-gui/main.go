package main

import (
	"bd-scan/internal/ui"
	"fmt"

	"fyne.io/fyne/app"
)

func main() {
	fmt.Print("Starting gui..")

	_ = app.New() // 👈 важно: даём понять tooling, что это Fyne

	ui.GuiInit()
}
