package main

import (
	"github.com/rivo/tview"

	"github.com/fennysoftware/vaultviewer/internal/config"
	"github.com/fennysoftware/vaultviewer/internal/ui"
)

func main() {

	vic, err := config.LoadConfig("./config.yml")
	if err != nil {
		panic(err)
	}

	grid := tview.NewGrid().
		SetRows(0).
		SetColumns(40, 0).
		SetBorders(true)
	ui.Get(vic, grid)

	app := tview.NewApplication()
	if err := app.SetRoot(grid, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}
