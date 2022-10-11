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

	tree := ui.GetTree(vic)
	if err := tview.NewApplication().SetRoot(tree, true).EnableMouse(true).Run(); err != nil {
		panic(err)
	}
}
