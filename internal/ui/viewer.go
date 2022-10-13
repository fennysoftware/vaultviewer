package ui

import (
	"github.com/fennysoftware/vaultviewer/internal/config"
	"github.com/fennysoftware/vaultviewer/internal/executer"
	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

type Viewer struct {
	tree    *tview.TreeView
	infobox *tview.TextArea
}

func Get(vic config.VaultInstanceConfig, grid *tview.Grid) *Viewer {
	vwr := Viewer{}
	vwr.tree = GetTree(vic)
	vwr.tree.SetSelectedFunc(func(node *tview.TreeNode) {
		reference := node.GetReference()
		if reference == nil {
			return
		}
		children := node.GetChildren()
		if len(children) == 0 {
			ref := reference.(*TNodeRef)
			if ref != nil {
				vwr.ShowInfo(ref)
				ref.Expand(node)
			}
		} else {
			// Collapse if visible, expand if collapsed.
			node.SetExpanded(!node.IsExpanded())
		}
	})

	vwr.tree.SetInputCapture(func(event *tcell.EventKey) *tcell.EventKey {
		handleEventWithKey(&vwr, event)
		return event
	})

	vwr.infobox = tview.NewTextArea() //tview.NewTextView()
	vwr.infobox.SetBorder(true).SetTitle("Info")
	grid.AddItem(vwr.infobox, 0, 1, 1, 1, 0, 0, false)
	// Layout for screens wider than 100 cells.
	grid.AddItem(vwr.tree, 0, 0, 1, 1, 0, 100, true)
	return &vwr
}

func handleEventWithKey(vwr *Viewer, event *tcell.EventKey) {
	if event == nil {
		return
	}

	switch event.Rune() {
	case 'i':
		node := vwr.tree.GetCurrentNode()
		reference := node.GetReference()
		ref := reference.(*TNodeRef)
		if ref != nil {
			vwr.ShowInfo(ref)
		} else {
			vwr.ShowInfo(nil)
		}

	case 'r':
		node := vwr.tree.GetCurrentNode()
		reference := node.GetReference()
		if reference != nil {
			ref := reference.(*TNodeRef)
			if ref != nil {
				// we want to run a new terminal/cmd.exe/bash etc
				executer.Runner(ref.Instance)
			}
		}
	}
}

func (vwr *Viewer) ShowInfo(ref *TNodeRef) {
	if ref == nil {
		vwr.infobox.SetText("Nothing Selected", false)
	} else {
		vwr.infobox.SetText(ref.GetInfo(), false)
	}
}
