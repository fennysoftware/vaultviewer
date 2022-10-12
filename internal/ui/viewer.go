package ui

import (
	"fmt"

	config "github.com/fennysoftware/vaultviewer/internal/config"

	"github.com/gdamore/tcell/v2"

	"github.com/rivo/tview"
)

type Viewer struct {
	tree    *tview.TreeView
	infobox *tview.TextView
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
	vwr.infobox = tview.NewTextView()
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
	}
}

func (vwr *Viewer) ShowInfo(ref *TNodeRef) {

	if ref == nil {
		vwr.infobox.SetText("Nothing Selected")
	} else {
		vwr.infobox.SetText(fmt.Sprintf("%v", ref))
	}

}
