package ui

import (
	"log"

	backend "github.com/fennysoftware/vaultviewer/internal/backend"
	config "github.com/fennysoftware/vaultviewer/internal/config"

	"github.com/gdamore/tcell/v2"

	"github.com/rivo/tview"
)

type TNodeRef struct {
	Displayname string
	Type        int
	PP          backend.PathPermissions
	Instance    *backend.VaultInstance
}

func GetTree(vic config.VaultInstanceConfig) *tview.TreeView {
	root := tview.NewTreeNode("Vault Instances").SetColor(tcell.ColorGreen)
	populateRootNode(vic, root)
	tree := tview.NewTreeView().SetRoot(root).SetCurrentNode(root)

	tree.SetSelectedFunc(func(node *tview.TreeNode) {
		reference := node.GetReference()
		if reference == nil {
			return
		}
		children := node.GetChildren()
		if len(children) == 0 {
			ref := reference.(*TNodeRef)
			if ref != nil {
				ref.Expand(node)
			}
		} else {
			// Collapse if visible, expand if collapsed.
			node.SetExpanded(!node.IsExpanded())
		}
	})

	return tree
}

func populateRootNode(vic config.VaultInstanceConfig, root *tview.TreeNode) {
	for _, ins := range vic.Instances {
		vi, err := backend.ConnectVaultInstance(ins.Address, ins.Namespace) //"https://127.0.0.1:8200", "steve", "steve", "")
		if err != nil {
			log.Printf("unable to initialize Vault client: %v", err)
			continue
		} else {

			update, err := vi.Login()
			if err != nil {
				log.Printf("unable to login: %v", err)
				continue
			}
			vi = update
			update, err = vi.GetACL()
			if err != nil {
				log.Printf("unable to get ACL: %v", err)
				continue
			}
			vi = update
			tnt := BuildNodeRef(&vi, vi.Namespace, 0, backend.PathPermissions{})
			vi_node := tview.NewTreeNode(vi.Address + " - " + vi.Namespace).SetColor(tcell.ColorGreen).SetReference(tnt)
			root.AddChild(vi_node)
		}
	}
}

// 0 = name space
// 1 = exact
// 2 = glob
// 3 = has capabilities
func BuildNodeRef(vi *backend.VaultInstance, name string, ntype int, pp backend.PathPermissions) *TNodeRef {
	tnt := TNodeRef{}
	tnt.Type = ntype
	tnt.Instance = vi
	tnt.PP = pp
	tnt.Displayname = name
	return &tnt
}

func addACLNodes(tnt *TNodeRef, target *tview.TreeNode) {
	exactrules_ref := BuildNodeRef(tnt.Instance, "ExactRules", 1, backend.PathPermissions{})
	exactrules := tview.NewTreeNode("ExactRules").SetReference(exactrules_ref).SetSelectable(true)
	if len(tnt.Instance.Acl.ExactRules) == 0 {
		exactrules.SetColor(tcell.ColorRed)
	}
	target.AddChild(exactrules)
	glob_ref := BuildNodeRef(tnt.Instance, "PrefixRules", 2, backend.PathPermissions{})
	globrules := tview.NewTreeNode("PrefixRules").SetReference(glob_ref).SetSelectable(true)
	if len(tnt.Instance.Acl.ExactRules) == 0 {
		globrules.SetColor(tcell.ColorRed)
	}
	target.AddChild(globrules)
	if tnt.Instance.Acl.Root {
		isroot := tview.NewTreeNode("IsRoot").SetSelectable(false)
		target.AddChild(isroot)
	} else {
		isroot := tview.NewTreeNode("NotRoot").SetSelectable(false)
		target.AddChild(isroot)
	}
}
func (tnt *TNodeRef) AddNodes(target *tview.TreeNode) {
	switch tnt.Type {
	case 0:
		addACLNodes(tnt, target)
	case 1:
		for _, v := range tnt.Instance.Acl.ExactRules {
			ref := BuildNodeRef(tnt.Instance, v.Path, 3, v)
			node := tview.NewTreeNode(ref.Displayname).
				SetReference(ref).SetSelectable(v.Permissions != nil)
			if v.Permissions != nil {
				node.SetColor(tcell.ColorGreen)
			}
			target.AddChild(node)
		}

	case 2:
		for _, v := range tnt.Instance.Acl.PrefixRules {
			ref := BuildNodeRef(tnt.Instance, v.Path, 3, v)
			node := tview.NewTreeNode(ref.Displayname).
				SetReference(ref).SetSelectable(v.Permissions != nil)
			if v.Permissions != nil {
				node.SetColor(tcell.ColorGreen)
			}
			target.AddChild(node)
		}
	case 3:
		cnode := tview.NewTreeNode("Capabilities").SetReference(tnt).SetSelectable(true)
		if tnt.PP.Permissions.CapabilitiesBitmap == backend.DenyCapabilityInt {
			cnode.SetColor(tcell.ColorRed)
		} else {
			cnode.SetColor(tcell.ColorYellow)
		}

		for _, cap := range tnt.PP.Permissions.Capabilities {
			node := tview.NewTreeNode(cap).SetReference(tnt).SetSelectable(false)
			cnode.AddChild(node)
		}
		target.AddChild(cnode)
	}

}

func (tnt *TNodeRef) Expand(target *tview.TreeNode) {
	tnt.AddNodes(target)
}
