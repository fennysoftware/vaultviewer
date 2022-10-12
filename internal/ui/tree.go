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
		vi, err := backend.ConnectVaultInstance(ins)
		if err != nil {
			log.Printf("unable to initialize Vault client: %v", err)
			continue
		} else {

			update, err := vi.Login(ins)
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
			tnt := BuildNodeRef(&vi, vi.DisplayName, 0, backend.PathPermissions{})
			vi_node := tview.NewTreeNode(vi.DisplayName).SetColor(tcell.ColorGreen).SetReference(tnt)
			root.AddChild(vi_node)
		}
	}
}

// 0 = name space
// 1 = exact
// 2 = glob
// 3 = has capabilities
// 4 = connection
func BuildNodeRef(vi *backend.VaultInstance, name string, ntype int, pp backend.PathPermissions) *TNodeRef {
	tnt := TNodeRef{}
	tnt.Type = ntype
	tnt.Instance = vi
	tnt.PP = pp
	tnt.Displayname = name
	return &tnt
}

func addNodes(target *tview.TreeNode, children []*tview.TreeNode) {
	for _, child := range children {
		target.AddChild(child)
	}
}

func addAppendNewNodeRef(ref *TNodeRef, children []*tview.TreeNode, selectable bool, col tcell.Color) []*tview.TreeNode {

	child := tview.NewTreeNode(ref.Displayname).SetReference(ref).SetSelectable(selectable)
	child.SetColor(col)

	// add node to array
	children = append(children, child)
	return children
}

func addACLNodes(tnt *TNodeRef) []*tview.TreeNode {
	children := []*tview.TreeNode{}
	// add nodes to array
	children = addAppendNewNodeRef(BuildNodeRef(tnt.Instance, "Connection", 4, backend.PathPermissions{}), children, true, tcell.ColorWhite)
	if len(tnt.Instance.Acl.ExactRules) == 0 {
		children = addAppendNewNodeRef(BuildNodeRef(tnt.Instance, "ExactRules", 1, backend.PathPermissions{}), children, true, tcell.ColorRed)
	} else {
		children = addAppendNewNodeRef(BuildNodeRef(tnt.Instance, "ExactRules", 1, backend.PathPermissions{}), children, true, tcell.ColorWhite)
	}
	if len(tnt.Instance.Acl.PrefixRules) == 0 {
		children = addAppendNewNodeRef(BuildNodeRef(tnt.Instance, "PrefixRules", 2, backend.PathPermissions{}), children, true, tcell.ColorRed)
	} else {
		children = addAppendNewNodeRef(BuildNodeRef(tnt.Instance, "PrefixRules", 2, backend.PathPermissions{}), children, true, tcell.ColorWhite)
	}
	return children
}

func addPermissionNodes(tnt *TNodeRef, pp []backend.PathPermissions, children []*tview.TreeNode) []*tview.TreeNode {
	for _, v := range pp {
		if v.Permissions != nil {
			children = addAppendNewNodeRef(BuildNodeRef(tnt.Instance, v.Path, 3, v), children, true, tcell.ColorGreen)
		} else {
			children = addAppendNewNodeRef(BuildNodeRef(tnt.Instance, v.Path, 3, v), children, false, tcell.ColorRed)
		}
	}
	return children
}

func (tnt *TNodeRef) AddNodes(target *tview.TreeNode) {

	children := []*tview.TreeNode{}

	switch tnt.Type {
	case 0:
		children = addACLNodes(tnt)
	case 1:
		children = addPermissionNodes(tnt, tnt.Instance.Acl.ExactRules, children)
	case 2:
		children = addPermissionNodes(tnt, tnt.Instance.Acl.PrefixRules, children)
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
	case 4:
		address := tview.NewTreeNode(tnt.Instance.Client.Address()).SetSelectable(true)
		target.AddChild(address)
		namespace := tview.NewTreeNode(tnt.Instance.Client.Namespace()).SetSelectable(true)
		target.AddChild(namespace)
		if tnt.Instance.Acl.Root {
			isroot := tview.NewTreeNode("IsRoot").SetSelectable(true)
			target.AddChild(isroot)
		} else {
			isroot := tview.NewTreeNode("NotRoot").SetSelectable(true)
			target.AddChild(isroot)
		}
		token := tview.NewTreeNode(tnt.Instance.Client.Token()).SetSelectable(false)
		target.AddChild(token)
	}

	addNodes(target, children)
}

func (tnt *TNodeRef) Expand(target *tview.TreeNode) {
	tnt.AddNodes(target)
}
