package ui

import (
	"encoding/json"
	"fmt"
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

func (tn *TNodeRef) GetInfo() string {

	if tn.Type == 4 {
		config := struct {
			Displayname string `json:"Displayname"`
			Token       string `json:"Token"`
			Namespace   string `json:"Namespace"`
			Address     string `json:"Address"`
			IsRoot      bool   `json:"IsRoot"`
		}{
			Displayname: tn.Displayname,
			Token:       tn.Instance.Client.Token(),
			Namespace:   tn.Instance.Client.Namespace(),
			Address:     tn.Instance.Client.Address(),
			IsRoot:      tn.Instance.Acl.Root,
		}

		data, err := json.MarshalIndent(&config, "", "\t")
		if err != nil {
			log.Fatal(err)
		}
		return string(data)
	} else {
		return fmt.Sprintf(`
		Displayname			: %s
		Node Type			: %d
		Instance 			: %s
		Path Permissions	: %s
		`,
			tn.Displayname,
			tn.Type,
			tn.Instance.Client.Address(),
			tn.PP.Path,
		)
	}
}

func GetTree(vic config.VaultInstanceConfig) *tview.TreeView {
	root := tview.NewTreeNode("/").SetColor(tcell.ColorGreen)
	populateRootNode(vic, root)
	root.ExpandAll()
	tree := tview.NewTreeView().SetRoot(root).SetCurrentNode(root)
	return tree
}

func populateRootNode(vic config.VaultInstanceConfig, root *tview.TreeNode) {
	for _, vconfig := range vic.Instances {
		vi, err := backend.BuildAndConnect(vconfig)
		if err != nil {
			log.Printf("unable to initialize Vault client: %v", err)
			continue
		}
		tnt := BuildNodeRef(&vi, vi.DisplayName, 0, backend.PathPermissions{})
		vi_node := tview.NewTreeNode(vi.DisplayName).SetColor(tcell.ColorGreen).SetReference(tnt)
		root.AddChild(vi_node)
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

func addConnectionNodes(tnt *TNodeRef) []*tview.TreeNode {
	children := []*tview.TreeNode{}
	children = addAppendNewNodeRef(BuildNodeRef(tnt.Instance, "Connection", 4, backend.PathPermissions{}), children, true, tcell.ColorWhite)
	return children
}

func addACLRoot(tnt *TNodeRef, children []*tview.TreeNode) []*tview.TreeNode {
	aclnode := tview.NewTreeNode("ACL").SetReference(tnt).SetSelectable(true)
	// add nodes to array
	perms := addACLNodes(tnt)
	addNodes(aclnode, perms)
	children = append(children, aclnode)
	return children
}

func addACLNodes(tnt *TNodeRef) []*tview.TreeNode {
	// add nodes to array
	children := []*tview.TreeNode{}
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

func (tnt *TNodeRef) Expand(target *tview.TreeNode) {
	children := []*tview.TreeNode{}

	switch tnt.Type {
	case 0:
		children = addConnectionNodes(tnt)
		children = addACLRoot(tnt, children)
	case 1:
		children = addPermissionNodes(tnt, tnt.Instance.Acl.ExactRules, children)
	case 2:
		children = addPermissionNodes(tnt, tnt.Instance.Acl.PrefixRules, children)
	case 3:
		cnode := tview.NewTreeNode("Capabilities").SetReference(tnt).SetSelectable(true)
		if tnt.PP.Permissions.CapabilitiesBitmap == backend.DenyCapabilityInt || len(tnt.PP.Permissions.Capabilities) == 0 {
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
	addNodes(target, children)
}
