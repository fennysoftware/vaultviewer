package backend

import (
	"log"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

const (
	DenyCapability   = "deny"
	CreateCapability = "create"
	ReadCapability   = "read"
	UpdateCapability = "update"
	DeleteCapability = "delete"
	ListCapability   = "list"
	SudoCapability   = "sudo"
	RootCapability   = "root"
	PatchCapability  = "patch"

	// Backwards compatibility
	OldDenyPathPolicy  = "deny"
	OldReadPathPolicy  = "read"
	OldWritePathPolicy = "write"
	OldSudoPathPolicy  = "sudo"
)

const (
	DenyCapabilityInt uint32 = 1 << iota
	CreateCapabilityInt
	ReadCapabilityInt
	UpdateCapabilityInt
	DeleteCapabilityInt
	ListCapabilityInt
	SudoCapabilityInt
	PatchCapabilityInt
)

func toPathPermissions(pt map[string]interface{}) []PathPermissions {

	pathps := []PathPermissions{}

	for k, v1 := range pt {
		pp := PathPermissions{}
		pp.Path = k

		log.Printf("parsing %s: %v", k, v1)
		pt1 := v1.(map[string]interface{})

		perms := &ACLPermissions{}
		perms.MinWrappingTTL = 0
		perms.MaxWrappingTTL = 0
		perms.AllowedParameters = map[string][]interface{}{}
		perms.DeniedParameters = map[string][]interface{}{}
		perms.RequiredParameters = []string{}

		for k, v2 := range pt1 {
			log.Printf("parsing %s: %v", k, v2)
			if k == "capabilities" {
				capabilities := v2.([]interface{})
				capabilitiesraw := []string{}
				res := uint32(0)
				for _, c := range capabilities {
					capability := c.(string)
					if capability != "" {
						log.Printf("\ncap: %s: %d\n", capability, cap2Int[capability])
						res |= cap2Int[capability]
						capabilitiesraw = append(capabilitiesraw, capability)
					}
				}
				log.Printf("\nfinal cap: %d\n", res)
				if res == 0 {
					perms.CapabilitiesBitmap = DenyCapabilityInt
				} else {
					perms.CapabilitiesBitmap = res
				}
				perms.Capabilities = capabilitiesraw
			}
		}
		pp.Permissions = perms
		pathps = append(pathps, pp)
	}

	sort.Sort(ppSort(pathps))

	return pathps
}

type PolicyType uint32

const (
	PolicyTypeACL PolicyType = iota
	PolicyTypeRGP
	PolicyTypeEGP

	// Triggers a lookup in the map to figure out if ACL or RGP
	PolicyTypeToken
)

func (p PolicyType) String() string {
	switch p {
	case PolicyTypeACL:
		return "acl"
	case PolicyTypeRGP:
		return "rgp"
	case PolicyTypeEGP:
		return "egp"
	}

	return ""
}

var cap2Int = map[string]uint32{
	DenyCapability:   DenyCapabilityInt,
	CreateCapability: CreateCapabilityInt,
	ReadCapability:   ReadCapabilityInt,
	UpdateCapability: UpdateCapabilityInt,
	DeleteCapability: DeleteCapabilityInt,
	ListCapability:   ListCapabilityInt,
	SudoCapability:   SudoCapabilityInt,
	PatchCapability:  PatchCapabilityInt,
}

type Policy struct {
	Name      string       `hcl:"name"`
	Paths     []*PathRules `hcl:"-"`
	Raw       string
	Type      PolicyType
	Templated bool
}

type PathPermissions struct {
	Path        string
	Permissions *ACLPermissions
}

type ppSort []PathPermissions

func (s ppSort) Len() int {
	return len(s)
}

func (s ppSort) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
}

func (s ppSort) Less(i, j int) bool {
	return (strings.Compare(s[i].Path, s[j].Path) < 0)
}

type ACL struct {
	// exactRules contains the path policies that are exact
	//exactRules *radix.Tree
	ExactRules []PathPermissions
	// prefixRules contains the path policies that are a prefix
	//prefixRules *radix.Tree
	PrefixRules []PathPermissions
	//segmentWildcardPaths map[string]interface{}

	// root is enabled if the "root" named policy is present.
	Root bool

	// Stores policies that are actually RGPs for later fetching
	//rgpPolicies []*Policy
}

type ControlGroup struct {
	TTL     time.Duration
	Factors []*ControlGroupFactor
}

type ControlGroupFactor struct {
	Name                   string
	Identity               *IdentityFactor `hcl:"identity"`
	ControlledCapabilities []string        `hcl:"controlled_capabilities"`
}

type IdentityFactor struct {
	GroupIDs          []string `hcl:"group_ids"`
	GroupNames        []string `hcl:"group_names"`
	ApprovalsRequired int      `hcl:"approvals"`
}

type ACLPermissions struct {
	CapabilitiesBitmap  uint32
	MinWrappingTTL      time.Duration
	MaxWrappingTTL      time.Duration
	AllowedParameters   map[string][]interface{}
	DeniedParameters    map[string][]interface{}
	RequiredParameters  []string
	MFAMethods          []string
	ControlGroup        *ControlGroup
	GrantingPoliciesMap map[uint32][]logical.PolicyInfo
	Capabilities        []string
}

// PathRules represents a policy for a path in the namespace.
type PathRules struct {
	Path                string
	Policy              string
	Permissions         *ACLPermissions
	IsPrefix            bool
	HasSegmentWildcards bool
	Capabilities        []string

	// These keys are used at the top level to make the HCL nicer; we store in
	// the ACLPermissions object though
	MinWrappingTTLHCL     interface{}              `hcl:"min_wrapping_ttl"`
	MaxWrappingTTLHCL     interface{}              `hcl:"max_wrapping_ttl"`
	AllowedParametersHCL  map[string][]interface{} `hcl:"allowed_parameters"`
	DeniedParametersHCL   map[string][]interface{} `hcl:"denied_parameters"`
	RequiredParametersHCL []string                 `hcl:"required_parameters"`
	MFAMethodsHCL         []string                 `hcl:"mfa_methods"`
	ControlGroupHCL       *ControlGroupHCL         `hcl:"control_group"`
}

type ControlGroupHCL struct {
	TTL     interface{}                    `hcl:"ttl"`
	Factors map[string]*ControlGroupFactor `hcl:"factor"`
}
