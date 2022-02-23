package main

import (
	"fmt"

	"gorm.io/gorm"
)

// Permission represents a permission in Mumble's ACL system.
type Permission uint32

// ACL
type ACL struct {
	gorm.Model

	ChannelID int `gorm:"NOT NULL;INDEX:idx_acl_channelid"`
	// Channel   Channel `gorm:"foreignkey:ChannelID"`

	UserID int `gorm:"NOT NULL;DEFAULT:-1"`
	Group  string

	ApplyHere bool `gorm:"NOT NULL"`
	ApplySubs bool `gorm:"NOT NULL"`
	Allow     Permission
	Deny      Permission
}

const (
	// Per-channel permissions
	NonePermission        = 0x0
	WritePermission       = 0x1
	TraversePermission    = 0x2
	EnterPermission       = 0x4
	SpeakPermission       = 0x8
	MuteDeafenPermission  = 0x10
	MovePermission        = 0x20
	MakeChannelPermission = 0x40
	LinkChannelPermission = 0x80
	WhisperPermission     = 0x100
	TextMessagePermission = 0x200
	TempChannelPermission = 0x400
	ListenPermission      = 0x800

	// Root channel only
	KickPermission         = 0x10000
	BanPermission          = 0x20000
	RegisterPermission     = 0x40000
	SelfRegisterPermission = 0x80000
	ResetUserContent       = 0x100000

	// Extra flags
	AllSubPermissions = NonePermission + WritePermission + TraversePermission + EnterPermission + SpeakPermission + MuteDeafenPermission + MovePermission + MakeChannelPermission + LinkChannelPermission + WhisperPermission + TextMessagePermission + TempChannelPermission + ListenPermission
	AllPermissions    = AllSubPermissions + KickPermission + BanPermission + RegisterPermission + SelfRegisterPermission + ResetUserContent
)

func (perm Permission) isSet(check Permission) bool {
	return perm&check == check
}

// IsUserACL returns true if the ACL is defined for a user,
// as opposed to a group.
func (acl *ACL) IsUserACL() bool {
	return acl.UserID != -1
}

// IsChannelACL returns true if the ACL is defined for a group,
// as opposed to a user.
func (acl *ACL) IsChannelACL() bool {
	return !acl.IsUserACL()
}

// indexOf finds the index of the context ctx in the context chain contexts.
// Returns -1 if the given context was not found in the context chain.
func indexOf(contexts []*Channel, ctx *Channel) int {
	for i, iter := range contexts {
		if iter == ctx {
			return i
		}
	}
	return -1
}

// buildChain walks from the context ctx back through all of its parents,
// collecting them all in a slice. The first element of the returned
// slice is the final ancestor (it has a nil Parent).
func buildChain(ctx *Channel) []*Channel {
	chain := []*Channel{}
	for ctx != nil {
		chain = append([]*Channel{ctx}, chain...)
		ctx = ctx.Parent()
	}
	return chain
}

// CalculatePermission gets current permission represention
func CalculatePermission(ctx *Channel, client *Client, temporaryTokens []string) Permission {
	// We can't check permissions on a nil ctx.
	if ctx == nil {
		panic("acl: CalculatePermission got nil context")
	}

	if client.IsSuperUser() {
		if ctx.ID == 0 {
			return Permission(AllPermissions)
		} else {
			return Permission(AllSubPermissions)
		}
	}

	if len(temporaryTokens) == 0 {
		if permVal, cached := client.server.aclQueryCache.Get(fmt.Sprintf("%d:%d", client.Session(), ctx.ID)); cached {
			return permVal.(Permission)
		}
	}

	// Default permissions
	defaults := Permission(TraversePermission | EnterPermission | SpeakPermission | WhisperPermission | TextMessagePermission)
	granted := defaults
	contexts := buildChain(ctx)
	origCtx := ctx

	traverse := true
	write := false

	for _, ctx := range contexts {
		// If the context does not inherit any ACLs, use the default permissions.
		if !ctx.InheritACL {
			granted = defaults
		}
		// Iterate through ACLs that are defined on ctx. Note: this does not include
		// ACLs that iter has inherited from a parent (unless there is also a group on
		// iter with the same name, that changes the permissions a bit!)
		for _, acl := range ctx.ACLs() {
			// Determine whether the ACL applies to user.
			// If it is a user ACL and the user id of the ACL
			// matches user's id, we're good to go.
			//
			// If it's a group ACL, we have to parse and interpret
			// the group string in the current context to determine
			// membership. For that we use GroupMemberCheck.

			if (origCtx.ID == ctx.ID && !acl.ApplyHere) || (origCtx.ID != ctx.ID && !acl.ApplySubs) {
				continue
			}

			matchUser := acl.IsUserACL() && acl.UserID == client.UserId()
			matchGroup := GroupMemberCheck(origCtx, ctx, acl.Group, client, temporaryTokens)
			if matchUser || matchGroup {
				if acl.Allow.isSet(TraversePermission) {
					traverse = true
				}
				if acl.Deny.isSet(TraversePermission) {
					traverse = false
				}
				if acl.Allow.isSet(WritePermission) {
					write = true
				}
				if acl.Deny.isSet(WritePermission) {
					write = false
				}
				granted |= acl.Allow
				granted &= ^acl.Deny
			}
		}
		// If traverse is not set and the user doesn't have write permissions
		// on the channel, the user will not have any permissions.
		// This is because -traverse removes all permissions, and +write grants
		// all permissions.
		if !traverse && !write {
			granted = NonePermission
			break
		}
	}

	if len(temporaryTokens) == 0 {
		client.server.aclQueryCache.Add(fmt.Sprintf("%d:%d", client.Session(), ctx.ID), granted)
	}

	return granted

}

func HasSomehowRestricted(ctx *Channel, perm Permission) bool {
	// We can't check permissions on a nil ctx.
	if ctx == nil {
		panic("acl: CalculatePermission got nil context")
	}

	if permVal, cached := ctx.server.aclQueryCache.Get(fmt.Sprintf("CHANNEL-RESTRICTION:%d:%d", perm, ctx.ID)); cached {
		return permVal.(bool)
	}

	contexts := buildChain(ctx)

	restricted := false

	for _, ctx := range contexts {
		// If the context does not inherit any ACLs, use the default permissions.
		// Iterate through ACLs that are defined on ctx. Note: this does not include
		// ACLs that iter has inherited from a parent (unless there is also a group on
		// iter with the same name, that changes the permissions a bit!)
		for _, acl := range ctx.ACLs() {
			// Determine whether the ACL applies to user.
			// If it is a user ACL and the user id of the ACL
			// matches user's id, we're good to go.
			//
			// If it's a group ACL, we have to parse and interpret
			// the group string in the current context to determine
			// membership. For that we use GroupMemberCheck.
			if acl.IsChannelACL() {
				if acl.Deny.isSet(perm) || acl.Deny.isSet(TraversePermission) {
					restricted = true
				}
			}
		}
	}

	ctx.server.aclQueryCache.Add(fmt.Sprintf("CHANNEL-RESTRICTION:%d:%d", perm, ctx.ID), restricted)

	return restricted
}

// HasPermission checks whether the given user has permission perm in the given context.
// The permission perm must be a single permission and not a combination of permissions.
func HasPermission(ctx *Channel, client *Client, perm Permission, temporaryTokens []string) bool {
	granted := CalculatePermission(ctx, client, temporaryTokens)

	// The +write permission implies all permissions except for +speak and +whisper.
	// This means that if the user has WritePermission, we should return true for all
	// permissions except SpeakPermission and WhisperPermission.
	if perm != SpeakPermission && perm != WhisperPermission {
		return (granted & (perm | WritePermission)) != NonePermission
	} else {
		return (granted & perm) != NonePermission
	}
}
