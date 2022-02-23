// Copyright (c) 2010 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"crypto/aes"
	"crypto/tls"
	"fmt"
	"strconv"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/wfjsw/hall/mumbleproto"
)

// Message describes an incoming proto message
type Message struct {
	buf    []byte
	kind   uint16
	client *Client
}

// VoiceBroadcast describes an incoming voice packet
type VoiceBroadcast struct {
	// The client who is performing the broadcast
	client *Client
	// The VoiceTarget identifier.
	target byte
	// The voice packet itself.
	buf []byte
}

func (server *Server) handleCryptSetup(client *Client, msg *Message) {
	cs := &mumbleproto.CryptSetup{}
	err := proto.Unmarshal(msg.buf, cs)
	if err != nil {
		panic(err) // Caught by incoming message hub
	}

	// No client nonce. This means the client
	// is requesting that we re-sync our nonces.
	if len(cs.ClientNonce) == 0 {
		client.Debugf("Client requested crypt-nonce resync")
		cs.ServerNonce = make([]byte, aes.BlockSize)
		func() {
			client.crypt.Lock()
			defer client.crypt.Unlock()

			if copy(cs.ServerNonce, client.crypt.EncryptIV[0:]) != aes.BlockSize {
				panic("Unable to copy nonce to server state")
			}
		}()
		err := client.sendMessage(cs)
		if err != nil {
			panic(err) // Caught by incoming message hub
		}
	} else {
		client.Debugf("Received client nonce")
		if len(cs.ClientNonce) != aes.BlockSize {
			panic(fmt.Sprintf("Invalid client nonce length: %d", len(cs.ClientNonce)))
		}
		func() {
			client.crypt.Lock()
			defer client.crypt.Unlock()

			client.crypt.Resync++
			if copy(client.crypt.DecryptIV[0:], cs.ClientNonce) != aes.BlockSize {
				panic("Unable to copy nonce to client state")
			}

			client.Debugf("Crypt re-sync successful")
		}()

	}
}

func (server *Server) handlePingMessage(client *Client, msg *Message) {
	defer client.recover(nil)

	ping := &mumbleproto.Ping{}
	err := proto.Unmarshal(msg.buf, ping)
	if err != nil {
		panic(err) // Caught by tlsRecvLoop
	}

	client.statsMutex.Lock()
	defer client.statsMutex.Unlock()

	client.crypt.Lock()
	defer client.crypt.Unlock()

	client.LastPing = time.Now().Unix()

	if ping.Good != nil {
		client.crypt.RemoteGood = *ping.Good
	}
	if ping.Late != nil {
		client.crypt.RemoteLate = *ping.Late
	}
	if ping.Lost != nil {
		client.crypt.RemoteLost = *ping.Lost
	}
	if ping.Resync != nil {
		client.crypt.RemoteResync = *ping.Resync
	}

	if ping.UdpPingAvg != nil {
		client.UDPPingAvg = *ping.UdpPingAvg
	}
	if ping.UdpPingVar != nil {
		client.UDPPingVar = *ping.UdpPingVar
	}
	if ping.UdpPackets != nil {
		client.UDPPackets = *ping.UdpPackets
	}

	if ping.TcpPingAvg != nil {
		client.TCPPingAvg = *ping.TcpPingAvg
	}
	if ping.TcpPingVar != nil {
		client.TCPPingVar = *ping.TcpPingVar
	}
	if ping.TcpPackets != nil {
		client.TCPPackets = *ping.TcpPackets
	}

	err = client.sendMessage(&mumbleproto.Ping{
		Timestamp: ping.Timestamp,
		Good:      proto.Uint32(client.crypt.Good),
		Late:      proto.Uint32(client.crypt.Late),
		Lost:      proto.Uint32(client.crypt.Lost),
		Resync:    proto.Uint32(client.crypt.Resync),
	})
	if err != nil {
		panic(err) // Caught by tlsRecvLoop
	}

	client.recalcUnstableUDP()
}

func (server *Server) handleChannelRemoveMessage(client *Client, msg *Message) {
	chanremove := &mumbleproto.ChannelRemove{}
	err := proto.Unmarshal(msg.buf, chanremove)
	if err != nil {
		panic(err) // Caught by incoming message hub
	}

	if chanremove.ChannelId == nil {
		return
	}

	channel := server.GetChannel(int(*chanremove.ChannelId))
	if channel == nil {
		return
	}

	if !HasPermission(channel, client, WritePermission, []string{}) {
		client.sendPermissionDenied(client, channel, WritePermission)
		return
	}

	server.RemoveChannel(channel)
}

// Handle channel state change.
func (server *Server) handleChannelStateMessage(client *Client, msg *Message) {
	chanstate := &mumbleproto.ChannelState{}
	err := proto.Unmarshal(msg.buf, chanstate)
	if err != nil {
		panic(err) // Caught by incoming message hub
	}

	var channel *Channel
	var parent *Channel
	// var ok bool

	// Lookup channel for channel ID
	if chanstate.ChannelId != nil {
		channel = server.GetChannel(int(*chanstate.ChannelId))
		if channel == nil {
			panic("Invalid channel specified in ChannelState message") // Caught by incoming message hub
		}
	}

	// Lookup parent
	if chanstate.Parent != nil {
		parent = server.GetChannel(int(*chanstate.Parent))
		if parent == nil {
			panic("Invalid parent channel specified in ChannelState message") // Caught by incoming message hub
		}
	}

	// The server can't receive links through the links field in the ChannelState message,
	// because clients are supposed to send modifications to a channel's link state through
	// the links_add and links_remove fields.
	// Make sure the links field is clear so we can transmit the channel's link state in our reply.
	chanstate.Links = nil

	var name string
	var description string

	// Extract the description and perform sanity checks.
	if chanstate.Description != nil {
		description, err = server.FilterText(*chanstate.Description)
		if err != nil {
			client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TextTooLong)
			return
		}
	}

	// Extract the the name of channel and check whether it's valid.
	// A valid channel name is a name that:
	//  a) Isn't already used by a channel at the same level as the channel itself (that is, channels
	//     that have a common parent can't have the same name.
	//  b) A name must be a valid name on the server (it must pass the channel name regexp)
	if chanstate.Name != nil {
		name = *chanstate.Name

		// We don't allow renames for the root channel.
		if channel != nil && channel.ID > 0 {
			// Pick a parent. If the name change is part of a re-parent (a channel move),
			// we must evaluate the parent variable. Since we're explicitly exlcuding the root
			// channel from renames, channels that are the target of renames are guaranteed to have
			// a parent.
			evalp := parent
			if evalp == nil {
				evalp = channel.Parent()
			}
			for _, iter := range evalp.Childrens() {
				if iter.Name == name {
					client.sendPermissionDeniedType(mumbleproto.PermissionDenied_ChannelName)
					return
				}
			}
		}
	}

	// If the channel does not exist already, the ChannelState message is a create operation.
	if channel == nil {
		if parent == nil || len(name) == 0 {
			return
		}

		// Check whether the client has permission to create the channel in parent.
		perm := Permission(NonePermission)
		if *chanstate.Temporary {
			// perm = Permission(acl.TempChannelPermission)
			client.sendPermissionDeniedText("Temporary channel is not implemented.")
			return
		}

		perm = Permission(MakeChannelPermission)
		if !HasPermission(parent, client, perm, []string{}) {
			client.sendPermissionDenied(client, parent, perm)
			return
		}

		// Only registered users can create channels.
		if !client.IsRegistered() && !client.HasCertificate() {
			client.sendPermissionDeniedTypeUser(mumbleproto.PermissionDenied_MissingCertificate, client)
			return
		}

		// We can't add channels to a temporary channel
		if parent.IsTemporary() {
			client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TemporaryChannel)
			return
		}

		key := ""
		if len(description) > 0 {
			key, err = blobStore.Put([]byte(description))
			if err != nil {
				server.Fatalf("Blobstore error: %v", err)
			}
		}

		// Add the new channel
		channel = server.NewChannel(name)
		channel.DescriptionBlob = key
		// channel.temporary = *chanstate.Temporary
		channel.Position = int(*chanstate.Position)

		if chanstate.MaxUsers != nil {
			channel.MaxUsers = int(*chanstate.MaxUsers)
		} else {
			channel.MaxUsers = 0
		}

		channel.Save()
		channel.SetParent(parent)

		// If the client wouldn't have WritePermission in the just-created channel,
		// add a +write ACL for the user's hash.
		if !HasPermission(channel, client, WritePermission, []string{}) {
			aclEntry := ACL{}
			aclEntry.ApplyHere = true
			aclEntry.ApplySubs = true
			if client.IsRegistered() {
				aclEntry.UserID = client.UserId()
			} else {
				aclEntry.Group = "$" + client.CertHash()
			}
			aclEntry.Deny = Permission(NonePermission)
			aclEntry.Allow = Permission(WritePermission | TraversePermission)

			channel.AppendACL(&aclEntry)
		}

		chanstate.ChannelId = proto.Uint32(uint32(channel.ID))

		server.ClearCaches()

		// Broadcast channel add
		server.broadcastProtoMessageWithPredicate(chanstate, func(client *Client) bool {
			return client.Version < 0x10202
		})

		// Remove description if client knows how to handle blobs.
		if chanstate.Description != nil && channel.HasDescription() {
			chanstate.Description = nil
			chanstate.DescriptionHash = channel.DescriptionBlobHashBytes()
		}
		server.broadcastProtoMessageWithPredicate(chanstate, func(client *Client) bool {
			return client.Version >= 0x10202
		})

		// If it's a temporary channel, move the creator in there.
		if channel.IsTemporary() {
			client.MoveChannel(channel, nil)
			// userstate := &mumbleproto.UserState{}
			// userstate.Session = proto.Uint32(client.Session())
			// userstate.ChannelId = proto.Uint32(uint32(channel.ID))
			// server.userEnterChannel(client, channel, userstate)
			// server.broadcastUserState(userstate)
		}
	} else {
		// Edit existing channel.
		// First, check whether the actor has the neccessary permissions.

		// Name change.
		if chanstate.Name != nil {
			// The client can only rename the channel if it has WritePermission in the channel.
			// Also, clients cannot change the name of the root channel.
			if !HasPermission(channel, client, WritePermission, []string{}) || channel.ID == 0 {
				client.sendPermissionDenied(client, channel, WritePermission)
				return
			}
		}

		// Description change
		if chanstate.Description != nil {
			if !HasPermission(channel, client, WritePermission, []string{}) {
				client.sendPermissionDenied(client, channel, WritePermission)
				return
			}
		}

		// Position change
		if chanstate.Position != nil {
			if !HasPermission(channel, client, WritePermission, []string{}) {
				client.sendPermissionDenied(client, channel, WritePermission)
				return
			}
		}

		// Parent change (channel move)
		if parent != nil {
			// No-op?
			if parent.ID == channel.ParentID {
				return
			}

			// Make sure that channel we're operating on is not a parent of the new parent.
			iter := parent
			for iter != nil {
				if iter.ID == channel.ID {
					client.sendPermissionDeniedText("Illegal channel reparent")
					return
				}
				iter = iter.Parent()
			}

			// A temporary channel must not have any subchannels, so deny it.
			if parent.IsTemporary() {
				client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TemporaryChannel)
				return
			}

			// To move a channel, the user must have WritePermission in the channel
			if !HasPermission(channel, client, WritePermission, []string{}) {
				client.sendPermissionDenied(client, channel, WritePermission)
				return
			}

			// And the user must also have MakeChannel permission in the new parent
			if !HasPermission(parent, client, MakeChannelPermission, []string{}) {
				client.sendPermissionDenied(client, parent, MakeChannelPermission)
				return
			}

			// If a sibling of parent already has this name, don't allow it.
			for _, iter := range parent.Childrens() {
				if iter.Name == channel.Name {
					client.sendPermissionDeniedType(mumbleproto.PermissionDenied_ChannelName)
					return
				}
			}
		}

		// Links
		linkadd := []*Channel{}
		linkremove := []*Channel{}
		if len(chanstate.LinksAdd) > 0 || len(chanstate.LinksRemove) > 0 {
			// Client must have permission to link
			if !HasPermission(channel, client, LinkChannelPermission, []string{}) {
				client.sendPermissionDenied(client, channel, LinkChannelPermission)
				return
			}
			// Add any valid channels to linkremove slice
			for _, cid := range chanstate.LinksRemove {
				if iter := server.GetChannel(int(cid)); iter != nil {
					linkremove = append(linkremove, iter)
				}
			}
			// Add any valid channels to linkadd slice
			for _, cid := range chanstate.LinksAdd {
				if iter := server.GetChannel(int(cid)); iter != nil {
					if !HasPermission(iter, client, LinkChannelPermission, []string{}) {
						client.sendPermissionDenied(client, iter, LinkChannelPermission)
						return
					}
					linkadd = append(linkadd, iter)
				}
			}
		}

		// Permission checks done!

		// Channel move
		if parent != nil {
			channel.SetParent(parent)
		}

		// Rename
		if chanstate.Name != nil {
			channel.Name = *chanstate.Name
		}

		// Description change
		if chanstate.Description != nil {
			if len(description) == 0 {
				channel.DescriptionBlob = ""
			} else {
				key, err := blobStore.Put([]byte(description))
				if err == nil {
					channel.DescriptionBlob = key
					// server.Panicf("Blobstore error: %v", err)
				}
			}
		}

		// Position change
		if chanstate.Position != nil {
			channel.Position = int(*chanstate.Position)
		}

		if chanstate.MaxUsers != nil {
			channel.MaxUsers = int(*chanstate.MaxUsers)
		}

		channel.Save()

		// Add links
		for _, iter := range linkadd {
			server.LinkChannels(channel, iter)
		}

		// Remove links
		for _, iter := range linkremove {
			server.UnlinkChannels(channel, iter)
		}

		server.ClearCaches()

		// Broadcast the update
		server.broadcastProtoMessageWithPredicate(chanstate, func(client *Client) bool {
			return client.Version < 0x10202
		})

		// Remove description blob when sending to 1.2.2 >= users. Only send the blob hash.
		if channel.HasDescription() {
			chanstate.Description = nil
			chanstate.DescriptionHash = channel.DescriptionBlobHashBytes()
		}
		chanstate.DescriptionHash = channel.DescriptionBlobHashBytes()
		server.broadcastProtoMessageWithPredicate(chanstate, func(client *Client) bool {
			return client.Version >= 0x10202
		})

	}

	// Update channel in datastore
	// if !channel.IsTemporary() {
	// 	server.UpdateFrozenChannel(channel, chanstate)
	// }

}

// Handle a user remove packet. This can either be a client disconnecting, or a
// user kicking or kick-banning another player.
func (server *Server) handleUserRemoveMessage(client *Client, msg *Message) {
	userremove := &mumbleproto.UserRemove{}
	err := proto.Unmarshal(msg.buf, userremove)
	if err != nil {
		panic(err) // Caught by incoming message hub
	}

	// Get the client to be removed.
	removeClient, ok := server.clients.Get(*userremove.Session)
	if !ok {
		client.sendMessage(&mumbleproto.UserRemove{
			Session: proto.Uint32(*userremove.Session),
		})
		client.Print("Invalid session in UserState message")
		return
	}

	isBan := false
	if userremove.Ban != nil {
		isBan = *userremove.Ban
	}

	// Check client's permissions
	perm := Permission(KickPermission)
	if isBan {
		perm = Permission(BanPermission)
	}
	rootChan := server.RootChannel()
	if removeClient.IsSuperUser() || !HasPermission(rootChan, client, perm, []string{}) {
		client.sendPermissionDenied(client, rootChan, perm)
		return
	}

	if isBan {
		ban := Ban{}
		ban.Address = removeClient.realip.IP
		ban.Mask = 128
		if userremove.Reason != nil {
			ban.Reason = *userremove.Reason
		}
		ban.Name = removeClient.ShownName()
		ban.Hash = removeClient.CertHash()
		ban.Start = time.Now().Unix()
		ban.Duration = 0

		server.AppendBan(&ban)
	}

	userremove.Actor = proto.Uint32(client.Session())

	func() {
		server.userStateLock.Lock()
		defer server.userStateLock.Unlock()
		server.broadcastProtoMessage(userremove)
	}()

	if isBan {
		client.Printf("Kick-banned %v (%v)", removeClient.ShownName(), removeClient.Session())
	} else {
		client.Printf("Kicked %v (%v)", removeClient.ShownName(), removeClient.Session())
	}

	removeClient.ForceDisconnect()

	server.ClearCachesByUser(removeClient)
}

// Handle user state changes
func (server *Server) handlePreConnectUserStateMessage(client *Client, msg *Message) {
	// GOROUTINE START
	defer client.recover(nil)

	userstate := &mumbleproto.UserState{}
	err := proto.Unmarshal(msg.buf, userstate)
	if err != nil {
		panic(err) // Caught by this function
	}

	if userstate.Session != nil {
		if *userstate.Session != client.Session() && *userstate.Session != 0 {
			panic(fmt.Sprintf("Non self-targeted state change is not allowed in pre-connect state. Target session: %d, Self session: %d", *userstate.Session, client.Session())) // Caught by this function
		}
	}

	if userstate.SelfDeaf != nil {
		client.SelfDeaf = *userstate.SelfDeaf
	}

	if userstate.SelfMute != nil {
		client.SelfMute = *userstate.SelfMute
	}

	if userstate.PluginContext != nil {
		client.PluginContext = userstate.PluginContext
	}

	if userstate.PluginIdentity != nil {
		client.PluginIdentity = *userstate.PluginIdentity
	}

}

// Handle user state changes
func (server *Server) handleUserStateMessage(client *Client, msg *Message) {
	userstate := &mumbleproto.UserState{}
	err := proto.Unmarshal(msg.buf, userstate)
	if err != nil {
		panic(err) // Caught by incoming message hub
	}

	actor, ok := server.clients.Get(client.Session())
	if !ok {
		server.Printf("Client %d not found in server's client map.", client.Session())
		return
	}
	target := actor
	if userstate.Session != nil {
		target, ok = server.clients.Get(*userstate.Session)
		if !ok {
			client.sendMessage(&mumbleproto.UserRemove{
				Session: proto.Uint32(*userstate.Session),
			})
			client.Print("Invalid session in UserState message")
			return
		}
	}

	userstate.Session = proto.Uint32(target.Session())
	userstate.Actor = proto.Uint32(actor.Session())

	// Does it have a channel ID?
	if userstate.ChannelId != nil {
		// Destination channel
		dstChan := server.GetChannel(int(*userstate.ChannelId))
		if dstChan == nil {
			return
		}

		// If the user and the actor aren't the same, check whether the actor has MovePermission on
		// the user's curent channel.
		// Check whether the actor has MovePermission on dstChan.  Check whether user has EnterPermission
		// on dstChan.
		// if !HasPermission(dstChan, actor, MovePermission) && !HasPermission(dstChan, target, EnterPermission) {

		//if actor != target && (!HasPermission(target.Channel(), actor, MovePermission) || !HasPermission(dstChan, actor, EnterPermission) || !HasPermission(dstChan, actor, MovePermission)) {
		//	client.sendPermissionDenied(actor, target.Channel(), MovePermission)
		//	return
		//} else if actor == target && !HasPermission(dstChan, target, EnterPermission) {
		//	client.sendPermissionDenied(target, dstChan, EnterPermission)
		//	return
		//}

		if actor.Session() != target.Session() {
			// Moving others

			// if target does not have TraversePermission on dstChan, deny
			if !HasPermission(dstChan, target, TraversePermission, []string{}) {
				client.sendPermissionDenied(target, dstChan, TraversePermission)
				return
			}

			// if target has EnterPermission on dstChan, only check MovePermission of actor on target's current channel
			if !HasPermission(dstChan, target, EnterPermission, []string{}) {
				if !HasPermission(target.Channel(), actor, MovePermission, []string{}) {
					client.sendPermissionDenied(actor, target.Channel(), MovePermission)
					return
				}
			} else {
				// Otherwise actor need to have MovePermission on dstChan
				if !HasPermission(dstChan, actor, MovePermission, []string{}) {
					client.sendPermissionDenied(actor, dstChan, MovePermission)
					return
				}
			}
		} else {
			temporaryTokens := userstate.GetTemporaryAccessTokens()

			// Moving self
			if !HasPermission(dstChan, target, EnterPermission, temporaryTokens) {
				client.sendPermissionDenied(target, dstChan, EnterPermission)
				return
			}
		}

		maxChannelUsers := server.cfg.MaxChannelUsers
		if dstChan.MaxUsers > 0 {
			maxChannelUsers = dstChan.MaxUsers
		}
		if maxChannelUsers != 0 && len(dstChan.Clients()) >= maxChannelUsers && !client.IsSuperUser() {
			client.sendPermissionDeniedFallback(mumbleproto.PermissionDenied_ChannelFull,
				0x010201, "Channel is full")
			return
		}
	}

	if userstate.Mute != nil || userstate.Deaf != nil || userstate.Suppress != nil || userstate.PrioritySpeaker != nil {
		// Disallow for SuperUser
		// if target.IsSuperUser() {
		// 	client.sendPermissionDeniedType(mumbleproto.PermissionDenied_SuperUser)
		// 	return
		// }

		// Check whether the actor has 'mutedeafen' permission on user's channel.
		if !HasPermission(target.Channel(), actor, MuteDeafenPermission, []string{}) {
			client.sendPermissionDenied(actor, target.Channel(), MuteDeafenPermission)
			return
		}

		// Check if this was a suppress operation. Only the server can suppress users.
		if userstate.Suppress != nil && *userstate.Suppress == true {
			client.sendPermissionDenied(actor, target.Channel(), MuteDeafenPermission)
			return
		}
	}

	// Comment set/clear
	if userstate.Comment != nil {
		comment := *userstate.Comment

		// Clearing another user's comment.
		if target != actor {
			// Check if actor has 'move' permissions on the root channel. It is needed
			// to clear another user's comment.
			rootChan := server.RootChannel()
			if !HasPermission(rootChan, actor, MovePermission, []string{}) {
				client.sendPermissionDenied(actor, rootChan, MovePermission)
				return
			}

			// Only allow empty text.
			if len(comment) > 0 {
				client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TextTooLong)
				return
			}
		}

		filtered, err := server.FilterText(comment)
		if err != nil {
			client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TextTooLong)
			return
		}

		userstate.Comment = proto.String(filtered)
	}

	// Texture change
	if userstate.Texture != nil {
		maximg := server.cfg.MaxImageMessageLength
		if maximg > 0 && len(userstate.Texture) > maximg {
			client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TextTooLong)
			return
		}
	}

	// Registration
	if userstate.UserId != nil {
		// If user == actor, check for SelfRegisterPermission on root channel.
		// If user != actor, check for RegisterPermission permission on root channel.
		perm := Permission(RegisterPermission)
		if actor == target {
			perm = Permission(SelfRegisterPermission)
		}

		rootChan := server.RootChannel()
		if target.IsRegistered() || !HasPermission(rootChan, actor, perm, []string{}) {
			client.sendPermissionDenied(actor, rootChan, perm)
			return
		}

		if !target.HasCertificate() {
			client.sendPermissionDeniedTypeUser(mumbleproto.PermissionDenied_MissingCertificate, target)
			return
		}
	}

	// Prevent self-targetting state changes to be applied to other users
	// That is, if actor != user, then:
	//   Discard message if it has any of the following things set:
	//      - SelfDeaf
	//      - SelfMute
	//      - Texture
	//      - PluginContext
	//      - PluginIdentity
	//      - Recording
	if actor != target && (userstate.SelfDeaf != nil || userstate.SelfMute != nil ||
		userstate.Texture != nil || userstate.PluginContext != nil || userstate.PluginIdentity != nil ||
		userstate.Recording != nil) {
		panic("Invalid UserState") // Caught by incoming message hub
	}

	broadcast := false

	// TODO: Lots of things here

	// if userstate.Texture != nil {
	// 	key, err := blobStore.Put(userstate.Texture)
	// 	if err != nil {
	// 		server.Panicf("Blobstore error: %v", err)
	// 		return
	// 	}

	// 	if target.user.TextureBlob != key {
	// 		target.user.TextureBlob = key
	// 	} else {
	// 		userstate.Texture = nil
	// 	}

	// 	broadcast = true
	// }

	if userstate.SelfDeaf != nil {
		target.SelfDeaf = *userstate.SelfDeaf
		if target.SelfDeaf {
			userstate.SelfDeaf = proto.Bool(true)
			target.SelfMute = true
		}
		broadcast = true
	}

	if userstate.SelfMute != nil {
		target.SelfMute = *userstate.SelfMute
		if !target.SelfMute {
			userstate.SelfDeaf = proto.Bool(false)
			target.SelfDeaf = false
		}
	}

	if userstate.PluginContext != nil {
		target.PluginContext = userstate.PluginContext
	}

	if userstate.PluginIdentity != nil {
		target.PluginIdentity = *userstate.PluginIdentity
	}

	// if userstate.Comment != nil {
	// 	key, err := blobStore.Put([]byte(*userstate.Comment))
	// 	if err != nil {
	// 		server.Panicf("Blobstore error: %v", err)
	// 	}

	// 	if target.user.CommentBlob != key {
	// 		target.user.CommentBlob = key
	// 	} else {
	// 		userstate.Comment = nil
	// 	}

	// 	broadcast = true
	// }

	if userstate.Mute != nil || userstate.Deaf != nil || userstate.Suppress != nil || userstate.PrioritySpeaker != nil {
		if userstate.Deaf != nil {
			target.Deaf = *userstate.Deaf
			if target.Deaf {
				userstate.Mute = proto.Bool(true)
			}
		}
		if userstate.Mute != nil {
			target.Mute = *userstate.Mute
			if !target.Mute {
				userstate.Deaf = proto.Bool(false)
				target.Deaf = false
			}
		}
		if userstate.Suppress != nil {
			target.Suppress = *userstate.Suppress
		}
		if userstate.PrioritySpeaker != nil {
			target.PrioritySpeaker = *userstate.PrioritySpeaker
		}
		broadcast = true
	}

	if userstate.Recording != nil && *userstate.Recording != target.Recording {
		target.Recording = *userstate.Recording

		txtmsg := &mumbleproto.TextMessage{}
		txtmsg.TreeId = append(txtmsg.TreeId, uint32(0))
		if target.Recording {
			txtmsg.Message = proto.String(fmt.Sprintf("User '%s' started recording", target.ShownName()))
		} else {
			txtmsg.Message = proto.String(fmt.Sprintf("User '%s' stopped recording", target.ShownName()))
		}

		server.broadcastProtoMessageWithPredicate(txtmsg, func(client *Client) bool {
			return client.Version < 0x10203 && client != actor
		})

		broadcast = true
	}

	// userRegistrationChanged := false
	// if userstate.UserId != nil {
	// 	uid, err := server.RegisterClient(target)
	// 	if err != nil {
	// 		client.Printf("Unable to register: %v", err)
	// 		userstate.UserId = nil
	// 	} else {
	// 		userstate.UserId = proto.Uint32(uid)
	// 		client.user = server.Users[uid]
	// 		userRegistrationChanged = true
	// 	}
	// 	broadcast = true
	// }

	if userstate.ChannelId != nil {
		channel := server.GetChannel(int(*userstate.ChannelId))
		if channel != nil {
			server.userEnterChannel(target, channel, userstate)
			broadcast = true
		}
	}

	if userstate.ListeningChannelAdd != nil {
		for _, channelId := range userstate.ListeningChannelAdd {
			channel := server.GetChannel(int(channelId))
			if channel != nil && HasPermission(channel, client, ListenPermission, []string{}) {
				client.ListenChannel(channel)
			} else {
				client.sendPermissionDenied(client, channel, ListenPermission)
				return
			}
		}
		broadcast = true
	}

	if userstate.ListeningChannelRemove != nil {
		for _, channelId := range userstate.ListeningChannelRemove {
			channel := server.GetChannel(int(channelId))
			if channel != nil {
				client.UnlistenChannel(channel)
			}
		}
		broadcast = true
	}

	if broadcast {

		server.ClearVTCache()

		// This variable denotes the length of a zlib-encoded "old-style" texture.
		// Mumble and Murmur used qCompress and qUncompress from Qt to compress
		// textures that were sent over the wire. We can use this to determine
		// whether a texture is a "new style" or an "old style" texture.
		texture := userstate.Texture
		texlen := uint32(0)
		if texture != nil && len(texture) > 4 {
			texlen = uint32(texture[0])<<24 | uint32(texture[1])<<16 | uint32(texture[2])<<8 | uint32(texture[3])
		}
		if texture != nil && len(texture) > 4 && texlen != 600*60*4 {
			// The sent texture is a new-style texture.  Strip it from the message
			// we send to pre-1.2.2 clients.
			userstate.Texture = nil
			server.broadcastUserStateWithPredicate(userstate, func(client *Client) bool {
				return client.Version < 0x10202 && client.hasFullUserList
			})
			// Re-add it to the message, so that 1.2.2+ clients *do* get the new-style texture.
			userstate.Texture = texture
		} else {
			// Old style texture.  We can send the message as-is.
			server.broadcastUserStateWithPredicate(userstate, func(client *Client) bool {
				return client.Version < 0x10202 && client.hasFullUserList
			})
		}

		// If a texture hash is set on user, we transmit that instead of
		// the texture itself. This allows the client to intelligently fetch
		// the blobs that it does not already have in its local storage.
		// if userstate.Texture != nil && target.user != nil && target.user.HasTexture() {
		// 	userstate.Texture = nil
		// 	userstate.TextureHash = target.user.TextureBlobHashBytes()
		// } else if target.user == nil {
		// 	userstate.Texture = nil
		// 	userstate.TextureHash = nil
		// }

		// Ditto for comments.
		// if userstate.Comment != nil && target.user.HasComment() {
		// 	userstate.Comment = nil
		// 	userstate.CommentHash = target.user.CommentBlobHashBytes()
		// } else if target.user == nil {
		// 	userstate.Comment = nil
		// 	userstate.CommentHash = nil
		// }

		// if userRegistrationChanged {
		// 	server.ClearCaches()
		// }

		server.broadcastUserStateWithPredicate(userstate, func(client *Client) bool {
			return client.Version >= 0x10203 && client.hasFullUserList
		})
	}

	// if target.IsRegistered() {
	// 	// server.UpdateFrozenUser(target, userstate)
	// }
}

func (server *Server) handleBanListMessage(client *Client, msg *Message) {
	banlist := &mumbleproto.BanList{}
	err := proto.Unmarshal(msg.buf, banlist)
	if err != nil {
		panic(err) // Caught by incoming message hub
	}

	rootChan := server.RootChannel()
	if !HasPermission(rootChan, client, BanPermission, []string{}) {
		client.sendPermissionDenied(client, rootChan, BanPermission)
		return
	}

	if banlist.Query != nil && *banlist.Query != false {
		banlist.Reset()

		bans := server.GetAllBanList()

		for _, ban := range bans {
			entry := &mumbleproto.BanList_BanEntry{}
			entry.Address = ban.Address
			entry.Mask = proto.Uint32(uint32(ban.Mask))
			entry.Name = proto.String(ban.Name)
			entry.Hash = proto.String(ban.Hash)
			entry.Reason = proto.String(ban.Reason)
			entry.Start = proto.String(ban.ISOStartDate())
			entry.Duration = proto.Uint32(uint32(ban.Duration))
			banlist.Bans = append(banlist.Bans, entry)
		}
		if err := client.sendMessage(banlist); err != nil {
			panic(err) // Caught by incoming message hub
		}
	} else {
		var bans []Ban
		for _, entry := range banlist.Bans {
			ban := Ban{}
			ban.Address = entry.Address
			ban.Mask = int(*entry.Mask)
			if entry.Name != nil {
				ban.Name = *entry.Name
			}
			if entry.Hash != nil {
				ban.Hash = *entry.Hash
			}
			if entry.Reason != nil {
				ban.Reason = *entry.Reason
			}
			if entry.Start != nil {
				ban.SetISOStartDate(*entry.Start)
			}
			if entry.Duration != nil {
				ban.Duration = int(*entry.Duration)
			}
			bans = append(bans, ban)
		}

		server.OverrideBanList(bans)

		client.Printf("Banlist updated")
	}
}

// Broadcast text messages
func (server *Server) handleTextMessage(client *Client, msg *Message) {
	txtmsg := &mumbleproto.TextMessage{}
	err := proto.Unmarshal(msg.buf, txtmsg)
	if err != nil {
		panic(err) // Caught by incoming message hub
	}

	filtered, err := server.FilterText(*txtmsg.Message)
	if err != nil {
		client.sendPermissionDeniedType(mumbleproto.PermissionDenied_TextTooLong)
		return
	}

	if len(filtered) == 0 {
		return
	}

	txtmsg.Message = proto.String(filtered)

	clients := make(map[uint32]*Client)

	// Tree
	for _, chanid := range txtmsg.TreeId {
		if channel := server.GetChannel(int(chanid)); channel != nil {
			if !HasPermission(channel, client, TextMessagePermission, []string{}) {
				client.sendPermissionDenied(client, channel, TextMessagePermission)
				return
			}
			for _, target := range channel.Clients() {
				clients[target.Session()] = target
			}
		}
	}

	// Direct-to-channel
	for _, chanid := range txtmsg.ChannelId {
		if channel := server.GetChannel(int(chanid)); channel != nil {
			if !HasPermission(channel, client, TextMessagePermission, []string{}) {
				client.sendPermissionDenied(client, channel, TextMessagePermission)
				return
			}
			for _, target := range channel.Clients() {
				clients[target.Session()] = target
			}
		}
	}

	// Direct-to-clients
	for _, session := range txtmsg.Session {
		if target, ok := server.clients.Get(session); ok {
			if !HasPermission(target.Channel(), client, TextMessagePermission, []string{}) {
				client.sendPermissionDenied(client, target.Channel(), TextMessagePermission)
				return
			}
			clients[session] = target
		}
	}

	// Remove ourselves
	delete(clients, client.Session())

	for _, target := range clients {
		err := target.sendMessage(&mumbleproto.TextMessage{
			Actor:   proto.Uint32(client.Session()),
			Message: txtmsg.Message,
		})
		if err != nil {
			target.Panic(err.Error())
		}
	}
}

// ACL set/query
func (server *Server) handleACLMessage(client *Client, msg *Message) {
	pacl := &mumbleproto.ACL{}
	err := proto.Unmarshal(msg.buf, pacl)
	if err != nil {
		panic(err) // Caught by incoming message hub
	}

	// Look up the channel this ACL message operates on.
	channel := server.GetChannel(int(*pacl.ChannelId))
	if channel == nil {
		return
	}

	// Does the user have permission to update or look at ACLs?
	if !HasPermission(channel, client, WritePermission, []string{}) && !(channel.ParentID > -1 && HasPermission(channel.Parent(), client, WritePermission, []string{})) {
		client.sendPermissionDenied(client, channel, WritePermission)
		return
	}

	reply := &mumbleproto.ACL{}
	reply.ChannelId = proto.Uint32(uint32(channel.ID))

	channels := []*Channel{}
	users := map[int]bool{}

	// Query the current ACL state for the channel
	if pacl.Query != nil && *pacl.Query != false {
		reply.InheritAcls = proto.Bool(channel.InheritACL)
		// Walk the channel tree to get all relevant channels.
		// (Stop if we reach a channel that doesn't have the InheritACL flag set)
		iter := channel
		for iter != nil {
			channels = append([]*Channel{iter}, channels...)
			if (iter.ID == channel.ID || iter.InheritACL) && iter.ParentID > -1 {
				iter = iter.Parent()
			} else {
				iter = nil
			}
		}

		// Construct the protobuf ChanACL objects corresponding to the ACLs defined
		// in our channel list.
		reply.Acls = []*mumbleproto.ACL_ChanACL{}
		for _, iter := range channels {
			for _, chanacl := range iter.ACLs() {
				if iter.ID == channel.ID || chanacl.ApplySubs {
					mpacl := &mumbleproto.ACL_ChanACL{}
					mpacl.Inherited = proto.Bool(iter.ID != channel.ID)
					mpacl.ApplyHere = proto.Bool(chanacl.ApplyHere)
					mpacl.ApplySubs = proto.Bool(chanacl.ApplySubs)
					if chanacl.UserID >= 0 {
						mpacl.UserId = proto.Uint32(uint32(chanacl.UserID))
						users[chanacl.UserID] = true
					} else {
						mpacl.Group = proto.String(chanacl.Group)
					}
					mpacl.Grant = proto.Uint32(uint32(chanacl.Allow))
					mpacl.Deny = proto.Uint32(uint32(chanacl.Deny))
					reply.Acls = append(reply.Acls, mpacl)
				}
			}
		}

		// parent := channel.parent
		// allnames := channel.ACL.GroupNames() // TODO

		// Construct the protobuf ChanGroups that we send back to the client.
		// Also constructs a usermap that is a set user ids from the channel's groups.
		// reply.Groups = []*mumbleproto.ACL_ChanGroup{}

		if err := client.sendMessage(reply); err != nil {
			panic(err) // Caught by incoming message hub
		}

		// TODO
		// Map the user ids in the user map to usernames of users.
		// queryusers := &mumbleproto.QueryUsers{}
		// for uid, _ := range users {
		// 	user, ok := server.Users[uint32(uid)]
		// 	if !ok {
		// 		client.Printf("Invalid user id in ACL")
		// 		continue
		// 	}
		// 	queryusers.Ids = append(queryusers.Ids, uint32(uid))
		// 	queryusers.Names = append(queryusers.Names, user.Name)
		// }
		// if len(queryusers.Ids) > 0 {
		// 	client.sendMessage(queryusers)
		// }

	} else {
		// Set new groups and ACLs

		// Clear current ACLs and groups
		// acls = []ACL{}
		channel.ClearACL()
		// Add the received groups to the channel.
		channel.InheritACL = *pacl.InheritAcls
		// for _, pbgrp := range pacl.Groups {
		// 	// TODO
		// 	changroup := acl.EmptyGroupWithName(*pbgrp.Name)

		// 	changroup.Inherit = *pbgrp.Inherit
		// 	changroup.Inheritable = *pbgrp.Inheritable
		// 	for _, uid := range pbgrp.Add {
		// 		changroup.Add[int(uid)] = true
		// 	}
		// 	for _, uid := range pbgrp.Remove {
		// 		changroup.Remove[int(uid)] = true
		// 	}
		// 	if temp, ok := oldtmp[*pbgrp.Name]; ok {
		// 		changroup.Temporary = temp
		// 	}

		// 	channel.ACL.Groups[changroup.Name] = changroup
		// }
		// Add the received ACLs to the channel.
		for _, pbacl := range pacl.Acls {
			chanacl := ACL{}
			chanacl.ApplyHere = *pbacl.ApplyHere
			chanacl.ApplySubs = *pbacl.ApplySubs
			if pbacl.UserId != nil {
				chanacl.UserID = int(*pbacl.UserId)
			} else {
				chanacl.Group = *pbacl.Group
			}
			chanacl.Deny = Permission(*pbacl.Deny & AllPermissions)
			chanacl.Allow = Permission(*pbacl.Grant & AllPermissions)

			channel.AppendACL(&chanacl)
		}

		// Regular user?
		if !HasPermission(channel, client, WritePermission, []string{}) && (client.IsRegistered() || client.HasCertificate()) {
			chanacl := ACL{}
			chanacl.ApplyHere = true
			chanacl.ApplySubs = false
			if client.IsRegistered() {
				chanacl.UserID = client.UserId()
			} else if client.HasCertificate() {
				chanacl.Group = "$" + client.CertHash()
			}
			chanacl.Deny = Permission(NonePermission)
			chanacl.Allow = Permission(WritePermission | TraversePermission)

			channel.AppendACL(&chanacl)
		}

		server.refreshChannelPermission(channel)

		// Clear the Server's caches
		server.ClearCaches()

	}
}

// User query
func (server *Server) handleQueryUsers(client *Client, msg *Message) {
	query := &mumbleproto.QueryUsers{}
	err := proto.Unmarshal(msg.buf, query)
	if err != nil {
		panic(err) // Caught by incoming message hub
	}

	// server.Printf("in handleQueryUsers")

	reply := &mumbleproto.QueryUsers{}

	// TODO
	if server.userCache != nil {
		for _, id := range query.Ids {
			user, exists := server.userCache[strconv.Itoa(int(id))]
			if exists {
				reply.Ids = append(reply.Ids, id)
				reply.Names = append(reply.Names, user.Username)
			}
		}
	}

	// for _, name := range query.Names {
	// 	user, exists := server.UserNameMap[name]
	// 	if exists {
	// 		reply.Ids = append(reply.Ids, user.Id)
	// 		reply.Names = append(reply.Names, name)
	// 	}
	// }

	if err := client.sendMessage(reply); err != nil {
		panic(err) // Caught by incoming message hub
	}
}

// User stats message. Shown in the Mumble client when a
// user right clicks a user and selects 'User Information'.
func (server *Server) handleUserStatsMessage(client *Client, msg *Message) {
	stats := &mumbleproto.UserStats{}
	err := proto.Unmarshal(msg.buf, stats)
	if err != nil {
		panic(err) // Caught by incoming message hub
	}

	if stats.Session == nil {
		return
	}

	target, exists := server.clients.Get(*stats.Session)
	if !exists {
		client.sendMessage(&mumbleproto.UserRemove{
			Session: proto.Uint32(*stats.Session),
		})
		return
	}

	extended := false
	// If a client is requesting a UserStats from itself, serve it the whole deal.
	if client == target {
		extended = true
	}
	// Otherwise, only send extended UserStats for people with +register permissions
	// on the root channel.
	rootChan := server.RootChannel()
	if HasPermission(rootChan, client, RegisterPermission, []string{}) {
		extended = true
	}

	// If the client wasn't granted extended permissions, only allow it to query
	// users in channels it can enter.
	if !extended && !HasPermission(target.Channel(), client, EnterPermission, []string{}) {
		client.sendPermissionDenied(client, target.Channel(), EnterPermission)
		return
	}

	details := extended
	local := extended || target.channelID == client.channelID

	if stats.StatsOnly != nil && *stats.StatsOnly == true {
		details = false
	}

	stats.Reset()
	stats.Session = proto.Uint32(target.Session())

	if details {
		// Only consider client certificates for direct connections, not WebSocket connections.
		// We do not support TLS-level client certificates for WebSocket client.
		if tlsconn, ok := target.conn.(*tls.Conn); ok {
			state := tlsconn.ConnectionState()
			for i := len(state.PeerCertificates) - 1; i >= 0; i-- {
				stats.Certificates = append(stats.Certificates, state.PeerCertificates[i].Raw)
			}
			stats.StrongCertificate = proto.Bool(target.IsVerified())
		}
	}

	if local {
		fromClient := &mumbleproto.UserStats_Stats{}
		fromClient.Good = proto.Uint32(target.crypt.Good)
		fromClient.Late = proto.Uint32(target.crypt.Late)
		fromClient.Lost = proto.Uint32(target.crypt.Lost)
		fromClient.Resync = proto.Uint32(target.crypt.Resync)
		stats.FromClient = fromClient

		fromServer := &mumbleproto.UserStats_Stats{}
		fromServer.Good = proto.Uint32(target.crypt.RemoteGood)
		fromServer.Late = proto.Uint32(target.crypt.RemoteLate)
		fromServer.Lost = proto.Uint32(target.crypt.RemoteLost)
		fromServer.Resync = proto.Uint32(target.crypt.RemoteResync)
		stats.FromServer = fromServer
	}

	stats.UdpPackets = proto.Uint32(target.UDPPackets)
	stats.TcpPackets = proto.Uint32(target.TCPPackets)
	stats.UdpPingAvg = proto.Float32(target.UDPPingAvg)
	stats.UdpPingVar = proto.Float32(target.UDPPingVar)
	stats.TcpPingAvg = proto.Float32(target.TCPPingAvg)
	stats.TcpPingVar = proto.Float32(target.TCPPingVar)

	if details {
		version := &mumbleproto.Version{}
		version.Version = proto.Uint32(target.Version)
		if len(target.ClientName) > 0 {
			version.Release = proto.String(target.ClientName)
		}
		if len(target.OSName) > 0 {
			version.Os = proto.String(target.OSName)
			if len(target.OSVersion) > 0 {
				version.OsVersion = proto.String(target.OSVersion)
			}
		}
		stats.Version = version
		stats.CeltVersions = target.codecs
		stats.Opus = proto.Bool(target.opus)
		stats.Address = target.realip.IP
	}

	stats.Onlinesecs = proto.Uint32(uint32(time.Now().Unix() - target.LoginTime))
	stats.Idlesecs = proto.Uint32(uint32(time.Now().Unix() - target.LastActiveTime))

	// fixme(mkrautz): we don't do bandwidth tracking yet

	if err := client.sendMessage(stats); err != nil {
		panic(err) // Caught by incoming message hub
	}
}

// Voice target message
func (server *Server) handleVoiceTarget(client *Client, msg *Message) {
	vt := &mumbleproto.VoiceTarget{}
	err := proto.Unmarshal(msg.buf, vt)
	if err != nil {
		panic(err) // Caught by incoming message hub
	}

	if vt.Id == nil {
		return
	}

	id := *vt.Id
	if id < 1 || id >= 0x1f {
		return
	}

	if len(vt.Targets) == 0 {
		client.vtMutex.Lock()
		delete(client.voiceTargets, id)
		client.vtMutex.Unlock()
	}

	for _, target := range vt.Targets {
		newTarget := &VoiceTarget{}
		for _, session := range target.Session {
			newTarget.AddSession(session)
		}
		if target.ChannelId != nil {
			chanid := *target.ChannelId
			group := ""
			links := false
			subchannels := false
			if target.Group != nil {
				group = *target.Group
			}
			if target.Links != nil {
				links = *target.Links
			}
			if target.Children != nil {
				subchannels = *target.Children
			}
			newTarget.AddChannel(chanid, subchannels, links, group)
		}
		client.vtMutex.Lock()
		if newTarget.IsEmpty() {
			delete(client.voiceTargets, id)
		} else {
			client.voiceTargets[id] = newTarget
		}
		client.vtMutex.Unlock()
	}
}

// Permission query
func (server *Server) handlePermissionQuery(client *Client, msg *Message) {
	query := &mumbleproto.PermissionQuery{}
	err := proto.Unmarshal(msg.buf, query)
	if err != nil {
		panic(err) // Caught by incoming message hub
	}

	if query.GetFlush() {
		server.ClearCachesByUser(client)
	}

	if query.ChannelId != nil {
		channel := server.GetChannel(int(*query.ChannelId))
		server.sendClientPermissions(client, channel)
	}
}

// Request big blobs from the server
func (server *Server) handleRequestBlob(client *Client, msg *Message) {
	blobreq := &mumbleproto.RequestBlob{}
	err := proto.Unmarshal(msg.buf, blobreq)
	if err != nil {
		panic(err) // Caught by incoming message hub
	}

	// userstate := &mumbleproto.UserState{}

	// Request for user textures
	// if len(blobreq.SessionTexture) > 0 {
	// 	for _, sid := range blobreq.SessionTexture {
	// 		if target, ok := server.clients[sid]; ok {
	// 			if target.user == nil {
	// 				continue
	// 			}
	// 			if target.user.HasTexture() {
	// 				buf, err := blobStore.Get(target.user.TextureBlob)
	// 				if err != nil {
	// 					server.Panicf("Blobstore error: %v", err)
	// 					return
	// 				}
	// 				userstate.Reset()
	// 				userstate.Session = proto.Uint32(uint32(target.Session()))
	// 				userstate.Texture = buf
	// 				if err := client.sendMessage(userstate); err != nil {
	// 					client.Panic(err)
	// 					return
	// 				}
	// 			}
	// 		}
	// 	}
	// }

	// Request for user comments
	// if len(blobreq.SessionComment) > 0 {
	// 	for _, sid := range blobreq.SessionComment {
	// 		if target, ok := server.clients[sid]; ok {
	// 			if target.user == nil {
	// 				continue
	// 			}
	// 			if target.user.HasComment() {
	// 				buf, err := blobStore.Get(target.user.CommentBlob)
	// 				if err != nil {
	// 					server.Panicf("Blobstore error: %v", err)
	// 					return
	// 				}
	// 				userstate.Reset()
	// 				userstate.Session = proto.Uint32(uint32(target.Session()))
	// 				userstate.Comment = proto.String(string(buf))
	// 				if err := client.sendMessage(userstate); err != nil {
	// 					client.Panic(err)
	// 					return
	// 				}
	// 			}
	// 		}
	// 	}
	// }

	chanstate := &mumbleproto.ChannelState{}

	// Request for channel descriptions
	if len(blobreq.ChannelDescription) > 0 {
		for _, cid := range blobreq.ChannelDescription {
			if channel := server.GetChannel(int(cid)); channel != nil {
				if channel.HasDescription() {
					chanstate.Reset()
					buf, err := blobStore.Get(channel.DescriptionBlob)
					if err != nil {
						server.Printf("Blobstore error: %v", err)
						return
					}
					chanstate.ChannelId = proto.Uint32(uint32(channel.ID))
					chanstate.Description = proto.String(string(buf))
					if err := client.sendMessage(chanstate); err != nil {
						panic(err) // Caught by incoming message hub
					}
				}
			}
		}
	}
}

// User list query, user rename, user de-register
func (server *Server) handleUserList(client *Client, msg *Message) {
	userlist := &mumbleproto.UserList{}
	err := proto.Unmarshal(msg.buf, userlist)
	if err != nil {
		panic(err) // Caught by incoming message hub
	}

	// Only users who are allowed to register other users can access the user list.
	rootChan := server.RootChannel()
	if !HasPermission(rootChan, client, RegisterPermission, []string{}) {
		client.sendPermissionDenied(client, rootChan, RegisterPermission)
		return
	}

	// Query user list
	if len(userlist.Users) == 0 {
		// for uid, user := range server.Users {
		// 	if uid == 0 {
		// 		continue
		// 	}
		// 	userlist.Users = append(userlist.Users, &mumbleproto.UserList_User{
		// 		UserId: proto.Uint32(uid),
		// 		Name:   proto.String(user.Name),
		// 	})
		// }
		if err := client.sendMessage(userlist); err != nil {
			panic(err) // Caught by incoming message hub
		}
		// Rename, registration removal
	} else {
		// if len(userlist.Users) > 0 {
		// 	tx := server.freezelog.BeginTx()
		// 	for _, listUser := range userlist.Users {
		// 		uid := *listUser.UserId
		// 		if uid == 0 {
		// 			continue
		// 		}
		// 		user, ok := server.Users[uid]
		// 		if ok {
		// 			if listUser.Name == nil {
		// 				// De-register
		// 				server.RemoveRegistration(uid)
		// 				err := tx.Put(&freezer.UserRemove{Id: listUser.UserId})
		// 				if err != nil {
		// 					server.Fatal(err)
		// 				}
		// 			} else {
		// 				// Rename user
		// 				// todo(mkrautz): Validate name.
		// 				user.Name = *listUser.Name
		// 				err := tx.Put(&freezer.User{Id: listUser.UserId, Name: listUser.Name})
		// 				if err != nil {
		// 					server.Fatal(err)
		// 				}
		// 			}
		// 		}
		// 	}
		// 	err := tx.Commit()
		// 	if err != nil {
		// 		server.Fatal(err)
		// 	}
		// }
	}
}
