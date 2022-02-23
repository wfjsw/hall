// Copyright (c) 2010 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"encoding/hex"
	"errors"
	"fmt"

	errors2 "github.com/pkg/errors"
	"gorm.io/gorm"
)

// A Mumble channel
type Channel struct {
	server *Server `gorm:"-"`

	ID       int    `gorm:"AUTO_INCREMENT;PRIMARY_KEY"`
	Name     string `gorm:"NOT NULL"`
	Position int    `gorm:"NOT NULL;DEFAULT:0"`

	MaxUsers int `gorm:"NOT NULL;DEFAULT:0"`

	ParentID int `gorm:"NOT NULL;DEFAULT:0;INDEX:idx_channel_parentid"`
	// Parent   *Channel `gorm:"foreignkey:ParentID"`

	// ACLs       []*ACL `gorm:"foreignkey:ChannelId"`
	InheritACL bool `gorm:"NOT NULL;DEFAULT:1"`

	// Childrens []*Channel `gorm:"foreignkey:ParentId"`

	Links []*Channel `gorm:"many2many:channel_links"`

	DescriptionBlob string
	Managed         bool `gorm:"NOT NULL;DEFAULT:0"`
	// clients     map[uint32]*Client `gorm:"-"`
}

// Create a new channel
func (server *Server) NewChannel(name string) (channel *Channel) {
	channel = new(Channel)
	channel.server = server
	channel.Name = name
	server.db.Create(channel)
	return
}

// Get a existing channel
func (server *Server) GetChannel(id int) (channel *Channel) {
	if c, cached := server.channelCache.Get(id); cached {
		return c.(*Channel)
	}

	channel = new(Channel)
	if err := server.db.First(channel, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		} else {
			server.Panicf("Failed to get channel %d: %s", id, err)
		}
	}
	channel.server = server
	// Cache it
	server.channelCache.Add(id, channel)
	return
}

// Get All Channels
func (server *Server) AllChannels() (channels []Channel) {
	server.db.Find(&channels)
	for i := range channels {
		channels[i].server = server
		server.channelCache.Add(channels[i].ID, &channels[i])
	}

	return
}

// Get Parent Channel
func (channel *Channel) Parent() (parent *Channel) {
	if channel.ParentID < 0 {
		parent = nil
		return
	}
	parent = new(Channel)
	if channel.ParentID > -1 {
		if cachedParent, cached := channel.server.channelCache.Get(channel.ParentID); !cached {
			if err := channel.server.db.First(&parent, channel.ParentID).Error; err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
				channel.ParentID = 0
				channel.Save()
				channel.server.db.First(parent, 0)
			}
			channel.server.channelCache.Add(parent.ID, parent)
		} else {
			parent = cachedParent.(*Channel)
		}
	}
	parent.server = channel.server

	return
}

// Get Childrens
func (channel *Channel) Childrens() (channels []Channel) {
	// channels = new([]*Channel)
	channel.server.db.Where("parent_id = ?", channel.ID).Find(&channels)
	for i := range channels {
		channels[i].server = channel.server
		// channel.server.channelCache.Add(i, channels[i])
	}
	return
}

// Get ACLs
func (channel *Channel) ACLs() (acls []*ACL) {
	// acls = new([]*ACL)
	if cachedAcls, cached := channel.server.aclStoreCache.Get(channel.ID); !cached {
		channel.server.db.Where("channel_id = ?", channel.ID).Order("id asc").Find(&acls)
		channel.server.aclStoreCache.Add(channel.ID, &acls)
	} else {
		acls = *cachedAcls.(*[]*ACL)
	}
	return
}

func (channel *Channel) GetLinks() (channels []Channel) {
	// channels = new([]*Channel)

	if cachedLinks, cached := channel.server.channelCache.Get(fmt.Sprintf("links:%d", channel.ID)); !cached {
		err := channel.server.db.Model(channel).Association("Links").Find(&channels)
		if err != nil {
			channel.server.Debugf("%+v", errors2.Wrap(err, "Failed to fetch links"))
			return
		}
		channel.server.channelCache.Add(fmt.Sprintf("links:%d", channel.ID), &channels)
	} else {
		channels = *cachedLinks.(*[]Channel)
	}

	for i := range channels {
		channels[i].server = channel.server
		// channel.server.channelCache.Add(i, channels[i])
	}
	// channel.server.db.Model(channel).Association("Links").Find(&channels)
	return
}

// CountChannels
func (server *Server) CountChannel() (count int64) {
	server.db.Model(&Channel{}).Count(&count)
	return
}

// SetParent set channel's parent
func (channel *Channel) SetParent(parent *Channel) {
	channel.server.db.Model(channel).Update("parent_id", parent.ID)
	channel.server.channelCache.Purge()
}

// AddClient, removeclient

// assignClient adds client to the channel
func (channel *Channel) assignClient(client *Client) {
	client.channelID = channel.ID
	client.channel = channel
}

// Clients Get Clients
func (channel *Channel) Clients() []*Client {
	return channel.server.clients.SnapshotWithFilter(func(k uint32, c *Client) bool {
		return c.state == StateClientReady && c.channelID == channel.ID
	}, 1)
}

func (channel *Channel) ClientsMap() map[uint32]*Client {
	return channel.server.clients.SnapshotMapWithFilter(func(k uint32, c *Client) bool {
		return c.state == StateClientReady && c.channelID == channel.ID
	}, 1)

}

// Save channel to database
func (channel *Channel) Save() {
	channel.server.db.Save(channel)
	channel.server.channelCache.Purge()
}

// HasDescription Does the channel have a description?
func (channel *Channel) HasDescription() bool {
	return len(channel.DescriptionBlob) > 0
}

// DescriptionBlobHashBytes gets the channel's blob hash as a byte slice for sending via a protobuf message.
// Returns nil if there is no blob.
func (channel *Channel) DescriptionBlobHashBytes() (buf []byte) {
	buf, err := hex.DecodeString(channel.DescriptionBlob)
	if err != nil {
		return nil
	}
	return buf
}

// AllLinks returns a slice of all channels in this channel's
// link chain.
func (channel *Channel) AllLinks() (seen map[int]*Channel) {
	if cachedAllLinks, cached := channel.server.channelCache.Get(fmt.Sprintf("all_links:%d", channel.ID)); !cached {
		seen = make(map[int]*Channel)
		walk := []*Channel{channel}
		for len(walk) > 0 {
			current := walk[len(walk)-1]
			walk = walk[0 : len(walk)-1]
			for _, linked := range current.GetLinks() {
				if _, alreadySeen := seen[linked.ID]; !alreadySeen {
					seen[linked.ID] = &linked
					walk = append(walk, &linked)
				}
			}
		}
		channel.server.channelCache.Add(fmt.Sprintf("all_links:%d", channel.ID), &seen)
	} else {
		seen = *cachedAllLinks.(*map[int]*Channel)
	}

	return
}

// AllSubChannels returns a slice of all of this channel's subchannels.
func (channel *Channel) AllSubChannels() (seen map[int]*Channel) {
	if cachedAllSubs, cached := channel.server.channelCache.Get(fmt.Sprintf("all_subs:%d", channel.ID)); !cached {
		seen = make(map[int]*Channel)
		walk := []*Channel{}
		if len(channel.Childrens()) > 0 {
			walk = append(walk, channel)
			for len(walk) > 0 {
				current := walk[len(walk)-1]
				walk = walk[0 : len(walk)-1]
				for _, child := range current.Childrens() {
					if _, alreadySeen := seen[child.ID]; !alreadySeen {
						seen[child.ID] = &child
						walk = append(walk, &child)
					}
				}
			}
		}
		channel.server.channelCache.Add(fmt.Sprintf("all_subs:%d", channel.ID), &seen)
	} else {
		seen = *cachedAllSubs.(*map[int]*Channel)
	}
	return
}

// IsTemporary checks whether the channel is temporary
func (channel *Channel) IsTemporary() bool {
	// return channel.temporary
	return false
}

// IsEmpty checks whether the channel is empty
func (channel *Channel) IsEmpty() bool {
	return len(channel.Clients()) == 0
}

// IsRoot check whether the channel is the root channel
func (channel *Channel) IsRoot() bool {
	return channel.ParentID == -1
}

// RemoveChanel removes a channel from the server.
func (channel *Channel) RemoveChannel() {
	if channel.ID == 0 {
		channel.server.Printf("Attempted to remove root channel.")
		return
	}
	for _, linkedChannel := range channel.GetLinks() {
		channel.server.UnlinkChannels(channel, &linkedChannel)
	}
	channel.server.db.Delete(&channel)
}

// Link two channels
func (server *Server) LinkChannels(channel *Channel, other *Channel) {
	err := server.db.Model(channel).Association("Links").Append(other)
	if err != nil {
		return
	}
	err = server.db.Model(other).Association("Links").Append(channel)
	if err != nil {
		return
	}
}

// Unlink two channels
func (server *Server) UnlinkChannels(channel *Channel, other *Channel) {
	err := server.db.Model(channel).Association("Links").Delete(other)
	if err != nil {
		return
	}
	err = server.db.Model(other).Association("Links").Delete(channel)
	if err != nil {
		return
	}
}

func (channel *Channel) AppendACL(acl *ACL) {
	acl.ChannelID = channel.ID
	channel.server.db.Save(acl)
	channel.server.clearACLStoreCache()
}

func (channel *Channel) RemoveACL(acl *ACL) {
	channel.server.db.Delete(acl)
	channel.server.clearACLStoreCache()
}

func (channel *Channel) ClearACL() {
	channel.server.db.Exec("DELETE FROM acls WHERE channel_id = ?", channel.ID)
	channel.server.clearACLStoreCache()
}

func (channel *Channel) GetListeners() []*Client {
	return channel.server.clients.SnapshotWithFilter(func(k uint32, c *Client) bool {
		if c.state != StateClientReady {
			return false
		}
		c.listenMutex.RLock()
		defer c.listenMutex.RUnlock()
		for _, ch := range c.listens {
			if ch.ID == channel.ID {
				return true
			}
		}
		return false
	}, 1)
}
