// Copyright (c) 2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"sort"
	"strings"
)

// A VoiceTarget holds information about a single
// VoiceTarget entry of a Client.
type VoiceTarget struct {
	sessions []uint32
	channels []voiceTargetChannel

	directCache       []*Client // map[uint32]*Client
	fromChannelsCache []*Client // map[uint32]*Client
}

type voiceTargetChannel struct {
	id          uint32
	subChannels bool
	links       bool
	onlyGroup   string
}

// AddSession Add's a client's session to the VoiceTarget
func (vt *VoiceTarget) AddSession(session uint32) {
	vt.sessions = append(vt.sessions, session)
}

// AddChannel adds a channel to the VoiceTarget.
// If subchannels is true, any sent voice packets will also be sent to all subchannels.
// If links is true, any sent voice packets will also be sent to all linked channels.
// If group is a non-empty string, any sent voice packets will only be broadcast to members
// of that group who reside in the channel (or its children or linked channels).
func (vt *VoiceTarget) AddChannel(id uint32, subchannels bool, links bool, group string) {
	vt.channels = append(vt.channels, voiceTargetChannel{
		id:          id,
		subChannels: subchannels,
		links:       links,
		onlyGroup:   group,
	})
}

// IsEmpty checks whether the VoiceTarget is empty (has no targets)
func (vt *VoiceTarget) IsEmpty() bool {
	return len(vt.sessions) == 0 && len(vt.channels) == 0
}

// ClearCache clears the VoiceTarget's cache.
func (vt *VoiceTarget) ClearCache() {
	vt.directCache = nil
	vt.fromChannelsCache = nil
}

func deduplicateChannelSlice(s []*Channel) []*Channel {
	if len(s) < 2 {
		return s
	}

	e := 1
	for i := 1; i < len(s); i++ {
		if s[i].ID == s[i-1].ID {
			continue
		}
		s[e] = s[i]
		e++
	}

	return s[:e]
}

func deduplicateClientSlice(s []*Client) []*Client {
	if len(s) < 2 {
		return s
	}

	e := 1
	for i := 1; i < len(s); i++ {
		if s[i].session == s[i-1].session {
			continue
		}
		s[e] = s[i]
		e++
	}

	return s[:e]
}

func filterClientSlice(s []*Client, f func(*Client) bool) []*Client {
	n := 0
	for _, x := range s {
		if f(x) {
			s[n] = x
			n++
		}

	}
	return s[:n]
}

// SendVoiceBroadcast Send the contents of the VoiceBroadcast to all targets specified in the
// VoiceTarget.
func (vt *VoiceTarget) SendVoiceBroadcast(vb *VoiceBroadcast) {
	buf := vb.buf
	client := vb.client
	server := client.server

	direct := vt.directCache
	fromChannels := vt.fromChannelsCache

	if direct == nil || fromChannels == nil {
		//direct = make(map[uint32]*Client)
		//fromChannels = make(map[uint32]*Client)
		direct = make([]*Client, 0, len(vt.sessions))
		fromChannels = make([]*Client, 0, server.clients.Len())

		for _, vtc := range vt.channels {
			channel := server.GetChannel(int(vtc.id))
			if channel == nil {
				continue
			}

			if !vtc.subChannels && !vtc.links && strings.TrimSpace(vtc.onlyGroup) == "" {
				if HasPermission(channel, client, WhisperPermission, []string{}) {
					// Non-Subchannel, Non-Link, Non-GroupSpecific
					//for _, target := range channel.Clients() {
					//	fromChannels[target.Session()] = target
					//}
					//fromChannels = append(fromChannels, channel.Clients()...)
					for _, target := range channel.Clients() {
						if target.session != client.session {
							fromChannels = append(fromChannels, target)
						}
					}

					//for _, target := range channel.GetListeners() {
					//	fromChannels[target.Session()] = target
					//}
					//fromChannels = append(fromChannels, channel.GetListeners()...)
					for _, target := range channel.GetListeners() {
						if target.session != client.session {
							fromChannels = append(fromChannels, target)
						}
					}
				}
			} else if channel.IsRoot() && vtc.subChannels {
				// Global Broadcast optimized
				newchans := server.AllChannels()

				for _, newchan := range newchans {
					clients := newchan.Clients()
					if len(clients) > 0 && HasPermission(&newchan, client, WhisperPermission, []string{}) {
						for _, target := range clients {
							if target.session == client.session {
								continue
							}
							if strings.TrimSpace(vtc.onlyGroup) == "" || (GroupMemberCheck(&newchan, &newchan, vtc.onlyGroup, target, []string{}) && !target.optBlockGroupShout) {
								//fromChannels[target.Session()] = target
								fromChannels = append(fromChannels, target)
							}
						}
					}
				}
			} else {
				// server.Printf("%v", vtc)
				// newchans := make(map[int]*Channel)
				newchans := make([]*Channel, 0, server.CountChannel())

				//newchans[channel.ID] = channel
				newchans = append(newchans, channel)
				if vtc.links {
					linkchans := channel.AllLinks()
					for _, v := range linkchans {
						// newchans[k] = v
						newchans = append(newchans, v)
					}
				}
				if vtc.subChannels {
					subchans := channel.AllSubChannels()
					for _, v := range subchans {
						// newchans[k] = v
						newchans = append(newchans, v)
					}
				}

				sort.Slice(newchans, func(i, j int) bool {
					return newchans[i].ID < newchans[j].ID
				})
				newchans = deduplicateChannelSlice(newchans)

				for _, newchan := range newchans {
					clients := newchan.Clients()
					if len(clients) > 0 && HasPermission(newchan, client, WhisperPermission, []string{}) {
						for _, target := range clients {
							if target.session == client.session {
								continue
							}
							if strings.TrimSpace(vtc.onlyGroup) == "" || (GroupMemberCheck(newchan, newchan, vtc.onlyGroup, target, []string{}) && !target.optBlockGroupShout) {
								// fromChannels[target.Session()] = target
								fromChannels = append(fromChannels, target)
							}
						}

						for _, target := range channel.GetListeners() {
							if target.session == client.session {
								continue
							}

							if strings.TrimSpace(vtc.onlyGroup) == "" || (GroupMemberCheck(newchan, newchan, vtc.onlyGroup, target, []string{}) && !target.optBlockGroupShout) {
								// fromChannels[target.Session()] = target
								fromChannels = append(fromChannels, target)
							}
						}
					}
				}
			}
		}

		for _, session := range vt.sessions {
			target, ok := server.clients.Get(session)
			if ok {
				if target.session != client.session {
					direct = append(direct, target)
				}
				//if _, alreadyInFromChannels := fromChannels[target.Session()]; !alreadyInFromChannels {
				//	direct[target.Session()] = target
				//}
			}
		}

		// Make sure we don't send to ourselves.
		//delete(direct, client.Session())
		//delete(fromChannels, client.Session())

		// deduplication
		sort.Slice(direct, func(i, j int) bool {
			return direct[i].Session() < direct[j].Session()
		})

		sort.Slice(fromChannels, func(i, j int) bool {
			return fromChannels[i].Session() < fromChannels[j].Session()
		})

		direct = deduplicateClientSlice(direct)
		fromChannels = deduplicateClientSlice(fromChannels)

		if vt.directCache == nil {
			vt.directCache = direct
		}

		if vt.fromChannelsCache == nil {
			vt.fromChannelsCache = fromChannels
		}
	}

	kind := buf[0] & 0xe0

	promiscUser := server.clients.SnapshotWithFilter(func(k uint32, c *Client) bool {
		return c.Session() != client.Session() && c.optPromiscuousMode
	}, 0.1)

	if len(fromChannels) > 0 {
		tclients := make([]*Client, 0, len(fromChannels))
		buf[0] = kind | 1
		for _, target := range fromChannels {
			if target.disconnected == false && target.Deaf == false && target.SelfDeaf == false {
				tclients = append(tclients, target)
				// go target.SendUDP(buf)
				// target.queueUDP(buf)
			}
		}

		if len(promiscUser) > 0 {
			for _, target := range promiscUser {
				if target.disconnected == false && target.Deaf == false && target.SelfDeaf == false {
					tclients = append(tclients, target)
					// target.queueUDP(buf)
				}
			}
		}

		server.QueueUDPBatch(buf, tclients)
	}

	if len(direct) > 0 {
		tclients := make([]*Client, 0, len(direct))
		buf[0] = kind | 2
		for _, target := range direct {
			if target.disconnected == false && target.Deaf == false && target.SelfDeaf == false {
				tclients = append(tclients, target)
				// go target.SendUDP(buf)
				// target.queueUDP(buf)
			}
		}

		if len(promiscUser) > 0 {
			for _, target := range promiscUser {
				if target.disconnected == false && target.Deaf == false && target.SelfDeaf == false {
					tclients = append(tclients, target)
					// target.queueUDP(buf)
				}
			}
		}

		server.QueueUDPBatch(buf, tclients)
	}
}

func (channel *Channel) SendUntargetedVoiceBroadcast(vb *VoiceBroadcast) {
	fromChannels := vb.client.untargetedCache
	if fromChannels == nil {
		newchans := channel.AllLinks()
		fromChannels = make(map[uint32]*Client)
		for _, newchan := range newchans {
			for _, target := range newchan.Clients() {
				fromChannels[target.Session()] = target
			}
		}
		for _, target := range channel.Clients() {
			fromChannels[target.Session()] = target
		}
		delete(fromChannels, vb.client.Session())
		if vb.client.untargetedCache == nil {
			vb.client.untargetedCache = fromChannels
		}
	}

	promiscUser := channel.server.clients.SnapshotWithFilter(func(k uint32, c *Client) bool {
		return c.Session() != vb.client.Session() && c.optPromiscuousMode
	}, 0.1)

	listeners := channel.GetListeners()

	tclients := make([]*Client, 0, len(fromChannels)+len(promiscUser)+len(listeners))

	if len(promiscUser) > 0 {
		for _, target := range promiscUser {
			if target.disconnected == false && target.Deaf == false && target.SelfDeaf == false {
				tclients = append(tclients, target)
				// target.queueUDP(vb.buf)
			}
		}
	}

	if len(fromChannels) > 0 {
		for _, target := range fromChannels {
			if target.disconnected == false && target.Deaf == false && target.SelfDeaf == false {
				tclients = append(tclients, target)
				// go target.SendUDP(vb.buf)
				// target.queueUDP(vb.buf)
			}
		}
	}

	if len(listeners) > 0 {
		for _, target := range listeners {
			if target.disconnected == false && target.Deaf == false && target.SelfDeaf == false {
				tclients = append(tclients, target)
				// target.queueUDP(vb.buf)
			}
		}
	}

	if len(tclients) > 0 {
		channel.server.QueueUDPBatch(vb.buf, tclients)
	}
}

func (channel *Channel) SendLocalVoiceBroadcast(vb *VoiceBroadcast) {
	promiscUser := channel.server.clients.SnapshotWithFilter(func(k uint32, c *Client) bool {
		return c.Session() != vb.client.Session() && c.optPromiscuousMode
	}, 0.1)

	listeners := channel.GetListeners()

	fromChannels := channel.Clients()

	tclients := make([]*Client, 0, len(fromChannels)+len(promiscUser)+len(listeners))

	if len(promiscUser) > 0 {
		for _, target := range promiscUser {
			if target.disconnected == false && target.Deaf == false && target.SelfDeaf == false {
				tclients = append(tclients, target)
				// target.queueUDP(vb.buf)
			}
		}
	}

	if len(fromChannels) > 0 {
		for _, target := range fromChannels {
			if target.disconnected == false && target.Deaf == false && target.SelfDeaf == false {
				tclients = append(tclients, target)
				// target.queueUDP(vb.buf)
			}
		}
	}

	if len(listeners) > 0 {
		for _, target := range listeners {
			if target.disconnected == false && target.Deaf == false && target.SelfDeaf == false {
				tclients = append(tclients, target)
				// target.queueUDP(vb.buf)
			}
		}
	}

	if len(tclients) > 0 {
		channel.server.QueueUDPBatch(vb.buf, tclients)
	}
}
