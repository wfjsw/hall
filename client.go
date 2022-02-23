// Copyright (c) 2010-2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gorm.io/gorm"

	"github.com/wfjsw/hall/cryptstate"
	"github.com/wfjsw/hall/mumbleproto"
	"github.com/wfjsw/hall/packetdata"
	"google.golang.org/protobuf/proto"
)

type waitableMessage struct {
	wg  *sync.WaitGroup
	msg interface{}
}

// Client A client connection
type Client struct {
	// Logging
	*log.Logger
	lf *clientLogForwarder

	// Connection-related
	laddr   net.IP
	tcpaddr *net.TCPAddr
	udpaddr *net.UDPAddr
	realip  *net.TCPAddr
	conn    net.Conn
	udpconn net.Conn
	reader  *bufio.Reader
	state   int
	server  *Server

	geoipCache *GeoIPResult

	hasFullUserList bool

	outgoingMessageQueue chan *waitableMessage
	udpsend              chan []byte
	udprecv              chan []byte

	disconnected   bool
	disconnectOnce sync.Once

	lastResync      int64
	crypt           cryptstate.CryptState
	codecs          []int32
	opus            bool
	udp             bool
	unstableUDP     bool
	voiceTargets    map[uint32]*VoiceTarget
	untargetedCache map[uint32]*Client
	vtMutex         sync.RWMutex

	// Ping stats
	UDPPingAvg      float32
	UDPPingVar      float32
	UDPPackets      uint32
	UDPTotalPackets uint64
	UDPVolume       uint64
	TCPPingAvg      float32
	TCPPingVar      float32
	TCPTotalPackets uint64
	TCPPackets      uint32
	TCPVolume       uint64
	statsMutex      sync.Mutex

	LoginTime      int64
	LastActiveTime int64
	LastPing       int64

	// Runtime Options
	optBlockGroupShout bool
	optPromiscuousMode bool

	// If the client is a registered user on the server,
	// the user field will point to the registration record.
	// user *User
	groups []string

	// The clientReady channel signals the client's receiever routine that
	// the client has been successfully authenticated and that it has been
	// sent the necessary information to be a participant on the server.
	// When this signal is received, the client has transitioned into the
	// 'ready' state.
	// clientReady chan bool

	// Version
	Version    uint32
	ClientName string
	OSName     string
	OSVersion  string
	CryptoMode string

	// Personal
	userID   uint32
	Username string
	Password string // used to reverify
	session  uint32
	certHash string
	tokens   []string
	// Channel         *Channel
	channelID       int
	channel         *Channel
	SelfMute        bool
	SelfDeaf        bool
	Mute            bool
	Deaf            bool
	Suppress        bool
	PrioritySpeaker bool
	Recording       bool
	PluginContext   []byte
	PluginIdentity  string

	listenMutex sync.RWMutex
	listens     []*Channel
}

type UserLastChannel struct {
	ID          uint32 `gorm:"PRIMARY_KEY"`
	LastChannel int
}

func (client *Client) GetLastChannel() (channelID int) {
	if !client.IsRegistered() {
		return 0
	}
	ulc := new(UserLastChannel)
	if err := client.server.db.First(&ulc, client.userID).Error; err != nil && errors.Is(err, gorm.ErrRecordNotFound) {
		client.server.db.Create(&UserLastChannel{
			ID:          client.userID,
			LastChannel: 0,
		})
		return 0
	}
	return ulc.LastChannel
}

func (client *Client) SetLastChannel(channelID int) {
	if !client.IsRegistered() {
		return
	}
	ulc := &UserLastChannel{
		ID:          client.userID,
		LastChannel: channelID,
	}
	client.server.db.Save(ulc)
}

func (client *Client) assignChannel(channel *Channel) {
	client.channelID = channel.ID
	client.channel = channel
}

// MoveChannel Move client into channel
func (client *Client) MoveChannel(channel *Channel, actor *Client) {

	if client.channelID == channel.ID {
		// No-OP
		return
	}

	userstate := &mumbleproto.UserState{}
	userstate.Session = proto.Uint32(client.Session())
	userstate.ChannelId = proto.Uint32(uint32(channel.ID))
	if actor != nil {
		userstate.Actor = proto.Uint32(actor.Session())
	}
	client.server.userEnterChannel(client, channel, userstate) // Note: panicable
	client.server.broadcastUserState(userstate)
}

// Debugf implements debug-level printing for Clients.
func (client *Client) Debugf(format string, v ...interface{}) {
	if client.server.cfg.Debug {
		client.Printf(format, v...)
	}
}

// IsRegistered Is the client a registered user?
func (client *Client) IsRegistered() bool {
	return client.UserId() > 0
	// return true // TODO: what if false?
}

// HasCertificate Does the client have a certificate?
func (client *Client) HasCertificate() bool {
	return len(client.certHash) > 0
}

// IsSuperUser Is the client the SuperUser?
func (client *Client) IsSuperUser() bool {
	// if client.user == nil {
	// 	return false
	// }
	// return client.user.Id == 0
	// MOCK:
	// return true
	return client.InGroup("admin")
}

func (client *Client) CertHash() string {
	return client.certHash
}

func (client *Client) Session() uint32 {
	return client.session
}

func (client *Client) Tokens() []string {
	return client.tokens
}

func (client *Client) Groups() []string {
	return client.groups
}

func (client *Client) InGroup(name string) bool {
	for _, group := range client.Groups() {
		if name == group {
			return true
		}
	}
	return false
}

func (client *Client) Channel() (channel *Channel) {
	if client.channel != nil {
		// UNSAFE: primitives may not be latest

		return client.channel
	}
	if channel = client.server.GetChannel(client.channelID); channel == nil {
		client.channelID = 0
		channel = client.server.GetChannel(0)
	}
	client.channel = channel
	return
}

// UserId gets the User ID of this client.
// Returns -1 if the client is not a registered user.
func (client *Client) UserId() int {
	return int(client.userID)
}

// ShownName gets the client's shown name.
func (client *Client) ShownName() string {
	// TODO
	// if client.IsSuperUser() {
	// 	return "SuperUser"
	// }
	// if client.IsRegistered() {
	// 	return client.user.Name
	// }
	return client.Username
}

// IsVerified checks whether the client's certificate is
// verified.
func (client *Client) IsVerified() bool {
	tlsconn := client.conn.(*tls.Conn)
	state := tlsconn.ConnectionState()
	return len(state.VerifiedChains) > 0
}

func (client *Client) GeoIP() (*GeoIPResult, error) {
	if client.geoipCache == nil {
		geoip, err := lookupIPAddress(client.realip.IP)
		if err != nil {
			return nil, err
		}
		client.geoipCache = geoip
		return geoip, nil
	} else {
		return client.geoipCache, nil
	}
}

// Log a panic and disconnect the client.
func (client *Client) Panic(v ...interface{}) {
	client.Print(v...)
	client.Disconnect()
}

// Log a formatted panic and disconnect the client.
func (client *Client) Panicf(format string, v ...interface{}) {
	client.Printf(format, v...)
	client.Disconnect()
}

// recover client thread from panic
func (client *Client) recover(wg *sync.WaitGroup) {
	if err := recover(); err != nil {
		if wg != nil {
			wg.Done()
		}
		ignore := false
		switch err.(type) {
		case error:
			if strings.Contains(err.(error).Error(), "Client is dead") || strings.Contains(err.(error).Error(), "io: read/write on closed pipe") {
				ignore = true
			}
			if strings.Contains(err.(error).Error(), "use of closed connection") || strings.Contains(err.(error).Error(), "io: read/write on closed pipe") {
				ignore = true
			}
		}
		if !ignore {
			client.Printf("panic: %v", err)
		}
		go client.Disconnect()
	}
}

// Internal disconnect function
func (client *Client) disconnect(kicked bool) {

	client.disconnected = true

	// Close the client's UDP receiever goroutine.
	if client.udprecv != nil {
		close(client.udprecv)
		// drain the channel to prevent deadlock
		for range client.udprecv {
			continue
		}
		// client.udprecv = nil
	}

	if client.udpsend != nil {
		close(client.udpsend)
		for range client.udpsend {
			continue
		}
		// client.udpsend = nil
	}

	if client.outgoingMessageQueue != nil {
		close(client.outgoingMessageQueue)

		// drain the channel to prevent deadlock
		for m := range client.outgoingMessageQueue {
			if m.wg != nil {
				m.wg.Done()
			}
		}

		// client.outgoingMessageQueue = nil
	}

	_ = client.conn.SetDeadline(time.Now().Add(1 * time.Second))
	_ = client.conn.Close()

	client.server.RemoveClient(client, kicked)

	client.Printf("Disconnected")
	client.state = StateClientDead

	if client.server.running {
		go client.server.updateCodecVersions(nil)
	}
}

// Disconnect Disconnect a client (client requested or server shutdown)
func (client *Client) Disconnect() {
	client.disconnectOnce.Do(func() { client.disconnect(false) })
}

// ForceDisconnect Disconnect a client (kick/ban)
func (client *Client) ForceDisconnect() {
	client.disconnectOnce.Do(func() { client.disconnect(true) })
}

// ClearCaches clears the client's caches
func (client *Client) ClearCaches() {
	client.vtMutex.RLock()
	client.untargetedCache = nil
	for _, vt := range client.voiceTargets {
		vt.ClearCache()
	}
	client.vtMutex.RUnlock()
}

// Reject an authentication attempt
func (client *Client) RejectAuth(rejectType mumbleproto.Reject_RejectType, reason string) {
	var reasonString *string = nil
	if len(reason) > 0 {
		client.Print(reason)
		reasonString = proto.String(reason)
	}

	_ = client.sendMessage(&mumbleproto.Reject{
		Type:   rejectType.Enum(),
		Reason: reasonString,
	})

	client.ForceDisconnect()
}

// Read a protobuf message from a client
func (client *Client) readProtoMessage() (msg *Message, err error) {
	var (
		length uint32
		kind   uint16
	)

	err = client.conn.SetReadDeadline(time.Now().Add(time.Duration(client.server.cfg.Timeout) * time.Second))
	if err != nil {
		return nil, err
	}

	// Read the message type (16-bit big-endian unsigned integer)
	err = binary.Read(client.reader, binary.BigEndian, &kind)
	if err != nil {
		return
	}

	// Read the message length (32-bit big-endian unsigned integer)
	err = binary.Read(client.reader, binary.BigEndian, &length)
	if err != nil {
		return
	}

	if length > 10000000 {
		client.server.tempIPBan.Add(client.realip.IP.String(), time.Now().Unix())
		return nil, errors.New("oversized protobuf message detected")
	}

	buf := make([]byte, length)
	_, err = io.ReadFull(client.reader, buf)
	if err != nil {
		return
	}

	err = client.conn.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, err
	}

	msg = &Message{
		buf:    buf,
		kind:   kind,
		client: client,
	}

	return
}

// Send permission denied by type
func (c *Client) sendPermissionDeniedType(denyType mumbleproto.PermissionDenied_DenyType) {
	c.sendPermissionDeniedTypeUser(denyType, nil)
}

// Send permission denied by type (and user)
func (c *Client) sendPermissionDeniedTypeUser(denyType mumbleproto.PermissionDenied_DenyType, user *Client) {
	pd := &mumbleproto.PermissionDenied{
		Type: denyType.Enum(),
	}
	if user != nil {
		pd.Session = proto.Uint32(user.Session())
	}
	err := c.sendMessage(pd)
	if err != nil {
		c.Panic(err)
		return
	}
}

// Send permission denied by who, what, where
func (c *Client) sendPermissionDenied(who *Client, where *Channel, what Permission) {
	pd := &mumbleproto.PermissionDenied{
		Permission: proto.Uint32(uint32(what)),
		ChannelId:  proto.Uint32(uint32(where.ID)),
		Session:    proto.Uint32(who.Session()),
		Type:       mumbleproto.PermissionDenied_Permission.Enum(),
	}
	err := c.sendMessage(pd)
	if err != nil {
		c.Panic(err)
		return
	}
}

// Send permission denied fallback
func (client *Client) sendPermissionDeniedFallback(denyType mumbleproto.PermissionDenied_DenyType, version uint32, text string) {
	pd := &mumbleproto.PermissionDenied{
		Type: denyType.Enum(),
	}
	if client.Version < version {
		pd.Reason = proto.String(text)
	}
	err := client.sendMessage(pd)
	if err != nil {
		panic(err) // Caught by incoming message hub
	}
}

// Send permission denied text
func (client *Client) sendPermissionDeniedText(text string) {
	pd := &mumbleproto.PermissionDenied{
		Type:   mumbleproto.PermissionDenied_Text.Enum(),
		Reason: proto.String(text),
	}
	err := client.sendMessage(pd)
	if err != nil {
		panic(err) // Caught by incoming message hub
	}
}

// UDP send loop
func (client *Client) udpSendLoop() {
	defer client.recover(nil)

	for packet := range client.udpsend {
		client.SendUDP(packet, false)
	}
}

// UDP receive loop
func (client *Client) udpRecvLoop() {
	// GOROUTINE START
	defer client.recover(nil)

	for buf := range client.udprecv {
		client.handleUDPPacket(buf)
	}
}

func (client *Client) handleUDPPacket(buf []byte) {
	defer client.recover(nil)

	if client.disconnected || client.state == StateClientDead {
		return
	}

	kind := (buf[0] >> 5) & 0x07

	if kind == mumbleproto.UDPMessagePing {
		client.SendUDP(buf, true)
		// client.queueUDP(buf)
		// xmitBuf.Put(buf)
		return
	}

	if client.state == StateClientReady {
		switch kind {
		case mumbleproto.UDPMessageVoiceSpeex:
			fallthrough
		case mumbleproto.UDPMessageVoiceCELTAlpha:
			fallthrough
		case mumbleproto.UDPMessageVoiceCELTBeta:
			if client.server.Opus {
				return
			}
			fallthrough
		case mumbleproto.UDPMessageVoiceOpus:
			target := buf[0] & 0x1f
			var counter uint8
			// outbuf := make([]byte, 1024)
			outbuf := (*(xmitBuf.Get().(*[]byte)))[:1024]

			incoming := packetdata.New(buf[1 : 1+(len(buf)-1)])
			outgoing := packetdata.New(outbuf[1 : 1+(len(outbuf)-1)])
			_ = incoming.GetUint32()

			if kind != mumbleproto.UDPMessageVoiceOpus {
				for {
					counter = incoming.Next8()
					incoming.Skip(int(counter & 0x7f))
					if !((counter&0x80) != 0 && incoming.IsValid()) {
						break
					}
				}
			} else {
				size := int(incoming.GetUint16())
				incoming.Skip(size & 0x1fff)
			}

			outgoing.PutUint32(client.Session())
			outgoing.PutBytes(buf[1 : 1+(len(buf)-1)])
			outbuf[0] = buf[0] & 0xe0 // strip target

			if target != 0x1f { // VoiceTarget

				client.LastActiveTime = time.Now().Unix()

				client.server.routeVoiceBroadcast(&VoiceBroadcast{
					client: client,
					buf:    outbuf[0 : 1+outgoing.Size()],
					target: target,
				})
			} else { // Server loopback
				client.queueUDP(outbuf[0 : 1+outgoing.Size()])
			}

			xmitBuf.Put(&buf)
		}
	}

}

func (client *Client) queueMessage(msg *waitableMessage) {
	defer client.recover(msg.wg) // Decrease the counter in case of exception
	client.outgoingMessageQueue <- msg
	return
}

// Queue UDP packet into server's UDP send queue
func (client *Client) queueUDP(buf []byte) {
	defer client.recover(nil)
	client.udpsend <- buf
}

func (client *Client) createUDPPacket(buf []byte, dst []byte) {
	// length = len(buf) + client.crypt.Overhead()
	// // out = make([]byte, length)
	client.crypt.Encrypt(dst, buf)
	return
}

// Send buf as a UDP message. If the client does not have
// an established UDP connection, the datagram will be tunelled
// through the client's control channel (TCP).
func (client *Client) SendUDP(buf []byte, force bool) {
	defer client.recover(nil)
	defer xmitBuf.Put(&buf)

	if force || (client.udp && !client.unstableUDP) {
		// crypted := make([]byte, len(buf)+client.crypt.Overhead())
		// client.crypt.Encrypt(crypted, buf)
		packetLen := len(buf) + client.crypt.Overhead()
		crypted := (*(xmitBuf.Get().(*[]byte)))[:packetLen]
		defer xmitBuf.Put(&crypted)
		client.createUDPPacket(buf, crypted)
		err := client.server.SendUDP(crypted, client.udpaddr, client.laddr)
		if err != nil {
			client.udp = false
		}
	} else {
		err := client.sendMessage(buf)
		if err != nil {
			panic(err) // Caught by this function
		}
	}
}

// Send a Message to the client.  The Message in msg to the client's
// buffered writer and flushes it when done.
//
// This method should only be called from within the client's own
// sender goroutine, since it serializes access to the underlying
// buffered writer.
func (client *Client) sendMessage(msg interface{}) error {
	if client.disconnected && client.state >= StateClientDead {
		return errors.New("client is dead")
	}

	buf := new(bytes.Buffer)
	var (
		kind    uint16
		msgData []byte
		err     error
	)

	kind = mumbleproto.MessageType(msg)
	if kind == mumbleproto.MessageUDPTunnel {
		msgData = msg.([]byte)
	} else {
		protoMsg, ok := (msg).(proto.Message)
		if !ok {
			return errors.New("client: expected a proto.Message")
		}
		msgData, err = proto.Marshal(protoMsg)
		if err != nil {
			return err
		}
	}

	err = binary.Write(buf, binary.BigEndian, kind)
	if err != nil {
		return err
	}
	err = binary.Write(buf, binary.BigEndian, uint32(len(msgData)))
	if err != nil {
		return err
	}
	_, err = buf.Write(msgData)
	if err != nil {
		return err
	}

	if client.disconnected && client.state >= StateClientDead {
		return errors.New("client is dead")
	}

	_ = client.conn.SetWriteDeadline(time.Now().Add(time.Duration(client.server.cfg.Timeout) * time.Second))
	_, err = client.conn.Write(buf.Bytes())
	_ = client.conn.SetWriteDeadline(time.Time{})
	if err != nil {
		return err
	}

	return nil
}

func strLimit(str string, cap int) string {
	if len(str) > cap {
		return str[:cap]
	} else {
		return str
	}
}

// TLS receive loop
func (client *Client) tlsRecvLoop() {
	defer client.recover(nil)

	for {
		if client.disconnected {
			return
		}

		// The client has just connected. Before it sends its authentication
		// information we must send it our version information so it knows
		// what version of the protocol it should speak.
		if client.state == StateClientConnected {
			version := &mumbleproto.Version{
				// CryptoModes: cryptstate.SupportedModes(),
			}
			if client.server.cfg.SendVersion {
				version.Version = proto.Uint32(uint32(verProtover))
			}
			if client.server.cfg.SendBuildInfo {
				version.Release = proto.String(fmt.Sprintf("%s %s", verRelease, VERSION))
				version.Os = proto.String(runtime.GOOS)
				version.OsVersion = proto.String("Unknown")
			}
			err := client.sendMessage(version)
			if err != nil {
				panic(err) // Caught by this function
			}
			client.state = StateServerSentVersion
			continue
		}

		msg, err := client.readProtoMessage()
		if err != nil {
			if err == io.EOF || strings.Contains(err.Error(), "use of closed network connection") || strings.Contains(err.Error(), "connection reset by peer") {
				client.Disconnect()
				return
			} else {
				panic(err) // Caught by this function
			}
		}

		atomic.AddUint64(&client.TCPTotalPackets, 1)
		atomic.AddUint64(&client.TCPVolume, uint64(len(msg.buf)))

		// Always deal with pings with highest priority.
		if msg.kind == mumbleproto.MessagePing {
			go client.server.handlePingMessage(client, msg)
		} else if client.state == StateServerSentVersion && msg.kind == mumbleproto.MessageVersion {
			version := &mumbleproto.Version{}
			err = proto.Unmarshal(msg.buf, version)
			if err != nil {
				panic(err) // Caught by this function
			}

			if version.Version != nil {
				client.Version = *version.Version
			} else {
				client.Version = 0x10200
			}

			// https://github.com/mumble-voip/mumble/pull/4101#issuecomment-619146743

			if version.Release != nil {
				client.ClientName = strLimit(*version.Release, 100)
			}

			if version.Os != nil {
				client.OSName = strLimit(*version.Os, 40)
			}

			if version.OsVersion != nil {
				client.OSVersion = strLimit(*version.OsVersion, 60)
			}

			// CHANGE: MinClientVersion

			if client.server.cfg.MinClientVersion > 0 {
				if uint32(client.server.cfg.MinClientVersion) > client.Version {
					client.RejectAuth(mumbleproto.Reject_WrongVersion, trnVersionTooOld)
					continue
				}
			}

			// CHANGE: MaxUsers

			if client.server.cfg.MaxUsers > 0 {
				if client.server.clients.Len() >= client.server.cfg.MaxUsers {
					client.RejectAuth(mumbleproto.Reject_ServerFull, trnServerIsFull)
					continue
				}
			}

			// CHANGE: RequireClientPlatformInfo

			if client.server.cfg.RequireClientPlatformInfo {
				if version.Os == nil || version.OsVersion == nil {
					client.RejectAuth(mumbleproto.Reject_None, trnPlatformInfoMissing)
					continue
				}
			}

			// Extract the client's supported crypto mode.
			// If the client does not pick a crypto mode
			// itself, use an invalid mode (the empty string)
			// as its requested mode. This is effectively
			// a flag asking for the default crypto mode.
			// requestedMode := ""
			// if len(version.CryptoModes) > 0 {
			// 	requestedMode = version.CryptoModes[0]
			// }

			// // Check if the requested crypto mode is supported
			// // by us. If not, fall back to the default crypto
			// // mode.
			// supportedModes := cryptstate.SupportedModes()
			// ok := false
			// for _, mode := range supportedModes {
			// 	if requestedMode == mode {
			// 		ok = true
			// 		break
			// 	}
			// }
			// if !ok {
			// 	requestedMode = "OCB2-AES128"
			// }

			// client.CryptoMode = requestedMode
			client.CryptoMode = "OCB2-AES128"
			client.state = StateClientSentVersion
		} else if client.state == StateClientSentVersion && msg.kind == mumbleproto.MessageAuthenticate {
			go client.server.handleAuthenticate(client, msg)
		} else if client.state >= StateClientConnected && client.state < StateClientAuthenticated && msg.kind == mumbleproto.MessageUserState {
			go client.server.handlePreConnectUserStateMessage(client, msg)
		} else if msg.kind == mumbleproto.MessageUDPTunnel {
			// Special case UDPTunnel messages. They're high priority and shouldn't
			// go through our synchronous path.
			client.udp = false
			// Safe to use: guarded by TLS close.
			buf := (*(xmitBuf.Get().(*[]byte)))[:len(msg.buf)]
			copy(buf, msg.buf)
			client.udprecv <- buf
		} else if client.state >= StateClientAuthenticated && client.state < StateClientDead {
			go client.server.handleIncomingMessage(client, msg)
		} else {
			client.Printf("Unexpected message type ID %d on state %d", msg.kind, client.state)
		}
	}
}

func (client *Client) outgoingMQHandler() {
	defer client.recover(nil)

	for m := range client.outgoingMessageQueue {
		func() {
			if m.wg != nil {
				defer m.wg.Done()
			}
			err := client.sendMessage(m.msg)
			if err != nil {
				panic(err)
				// if err.Error() != "Client is dead" {
				// 	panic(err) // Caught by this function
				// } else if err.Error() == "Client is dead" {
				// 	return
				// }
			}
		}()
	}

}

func (client *Client) sendChannelList() {
	// client.sendChannelTree(client.server.RootChannel())
	channels := client.server.AllChannels()

	for _, channel := range channels {
		chanstate := &mumbleproto.ChannelState{
			ChannelId: proto.Uint32(uint32(channel.ID)),
			Name:      proto.String(channel.Name),
			// IsEnterRestricted: proto.Bool(HasSomehowRestricted(&channel, EnterPermission)),
			// CanEnter:          proto.Bool(HasPermission(&channel, client, EnterPermission, []string{})),
		}

		if channel.HasDescription() {
			if client.Version >= 0x10202 {
				chanstate.DescriptionHash = channel.DescriptionBlobHashBytes()
			} else {
				buf, err := blobStore.Get(channel.DescriptionBlob)
				if err == nil {
					// panic("Blobstore error.")
					chanstate.Description = proto.String(string(buf))
				}
			}
		}

		if channel.ParentID != -1 {
			chanstate.Parent = proto.Uint32(0)
		}

		chanstate.Position = proto.Int32(int32(channel.Position))

		if channel.IsTemporary() {
			chanstate.Temporary = proto.Bool(true)
		}

		err := client.sendMessage(chanstate)
		if err != nil {
			panic(err) // Caught by authentication function
		}
	}

	for _, channel := range channels {
		chanstate := &mumbleproto.ChannelState{
			ChannelId: proto.Uint32(uint32(channel.ID)),
		}

		if channel.ParentID != -1 {
			chanstate.Parent = proto.Uint32(uint32(channel.ParentID))
		}

		chanstate.Position = proto.Int32(int32(channel.Position))

		if channel.IsTemporary() {
			chanstate.Temporary = proto.Bool(true)
		}

		err := client.sendMessage(chanstate)
		if err != nil {
			panic(err) // Caught by authentication function
		}
	}
}

// func (client *Client) sendChannelTree(channel *Channel) {
// 	chanstate := &mumbleproto.ChannelState{
// 		ChannelId: proto.Uint32(uint32(channel.ID)),
// 		Name:      proto.String(channel.Name),
// 	}
// 	if channel.ParentID != -1 {
// 		chanstate.Parent = proto.Uint32(uint32(channel.ParentID))
// 	}

// 	if channel.HasDescription() {
// 		if client.Version >= 0x10202 {
// 			chanstate.DescriptionHash = channel.DescriptionBlobHashBytes()
// 		} else {
// 			buf, err := blobStore.Get(channel.DescriptionBlob)
// 			if err == nil {
// 				// panic("Blobstore error.")
// 				chanstate.Description = proto.String(string(buf))
// 			}
// 		}
// 	}

// 	if channel.IsTemporary() {
// 		chanstate.Temporary = proto.Bool(true)
// 	}

// 	chanstate.Position = proto.Int32(int32(channel.Position))

// 	err := client.sendMessage(chanstate)
// 	if err != nil {
// 		panic(err) // Caught by authentication function
// 	}

// 	for _, subchannel := range channel.Childrens() {
// 		client.sendChannelTree(subchannel)
// 	}
// }

type channelLinksResult struct {
	ChannelID int
	Links     string
}

func (client *Client) sendChannelLinks() {
	var result []channelLinksResult
	client.server.db.Raw("SELECT channel_id, GROUP_CONCAT(link_id) AS links FROM \"channel_links\" GROUP BY channel_id").Scan(&result)

	for _, link := range result {

		var links []uint32
		dbLinks := strings.Split(link.Links, ",")
		for _, linkChan := range dbLinks {
			linkID, err := strconv.ParseUint(linkChan, 10, 32)
			if err != nil {
				panic(err)
			}
			links = append(links, uint32(linkID))
		}
		chanstate := &mumbleproto.ChannelState{
			ChannelId: proto.Uint32(uint32(link.ChannelID)),
			Links:     links,
		}
		err := client.sendMessage(chanstate)
		if err != nil {
			panic(err) // Caught by authentication function
		}
	}

	return
}

// Try to do a crypto resync
func (client *Client) cryptResync() {
	defer client.recover(nil)
	goodElapsed := time.Now().Unix() - client.crypt.LastGoodTime
	if goodElapsed > 5 {
		requestElapsed := time.Now().Unix() - client.lastResync
		if requestElapsed > 5 {
			client.Debugf("requesting crypt resync")
			client.lastResync = time.Now().Unix()
			cryptsetup := &mumbleproto.CryptSetup{}
			err := client.sendMessage(cryptsetup)
			if err != nil {
				panic(err) // Caught by this function
			}
		}
	}
}

func (client *Client) recalcUnstableUDP() {
	if client.server.cfg.UDPMarkUnstableRate <= 0 {
		return
	}

	lostRate := float64(client.crypt.RemoteLost) / float64(client.crypt.RemoteGood+client.crypt.RemoteLate+client.crypt.RemoteLost)

	if lostRate > client.server.cfg.UDPMarkUnstableRate {
		client.unstableUDP = true
	}
	// do not mark it back
	// else {
	// 	client.unstableUDP = false
	// }
}

func (client *Client) ListenChannel(channel *Channel) {
	if channel == nil {
		return
	}

	//if channel.ID == client.channelID {
	//	return
	//}

	client.listenMutex.Lock()
	defer client.listenMutex.Unlock()

	if client.hasListenedChannel(channel) {
		return
	}

	client.listens = append(client.listens, channel)
}

func (client *Client) UnlistenChannel(channel *Channel) {
	if channel == nil {
		return
	}

	//if channel.ID == client.channelID {
	//	return
	//}

	client.listenMutex.Lock()
	defer client.listenMutex.Unlock()

	index := 0
	for _, listen := range client.listens {
		if listen.ID == channel.ID {
			break
		}
		index++
	}

	if index >= 0 && index < len(client.listens) {
		client.listens[len(client.listens)-1], client.listens[index] = nil, client.listens[len(client.listens)-1]
		client.listens = client.listens[:len(client.listens)-1]
	}
}

func (client *Client) hasListenedChannel(channel *Channel) bool {
	index := 0
	for _, listen := range client.listens {
		if listen.ID == channel.ID {
			break
		}
		index++
	}
	return index >= 0 && index < len(client.listens)
}

func (client *Client) sendChannelPermissions() {
	defer client.recover(nil)

	channels := client.server.AllChannels()

	for _, channel := range channels {
		chanstate := &mumbleproto.ChannelState{
			ChannelId:         proto.Uint32(uint32(channel.ID)),
			IsEnterRestricted: proto.Bool(HasSomehowRestricted(&channel, EnterPermission)),
			CanEnter:          proto.Bool(HasPermission(&channel, client, EnterPermission, []string{})),
		}
		client.queueMessage(&waitableMessage{
			wg:  nil,
			msg: chanstate,
		})
	}
}
