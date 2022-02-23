// Copyright (c) 2010-2011 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

package main

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	gormlogger "gorm.io/gorm/logger"

	"github.com/wfjsw/hall/htmlfilter"
	"github.com/wfjsw/hall/mumbleproto"
	"github.com/wfjsw/hall/sessionpool"
	"google.golang.org/protobuf/proto"

	xerrors "github.com/pkg/errors"
	proxyProtocol "github.com/wfjsw/go-proxy-protocol"
	"golang.org/x/net/ipv4"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"

	"github.com/dyson/certman"
)

// DefaultPort The default port a Murmur server listens on
const DefaultPort = 64738
const DefaultWebPort = 443
const UDPPacketSize = 1024

const LogOpsBeforeSync = 100
const CeltCompatBitstream = -2147483637

// maximum packet size
const mtuLimit = 1500
const batchSize = 128

const (
	StateClientConnected = iota
	StateServerSentVersion
	StateClientSentVersion
	StateClientAuthenticated
	StateClientReady
	StateClientDead
)

type KeyValuePair struct {
	Key   string
	Value string
	Reset bool
}

type udpAddressPacket struct {
	addr *net.UDPAddr
	data []byte
}

type udpClientPacket struct {
	data   []byte
	client []*Client
}

type ifacePacket struct {
	laddr net.IP
	raddr *net.UDPAddr
	data  []byte
}

// Server A Murmur server instance
type Server struct {
	ID int64

	// tcpl    *net.TCPListener
	tcpl *proxyProtocol.TCPProxyListener
	// udpconn  *net.UDPConn
	udpconnpool *PacketConnPool
	tlscfg      *tls.Config
	bye         chan bool
	netwg       sync.WaitGroup
	running     bool
	stopOnce    sync.Once

	// incoming       chan *Message
	// voicebroadcast chan *VoiceBroadcast
	// tempRemove chan *Channel
	afterAuth chan *Client

	// Server configuration
	cfg     ServerConfig
	dataDir string
	db      *gorm.DB

	// Clients
	clients *ClientStorage

	// Host, host/port -> client mapping
	hmutex   sync.Mutex
	hclients map[string][]*Client
	// hpclients map[string]*Client
	hpclients sync.Map

	udpIncomingQueue  chan *udpAddressPacket
	udpBatchSendQueue chan map[string][]ipv4.Message

	userStateLock sync.Mutex

	// Codec information
	AlphaCodec       int32
	BetaCodec        int32
	PreferAlphaCodec bool
	Opus             bool

	// Channels
	// Channels   map[int]*Channel
	// nextChanId int

	// Users
	// Users       map[uint32]*User
	// UserCertMap map[string]*User
	// UserNameMap map[string]*User
	// nextUserId  uint32
	userCache AuthenticatorUsers

	// Sessions
	pool *sessionpool.SessionPool

	// Bans
	// banlock sync.RWMutex
	// Bans    []ban.Ban
	tempIPBan     *LRU
	aclStoreCache *LRU
	aclQueryCache *LRU
	channelCache  *LRU

	// Logging
	*log.Logger
}

type clientLogForwarder struct {
	client *Client
	logger *log.Logger
}

var (
	// a system-wide packet buffer shared
	// to mitigate high-frequency memory allocation for packets, bytes from xmitBuf
	// is aligned to 64bit
	xmitBuf sync.Pool
)

func init() {
	xmitBuf.New = func() interface{} {
		pkt := make([]byte, mtuLimit)
		return &pkt
	}
}

func (lf clientLogForwarder) Write(incoming []byte) (int, error) {
	buf := new(bytes.Buffer)
	buf.WriteString(fmt.Sprintf("<%v:%v(%v)> ", lf.client.Session(), lf.client.ShownName(), lf.client.UserId()))
	buf.Write(incoming)
	lf.logger.Output(3, buf.String())
	return len(incoming), nil
}

// NewServer Allocate a new Murmur instance
func NewServer(datadir string, config ServerConfig, logwriter io.Writer) (server *Server, err error) {
	server = new(Server)

	databasePath := config.DatabasePath
	if databasePath == "" {
		databasePath = filepath.Join(datadir, "data.db")
	}

	//db, err := gorm.Open("sqlite3", databasePath+"?_journal=WAL")

	dbLogger := gormlogger.Default.LogMode(gormlogger.Warn)
	if config.Debug {
		dbLogger = dbLogger.LogMode(gormlogger.Info)
	}

	db, err := gorm.Open(sqlite.Open(databasePath+"?_journal=WAL"), &gorm.Config{
		PrepareStmt: true,
		Logger:      dbLogger,
	})
	if err != nil {
		panic("failed to connect database")
	}
	server.db = db

	err = db.AutoMigrate(&Ban{}, &Channel{}, &ACL{}, &UserLastChannel{})
	if err != nil {
		return nil, err
	}

	server.ID = int64(config.ServerId)
	server.cfg = config
	server.dataDir = datadir

	server.tempIPBan, err = NewLRUCache(512)
	if err != nil {
		panic("failed to create temporary ban cache")
	}

	server.aclQueryCache, err = NewLRUCache(server.cfg.AclCacheSize)
	if err != nil {
		panic("failed to create acl cache")
	}

	server.aclStoreCache, err = NewLRUCache(server.cfg.AclCacheSize)
	if err != nil {
		panic("failed to create acl cache")
	}

	server.channelCache, err = NewLRUCache(4096)
	if err != nil {
		panic("failed to create channel cache")
	}

	var rootChannelName string

	if config.RegisterName != "" {
		rootChannelName = config.RegisterName
	} else {
		rootChannelName = "Root"
	}

	rootChannel := server.GetChannel(0)
	if rootChannel == nil {
		// rootChannel = s.NewChannel(rootChannelName, true)
		server.db.Exec("INSERT INTO channels VALUES (0, ?, 0, 0, -1, 1, NULL, 0)", rootChannelName)
	} else if rootChannel.Name != rootChannelName {
		// rootChannel.Name = rootChannelName
		// rootChannel.Save()
		server.db.Exec("UPDATE channels SET name = ? WHERE id = 0", rootChannelName)
	}

	server.Logger = log.New(logwriter, fmt.Sprintf("[Server %v] ", server.ID), 0)

	if server.cfg.UseOfflineCache {
		server.loadUserCache()
		if server.userCache == nil {
			server.PullUserList()
		}
	}

	return
}

// Debugf implements debug-level printing for Servers.
func (server *Server) Debugf(format string, v ...interface{}) {
	if server.cfg.Debug {
		server.Printf(format, v...)
	}
}

// recover server thread from panic
func (server *Server) recover() {
	if err := recover(); err != nil {
		server.Printf("server panic: %v\n%s", err, debug.Stack())
		server.Stop()
	}
}

func (server *Server) nonFatalRecover() {
	if err := recover(); err != nil {
		server.Printf("server panic: %v\n%s", err, debug.Stack())
	}
}

// maxUsers get max user of server for memory allocation advise
func (server *Server) maxUsers() int {
	if server.cfg.MaxUsers <= 0 {
		return 4096
	}
	return server.cfg.MaxUsers
}

// RootChannel gets a pointer to the root channel
func (server *Server) RootChannel() *Channel {
	root := server.GetChannel(0)
	if root == nil {
		server.Fatalf("No Root channel found for server")
	}
	return root
}

// DefaultChannel gets a pointer to the default channel
func (server *Server) DefaultChannel() *Channel {
	channel := server.GetChannel(server.cfg.DefaultChannel)
	if channel == nil {
		channel = server.RootChannel()
	}
	return channel
}

// Clients get a list of clients
func (server *Server) Clients() []*Client {
	return server.clients.SnapshotWithFilter(func(k uint32, c *Client) bool {
		return c.state >= StateClientAuthenticated && c.state < StateClientDead && !c.disconnected
	}, 1)
}

func (server *Server) ClientsMap() map[uint32]*Client {
	return server.clients.SnapshotMapWithFilter(func(k uint32, c *Client) bool {
		return c.state >= StateClientAuthenticated && c.state < StateClientDead && !c.disconnected
	}, 1)
}

// Called by the server to initiate a new client connection.
func (server *Server) handleIncomingClient(conn net.Conn, realip *net.TCPAddr, laddr net.IP) {
	client := new(Client)

	client.lf = &clientLogForwarder{client, server.Logger}
	client.Logger = log.New(client.lf, "", 0)

	addr := conn.RemoteAddr()
	if addr == nil {
		client.Print("Unable to extract address for client.")
		return
	}

	// client.tcpaddr = addr.(*net.TCPAddr)
	// client.tcpaddr, _ = net.ResolveTCPAddr("tcp", addr.String())
	switch addr := addr.(type) {
	case *net.UDPAddr:
		// Faking TCPAddr Type
		client.tcpaddr = &net.TCPAddr{
			IP:   addr.IP,
			Port: addr.Port,
			Zone: addr.Zone,
		}
	case *net.TCPAddr:
		client.tcpaddr = addr
	}
	client.realip = realip
	client.server = server
	client.laddr = laddr

	client.conn = tls.Server(conn, server.tlscfg) // conn
	client.reader = bufio.NewReader(client.conn)

	// Extract user's cert hash
	// Only consider client certificates for direct connections, not WebSocket connections.
	// We do not support TLS-level client certificates for WebSocket client.
	if tlsconn, ok := client.conn.(*tls.Conn); ok {
		err := tlsconn.Handshake()
		if err == io.EOF {
			client.Disconnect()
			return
		} else if err != nil {
			// client.Panicf("TLS handshake failed: %v", err)
			client.Print(err)
			client.conn.SetDeadline(time.Now().Add(1 * time.Second))
			client.conn.Close()
			return
		}

		state := tlsconn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			hash := sha1.New()
			hash.Write(state.PeerCertificates[0].Raw)
			sum := hash.Sum(nil)
			client.certHash = hex.EncodeToString(sum)
		}

		// Check whether the client's cert hash is banned
		if server.IsCertHashBanned(client.CertHash()) {
			client.Printf("Certificate hash is banned")
			client.Disconnect()
			return
		}
	} else {
		client.Printf("Unable to resolve connection to TLS connection")
		client.conn.SetDeadline(time.Now().Add(1 * time.Second))
		client.conn.Close()
		return
	}

	client.session = server.pool.Get()
	// client.Printf("New connection: %v (%v)", conn.RemoteAddr(), client.Session())
	if conn.(*proxyProtocol.TCPConn).IsProxyDataAvailable() {
		client.Printf("New session created: [PROXIED] %v => %v (%v)", client.tcpaddr, client.realip, client.Session())
	} else {
		client.Printf("New session created: %v (%v)", client.tcpaddr, client.Session())
	}

	client.UDPTotalPackets = 0
	client.UDPVolume = 0
	client.TCPTotalPackets = 0
	client.TCPVolume = 0

	client.LoginTime = time.Now().Unix()
	client.LastActiveTime = time.Now().Unix()
	client.LastPing = time.Now().Unix()

	client.outgoingMessageQueue = make(chan *waitableMessage, 128)
	client.udpsend = make(chan []byte, 1024)
	client.udprecv = make(chan []byte, 1024)
	client.voiceTargets = make(map[uint32]*VoiceTarget, 32)

	client.state = StateClientConnected

	// Add the client to the connected list
	server.clients.Put(client.Session(), client)
	// Add the client to the host slice for its host address.
	host := client.tcpaddr.IP.String()
	server.hmutex.Lock()
	server.hclients[host] = append(server.hclients[host], client)
	server.hmutex.Unlock()

	// client.user = nil
	conn.SetDeadline(time.Time{})
	// Launch network readers
	go client.tlsRecvLoop()
	go client.udpSendLoop()
	go client.udpRecvLoop()
	go client.outgoingMQHandler()

	return
}

// RemoveClient removes a disconnected client from the server's
// internal representation.
func (server *Server) RemoveClient(client *Client, kicked bool) {

	sessionID := client.Session()
	userID := client.UserId()

	if client.IsRegistered() {
		go server.EndSession(sessionID, userID, time.Now())
	}

	server.clients.Delete(sessionID)

	host := client.tcpaddr.IP.String()

	server.hmutex.Lock()
	oldclients, found := server.hclients[host]
	if found {
		// newclients := []*Client{}
		// for _, hostclient := range oldclients {
		// 	if hostclient != client {
		// 		newclients = append(newclients, hostclient)
		// 	}
		// }
		removed := false
		for i, hostclient := range oldclients {
			if hostclient == client {
				oldclients[len(oldclients)-1], oldclients[i] = nil, oldclients[len(oldclients)-1]
				removed = true
				break
			}
		}
		if removed {
			server.hclients[host] = oldclients[:len(oldclients)-1] // newclients
			if len(server.hclients[host]) == 0 {
				delete(server.hclients, host)
			}
		}
	}
	server.hmutex.Unlock()

	if client.udpaddr != nil {
		// delete(server.hpclients, client.udpaddr.String())
		server.hpclients.Delete(client.udpaddr.String())
	}

	server.pool.Reclaim(sessionID)

	// If the user was not kicked, broadcast a UserRemove message.
	// If the user is disconnect via a kick, the UserRemove message has already been sent
	// at this point.
	if !kicked && client.state >= StateClientAuthenticated && sessionID > 0 {
		go func(server *Server, session uint32) {
			server.broadcastProtoMessageWithPredicate(&mumbleproto.UserRemove{
				Session: proto.Uint32(session),
			}, func(client *Client) bool {
				return client.hasFullUserList
			})
		}(server, sessionID)
	}
}

func (server *Server) cleanupDeadClient() {
	now := time.Now().Unix()
	timeout := server.cfg.Timeout
	if timeout <= 0 {
		timeout = 30
	}
	toclean := server.clients.SnapshotWithFilter(func(k uint32, c *Client) bool {
		return (now-c.LastPing) > int64(timeout) || c.state == StateClientDead
	}, 0.1)
	for _, c := range toclean {
		server.Printf("Cleaned a unresponsive client %d<%s>(%s)", c.UserId(), c.realip.IP.String(), c.ShownName())
		c.Disconnect()
	}

	return
}

func (server *Server) routeVoiceBroadcast(vb *VoiceBroadcast) {
	if vb.client.Suppress == true || vb.client.Mute == true || vb.client.SelfMute == true {
		// Sanity Check
		return
	}

	if vb.target == 0 { // Current channel

		if !vb.client.IsSuperUser() && server.cfg.DirectVoiceBehavior == "block" {
			// TODO: allow this for specific role
			vb.client.Suppress = true
			vb.client.Printf("Suppressed for Direct Voice")
			vb.client.queueMessage(&waitableMessage{
				wg: nil,
				msg: &mumbleproto.TextMessage{
					Session: []uint32{vb.client.Session()},
					Message: proto.String(trnDirectVoiceBlock),
				},
			})
			userstate := &mumbleproto.UserState{
				Session:  proto.Uint32(vb.client.Session()),
				Suppress: proto.Bool(true),
			}
			server.broadcastUserState(userstate)
			return
		}

		channel := vb.client.Channel()

		//if !HasPermission(channel, vb.client, SpeakPermission) {
		//	return
		//}

		if server.cfg.DirectVoiceBehavior == "" || server.cfg.DirectVoiceBehavior == "vanilla" {
			channel.SendUntargetedVoiceBroadcast(vb)
		} else if server.cfg.DirectVoiceBehavior == "local" {
			channel.SendLocalVoiceBroadcast(vb)
		}
	} else {
		vb.client.vtMutex.RLock()
		target, ok := vb.client.voiceTargets[uint32(vb.target)]
		vb.client.vtMutex.RUnlock()
		if !ok {
			return
		}

		target.SendVoiceBroadcast(vb)
	}
}

// This is the synchronous handler goroutine.
// Important control channel messages are routed through this Goroutine
// to keep server state synchronized.
func (server *Server) handlerLoop() {
	defer server.recover()

	regtick := time.Tick(time.Hour)
	synctick := time.Tick(30 * time.Second)
	cleanuptick := time.Tick(5 * time.Second)
	// synctick
	for {

		select {
		// We're done. Stop the server's event handler
		case <-server.bye:
			return
		// Control channel messages
		// case msg := <-server.incoming:
		// 	client := msg.client
		// 	go server.handleIncomingMessage(client, msg)
		// Voice broadcast
		// case vb := <-server.voicebroadcast:
		// 	server.routeVoiceBroadcast(vb)
		// Remove a temporary channel
		// case tempChannel := <-server.tempRemove:
		// 	if tempChannel.IsEmpty() {
		// 		server.RemoveChannel(tempChannel)
		// 	}

		// Finish client authentication. Send post-authentication
		// server info.
		// case client := <-server.afterAuth:
		// 	server.finalizeAuthentication(client)

		// Server registration update
		// Tick every hour + a minute offset based on the server id.
		case <-regtick:
			if server.cfg.Publish {
				server.RegisterPublicServer()
			}

		case <-synctick:
			go server.PullUserList()
			go server.doSync()
			// go server.SyncAllClientState() // TODO: not implemented
		case <-cleanuptick:
			server.cleanupDeadClient()
		}
	}
}

func (server *Server) afterAuthLoop() {
	defer server.recover()
	for c := range server.afterAuth {
		server.finalizeAuthentication(c)
	}
}

// Handle an Authenticate protobuf message.  This is handled in a separate
// goroutine to allow for remote authenticators that are slow to respond.
//
// Once a user has been authenticated, it will ping the server's handler
// routine, which will call the finishAuthenticate method on Server which
// will send the channel tree, user list, etc. to the client.
func (server *Server) handleAuthenticate(client *Client, msg *Message) {
	// Is this message not an authenticate message? If not, discard it...
	// if msg.kind != mumbleproto.MessageAuthenticate {
	// 	client.Panic("Unexpected message. Expected Authenticate.")
	// 	return
	// }

	defer client.recover(nil)

	auth := &mumbleproto.Authenticate{}
	err := proto.Unmarshal(msg.buf, auth)
	if err != nil {
		panic(err) // Caught by this function
	}

	// Set access tokens. Clients can set their access tokens any time
	// by sending an Authenticate message with he contents of their new
	// access token list.
	client.tokens = auth.Tokens
	server.ClearCachesByUser(client)

	if client.state >= StateClientAuthenticated {
		return
	}

	// GOROUTINE START

	// Did we get a username?
	if auth.Username == nil || len(*auth.Username) == 0 {
		client.RejectAuth(mumbleproto.Reject_InvalidUsername, trnInvalidUsername)
		return
	}

	client.Username = *auth.Username
	client.Password = *auth.Password

	// TODO: Add RPC User Auth Here
	// tatus, newname, groups := server.Authenticate(*auth.Username, *auth.Password, client.CertHash(), client.realip.IP.String())
	status, userId, nickname, groups, err := server.Authenticate(
		*auth.Username, *auth.Password, client.CertHash(), client.Session(), client.realip.IP.String(), client.Version,
		client.ClientName, client.OSName, client.OSVersion)

	if status == -3 {
		// Server issue
		client.RejectAuth(mumbleproto.Reject_AuthenticatorFail, trnAuthenticatorFail)
		return
	} else if status == -2 {
		// No such user
		if !server.cfg.AllowGuest {
			client.RejectAuth(mumbleproto.Reject_InvalidUsername, trnAuthenticatorNoUser)
			return
		}
	} else if status == -1 {
		// Wrong Password
		client.RejectAuth(mumbleproto.Reject_WrongUserPW, trnAuthenticatorInvalidCred)
		return
	} else if status >= 0 {
		client.userID = uint32(userId)
		client.Username = nickname
		client.groups = groups
	} else {
		panic("Unrecognized authenticator status") // Caught by this function
	}

	if client.groups == nil {
		// initialize group array to prevent crash
		client.groups = make([]string, 0)
	}

	if !client.IsRegistered() && !server.cfg.AllowGuest {
		panic("Unexpected non-registered user.")
	}

	if server.cfg.CertRequired {
		if client.IsRegistered() && client.HasCertificate() == false {
			client.RejectAuth(mumbleproto.Reject_NoCertificate, trnCertRequired)
			return
		}
	}

	if len(client.Username) <= 0 {
		panic("Unexpected empty username.")
	}

	if client.IsRegistered() && len(server.cfg.RequiredGroup) > 0 {
		hasOne := false
		for _, g := range server.cfg.RequiredGroup {
			// OR group
			validated := true
			for _, gg := range g {
				// AND group
				hasThis := false
				for _, t := range client.Groups() {
					if strings.TrimSpace(strings.ToLower(gg)) == strings.TrimSpace(strings.ToLower(t)) {
						hasThis = true
						break
					}
				}
				validated = validated && hasThis
			}
			if validated {
				hasOne = true
				break
			}
		}
		if !hasOne {
			client.RejectAuth(mumbleproto.Reject_None, trnRequiredGroupNotMet)
			return
		}
	}

	// Setup the cryptstate for the client.
	err = client.crypt.GenerateKey(client.CryptoMode)
	if err != nil {
		panic(err) // Caught by this function
	}

	// Send CryptState information to the client so it can establish an UDP connection,
	// if it wishes.
	client.lastResync = time.Now().Unix()
	err = client.sendMessage(&mumbleproto.CryptSetup{
		Key:         client.crypt.Key,
		ClientNonce: client.crypt.DecryptIV,
		ServerNonce: client.crypt.EncryptIV,
	})
	if err != nil {
		panic(err) // Caught by this function
	}

	// Add codecs
	client.codecs = auth.CeltVersions
	client.opus = auth.GetOpus()

	client.state = StateClientAuthenticated

	// TODO: these fn have bad performance. try to optimize them later.
	client.sendChannelList()
	client.sendChannelLinks()

	server.afterAuth <- client
	return
}

func (server *Server) finalizeAuthentication(client *Client) {
	defer client.recover(nil)

	if client.disconnected {
		// client crashed somehow. quit early
		return
	}

	multiCount := 0

	if client.IsRegistered() {
		for _, connectedClient := range server.Clients() {
			if connectedClient.state < StateClientAuthenticated {
				continue
			}
			if connectedClient.UserId() == client.UserId() && (server.cfg.MultiLoginLimitSameIP && !client.realip.IP.Equal(connectedClient.realip.IP)) {
				// server.cmutex.RUnlock()
				client.RejectAuth(mumbleproto.Reject_UsernameInUse, trnSimultaneousLoginDifferentIP)
				return
			} else if connectedClient.UserId() == client.UserId() {
				multiCount++
			}
		}

		if server.cfg.MaxMultipleLoginCount > 0 && multiCount > server.cfg.MaxMultipleLoginCount {
			client.RejectAuth(mumbleproto.Reject_UsernameInUse, trnTooManySimultaneousLogin)
			return
		}
	}

	// Warn clients without CELT support that they might not be able to talk to everyone else.
	if len(client.codecs) == 0 {
		client.codecs = []int32{CeltCompatBitstream}
		server.Printf("Client %v connected without CELT codecs. Faking compat bitstream.", client.Session())
		if server.Opus && !client.opus {
			err := client.sendMessage(&mumbleproto.TextMessage{
				Session: []uint32{client.Session()},
				Message: proto.String(trnNoCELTSupport),
			})
			if err != nil {
				panic(err) // Caught by this function
			}
		}
	}

	// First, check whether we need to tell the other connected
	// clients to switch to a codec so the new guy can actually speak.
	server.updateCodecVersions(client)

	// NOTE: this lock could deadlock client.Panic(). Beware.
	// Ensure this lock globally in this function instead of sendUserList provide more stability.

	func() {
		server.userStateLock.Lock()
		defer server.userStateLock.Unlock()

		server.sendUserList(client)

		channel := server.DefaultChannel()
		if client.IsRegistered() {
			lastChannelID := client.GetLastChannel()
			if lastChannelID > 0 {
				if lastChannel := server.GetChannel(lastChannelID); lastChannel != nil {
					if !server.cfg.CheckLastChannelPermission || HasPermission(lastChannel, client, EnterPermission, []string{}) {
						channel = lastChannel
					}
				}
			}
		}

		userstate := &mumbleproto.UserState{
			Session:   proto.Uint32(client.Session()),
			Actor:     proto.Uint32(client.Session()),
			Name:      proto.String(client.ShownName()),
			ChannelId: proto.Uint32(uint32(channel.ID)),
		}

		// INCONSISTENCY: this broadcast to all old users.
		if client.HasCertificate() {
			userstate.Hash = proto.String(client.CertHash())
		}

		if client.IsRegistered() {
			userstate.UserId = proto.Uint32(uint32(client.UserId()))

			// if client.user.HasTexture() {
			// 	// TODO: disable? or fetch from server

			// 	// Does the client support blobs?
			// 	if client.Version >= 0x10203 {
			// 		userstate.TextureHash = client.user.TextureBlobHashBytes()
			// 	} else {
			// 		buf, err := blobStore.Get(client.user.TextureBlob)
			// 		if err != nil {
			// 			server.Panicf("Blobstore error: %v", err.Error())
			// 		}
			// 		userstate.Texture = buf
			// 	}
			// }

			// if client.user.HasComment() {
			// 	// Does the client support blobs?
			// 	if client.Version >= 0x10203 {
			// 		userstate.CommentHash = client.user.CommentBlobHashBytes()
			// 	} else {
			// 		buf, err := blobStore.Get(client.user.CommentBlob)
			// 		if err != nil {
			// 			server.Panicf("Blobstore error: %v", err.Error())
			// 		}
			// 		userstate.Comment = proto.String(string(buf))
			// 	}
			// }
		}

		server.userEnterChannel(client, channel, userstate)

		if client.disconnected {
			// client crashed somehow. quit early
			return
		}

		server.broadcastProtoMessageWithPredicate(userstate, func(c *Client) bool {
			return c == client || c.hasFullUserList
		})
	}()

	serverSync := &mumbleproto.ServerSync{}
	serverSync.Session = proto.Uint32(client.Session())
	serverSync.MaxBandwidth = proto.Uint32(uint32(server.cfg.MaxBandwidth))
	serverSync.WelcomeText = proto.String(server.cfg.WelcomeText) // TODO: Dynamic mask
	perm := CalculatePermission(server.RootChannel(), client, []string{})
	serverSync.Permissions = proto.Uint64(uint64(perm))

	if err := client.sendMessage(serverSync); err != nil {
		panic(err) // Caught by this function
	}

	err := client.sendMessage(&mumbleproto.ServerConfig{
		AllowHtml:          proto.Bool(server.cfg.AllowHTML),
		MessageLength:      proto.Uint32(uint32(server.cfg.MaxTextMessageLength)),
		ImageMessageLength: proto.Uint32(uint32(server.cfg.MaxImageMessageLength)),
		MaxUsers:           proto.Uint32(uint32(server.cfg.MaxUsers)),
	})
	if err != nil {
		panic(err) // Caught by this function
	}

	if client.SelfMute || client.SelfDeaf {
		server.broadcastProtoMessageWithPredicate(&mumbleproto.UserState{
			Session:  proto.Uint32(client.Session()),
			Actor:    proto.Uint32(client.Session()),
			SelfMute: proto.Bool(client.SelfMute),
			SelfDeaf: proto.Bool(client.SelfDeaf),
		}, func(c *Client) bool {
			return c.hasFullUserList
		})
	}

	client.Printf("Authenticated")
	client.state = StateClientReady

	suggest := &mumbleproto.SuggestConfig{}
	doSuggest := false
	if server.cfg.SuggestVersion > 0 {
		suggest.Version = proto.Uint32(uint32(server.cfg.SuggestVersion))
		doSuggest = true
	}
	if server.cfg.SuggestPositional != nil {
		suggest.Positional = proto.Bool(*server.cfg.SuggestPositional)
		doSuggest = true
	}
	if server.cfg.SuggestPushToTalk != nil {
		suggest.PushToTalk = proto.Bool(*server.cfg.SuggestPushToTalk)
		doSuggest = true
	}
	if doSuggest {
		if err := client.sendMessage(suggest); err != nil {
			panic(err) // Caught by this function
		}
	}

	if server.cfg.SendPermissionInfo {
		go client.sendChannelPermissions()
	}
}

func (server *Server) updateCodecVersions(connecting *Client) {
	codecusers := map[int32]int{}
	var (
		winner     int32
		count      int
		users      int
		opus       int
		enableOpus bool
		txtMsg     = &mumbleproto.TextMessage{
			Message: proto.String(trnNoOpusSupport),
		}
	)

	// TODO: force opus

	clients := server.clients.SnapshotWithFilter(func(k uint32, client *Client) bool {
		return client.state == StateClientReady
	}, 1)

	for _, client := range clients {
		users++
		if client.opus {
			opus++
		}
		for _, codec := range client.codecs {
			codecusers[codec]++
		}
	}

	for codec, users := range codecusers {
		if users > count {
			count = users
			winner = codec
		}
		if users == count && codec > winner {
			winner = codec
		}
	}

	var current int32
	if server.PreferAlphaCodec {
		current = server.AlphaCodec
	} else {
		current = server.BetaCodec
	}

	if users <= 0 {
		// makes no sense to discuss about codec when no user
		return
	}

	opusPercentage := opus * 100 / users

	enableOpus = (100 - opusPercentage) <= server.cfg.OpusThreshold

	if winner != current {
		if winner == CeltCompatBitstream {
			server.PreferAlphaCodec = true
		} else {
			server.PreferAlphaCodec = !server.PreferAlphaCodec
		}

		if server.PreferAlphaCodec {
			server.AlphaCodec = winner
		} else {
			server.BetaCodec = winner
		}
	} else if server.Opus == enableOpus {
		if server.Opus && connecting != nil && !connecting.opus {
			txtMsg.Session = []uint32{connecting.Session()}
			err := connecting.sendMessage(txtMsg)
			if err != nil {
				connecting.Panic(err.Error())
				return
			}
		}
		return
	}

	server.Opus = enableOpus

	server.broadcastProtoMessage(&mumbleproto.CodecVersion{
		Alpha:       proto.Int32(server.AlphaCodec),
		Beta:        proto.Int32(server.BetaCodec),
		PreferAlpha: proto.Bool(server.PreferAlphaCodec),
		Opus:        proto.Bool(server.Opus),
	})

	if server.Opus {
		nonOpusClients := server.clients.SnapshotWithFilter(func(k uint32, client *Client) bool {
			return !client.opus && client.state == StateClientReady && !client.disconnected
		}, 0.3)

		wg := sync.WaitGroup{}

		for _, client := range nonOpusClients {
			wg.Add(1)
			txtMsg.Session = []uint32{connecting.Session()}
			client.queueMessage(&waitableMessage{
				wg:  nil,
				msg: txtMsg,
			})
		}

		wg.Wait()
	}

	server.Printf("CELT codec switch %#x %#x (PreferAlpha %v) (Opus %v)", uint32(server.AlphaCodec), uint32(server.BetaCodec), server.PreferAlphaCodec, server.Opus)
	return
}

func (server *Server) sendUserList(client *Client) {

	connectedClients := server.clients.SnapshotWithFilter(func(k uint32, c *Client) bool {
		return c.state >= StateClientAuthenticated && c.state < StateClientDead && client != c
	}, 1)
	for _, connectedClient := range connectedClients {
		userstate := &mumbleproto.UserState{
			Session:   proto.Uint32(connectedClient.Session()),
			Name:      proto.String(connectedClient.ShownName()),
			ChannelId: proto.Uint32(uint32(connectedClient.channelID)),
		}

		if connectedClient.HasCertificate() && client.IsRegistered() {
			userstate.Hash = proto.String(connectedClient.CertHash())
		}

		if connectedClient.IsRegistered() {
			userstate.UserId = proto.Uint32(uint32(connectedClient.UserId()))

			// TODO: Same shit
			// if connectedClient.user.HasTexture() {
			// 	// Does the client support blobs?
			// 	if client.Version >= 0x10203 {
			// 		userstate.TextureHash = connectedClient.user.TextureBlobHashBytes()
			// 	} else {
			// 		buf, err := blobStore.Get(connectedClient.user.TextureBlob)
			// 		if err != nil {
			// 			server.Panicf("Blobstore error: %v", err.Error())
			// 		}
			// 		userstate.Texture = buf
			// 	}
			// }

			// if connectedClient.user.HasComment() {
			// 	// Does the client support blobs?
			// 	if client.Version >= 0x10203 {
			// 		userstate.CommentHash = connectedClient.user.CommentBlobHashBytes()
			// 	} else {
			// 		buf, err := blobStore.Get(connectedClient.user.CommentBlob)
			// 		if err != nil {
			// 			server.Panicf("Blobstore error: %v", err.Error())
			// 		}
			// 		userstate.Comment = proto.String(string(buf))
			// 	}
			// }
		}

		if connectedClient.Mute {
			userstate.Mute = proto.Bool(true)
		}
		if connectedClient.Suppress {
			userstate.Suppress = proto.Bool(true)
		}
		if connectedClient.SelfMute {
			userstate.SelfMute = proto.Bool(true)
		}
		if connectedClient.SelfDeaf {
			userstate.SelfDeaf = proto.Bool(true)
		}
		if connectedClient.PrioritySpeaker {
			userstate.PrioritySpeaker = proto.Bool(true)
		}
		if connectedClient.Recording {
			userstate.Recording = proto.Bool(true)
		}

		var listeningChannelList []uint32

		func() {
			connectedClient.listenMutex.RLock()
			defer connectedClient.listenMutex.RUnlock()
			for _, channel := range connectedClient.listens {
				listeningChannelList = append(listeningChannelList, uint32(channel.ID))
			}
		}()

		userstate.ListeningChannelAdd = listeningChannelList

		// if connectedClient.PluginContext != nil || len(connectedClient.PluginContext) > 0 {
		// 	userstate.PluginContext = connectedClient.PluginContext
		// }
		// if len(connectedClient.PluginIdentity) > 0 {
		// 	userstate.PluginIdentity = proto.String(connectedClient.PluginIdentity)
		// }

		err := client.sendMessage(userstate)
		if err != nil {
			panic(err)
		}
	}
	client.hasFullUserList = true

	return
}

// Send a client its permissions for channel.
func (server *Server) sendClientPermissions(client *Client, channel *Channel) {
	// No caching for SuperUser
	// if client.IsSuperUser() {
	// 	return
	// }

	perm := CalculatePermission(channel, client, []string{})
	err := client.sendMessage(&mumbleproto.PermissionQuery{
		ChannelId:   proto.Uint32(uint32(channel.ID)),
		Permissions: proto.Uint32(uint32(perm)),
	})
	if err != nil {
		panic(err) // Caught by incoming message hub and closure
	}
}

type clientPredicate func(client *Client) bool

func (server *Server) broadcastProtoMessageWithPredicate(msg interface{}, clientcheck clientPredicate) {
	// server.cmutex.RLock()
	// defer server.cmutex.RUnlock()
	clientList := server.clients.SnapshotWithFilter(func(k uint32, client *Client) bool {
		if !clientcheck(client) {
			return false
		}
		if client.state < StateClientAuthenticated {
			return false
		}
		if client.state == StateClientDead {
			return false
		}
		if client.disconnected {
			return false
		}
		return true
	}, 1)

	wg := sync.WaitGroup{}

	for _, client := range clientList {
		wg.Add(1)
		client.queueMessage(&waitableMessage{
			wg:  &wg,
			msg: msg,
		})
	}

	wg.Wait()

	return
}

func (server *Server) broadcastProtoMessage(msg interface{}) {
	server.broadcastProtoMessageWithPredicate(msg, func(client *Client) bool { return true })
	return
}

func (server *Server) broadcastUserStateWithPredicate(msg *mumbleproto.UserState, clientcheck clientPredicate) {
	sessionID := *msg.Session
	client, ok := server.clients.Get(sessionID)
	if !ok || client.disconnected {
		// session has gone, no need to broadcast.
		return
	}

	server.userStateLock.Lock()
	defer server.userStateLock.Unlock()

	server.broadcastProtoMessageWithPredicate(msg, func(client *Client) bool {
		return clientcheck(client) && client.hasFullUserList
	})
	return
}

func (server *Server) broadcastUserState(msg *mumbleproto.UserState) {
	server.broadcastUserStateWithPredicate(msg, func(client *Client) bool {
		return client.hasFullUserList
	})
	return
}

func (server *Server) handleIncomingMessage(client *Client, msg *Message) {
	defer client.recover(nil)

	// NOTE: all the following function is panickable if fail on communication,
	// so remember to catch them by recover function.

	switch msg.kind {
	case mumbleproto.MessageAuthenticate:
		server.handleAuthenticate(msg.client, msg)
	case mumbleproto.MessageChannelRemove:
		server.handleChannelRemoveMessage(msg.client, msg)
	case mumbleproto.MessageChannelState:
		server.handleChannelStateMessage(msg.client, msg)
	case mumbleproto.MessageUserState:
		server.handleUserStateMessage(msg.client, msg)
	case mumbleproto.MessageUserRemove:
		server.handleUserRemoveMessage(msg.client, msg)
	case mumbleproto.MessageBanList:
		server.handleBanListMessage(msg.client, msg)
	case mumbleproto.MessageTextMessage:
		server.handleTextMessage(msg.client, msg)
	case mumbleproto.MessageACL:
		server.handleACLMessage(msg.client, msg)
	case mumbleproto.MessageQueryUsers:
		server.handleQueryUsers(msg.client, msg)
	case mumbleproto.MessageCryptSetup:
		server.handleCryptSetup(msg.client, msg)
	case mumbleproto.MessageContextAction:
		// TODO: customize it
		// server.Printf("MessageContextAction from client")
	case mumbleproto.MessageUserList:
		server.handleUserList(msg.client, msg)
	case mumbleproto.MessageVoiceTarget:
		server.handleVoiceTarget(msg.client, msg)
	case mumbleproto.MessagePermissionQuery:
		server.handlePermissionQuery(msg.client, msg)
	case mumbleproto.MessageUserStats:
		server.handleUserStatsMessage(msg.client, msg)
	case mumbleproto.MessageRequestBlob:
		server.handleRequestBlob(msg.client, msg)
	}

}

// SendUDP Send the content of buf as a UDP packet to addr.
func (server *Server) SendUDP(buf []byte, addr *net.UDPAddr, laddr net.IP) (err error) {
	conn := server.udpconnpool.Pick(laddr.String())
	oob := &ipv4.ControlMessage{
		Src: laddr,
	}
	_, err = conn.WriteTo(buf, oob, addr)
	return
}

func (server *Server) udpQueueLoop() {
	defer server.recover()

	for batch := range server.udpBatchSendQueue {
		server.sendUDPBatch(batch)
	}
}

func (server *Server) QueueUDPBatch(data []byte, clients []*Client) {
	defer server.nonFatalRecover()
	defer xmitBuf.Put(&data)

	packetSet := make(map[string][]ipv4.Message)
	c := make(chan ifacePacket, len(clients))

	sorterDone := make(chan bool, 1)

	go func() {
		for i := range c {
			if _, exists := packetSet[i.laddr.String()]; !exists {
				packetSet[i.laddr.String()] = make([]ipv4.Message, 0, len(clients))
			}

			packetSet[i.laddr.String()] = append(packetSet[i.laddr.String()], ipv4.Message{
				Addr:    i.raddr,
				Buffers: [][]byte{i.data},
			})
		}

		sorterDone <- true
	}()

	wg := sync.WaitGroup{}

	for _, client := range clients {
		wg.Add(1)
		go func(client *Client, c chan ifacePacket, wg *sync.WaitGroup) {
			defer client.recover(nil)
			defer wg.Done()

			if !client.udp || client.unstableUDP || client.udpaddr == nil {
				buf2 := (*xmitBuf.Get().(*[]byte))[:len(data)]
				copy(buf2, data)
				client.queueUDP(buf2)
				return
			}

			pktLen := len(data) + client.crypt.Overhead()
			buf := (*(xmitBuf.Get().(*[]byte)))[:pktLen]
			client.createUDPPacket(data, buf)
			// var msg ipv4.Message
			msg := new(ipv4.Message)
			msg.Buffers = [][]byte{buf}
			msg.Addr = client.udpaddr

			c <- ifacePacket{
				laddr: client.laddr,
				raddr: client.udpaddr,
				data:  buf,
			}

			// packetSet = append(packetSet, msg)
		}(client, c, &wg)
	}
	wg.Wait()
	close(c)
	<-sorterDone

	server.udpBatchSendQueue <- packetSet
	return
}

func (server *Server) sendUDPBatch(batch map[string][]ipv4.Message) {
	defer server.nonFatalRecover()

	wg := sync.WaitGroup{}

	for iface := range batch {
		wg.Add(1)
		go func(iface string, pkts []ipv4.Message, wg *sync.WaitGroup) {
			defer server.nonFatalRecover()
			defer wg.Done()
			conn := server.udpconnpool.Pick(iface)
			if conn == nil {
				server.Panicf("Unknown interface %s", iface)
			}

			// nbytes := 0
			// npkts := 0
			for len(pkts) > 0 {
				if n, err := conn.WriteBatch(pkts, 0); err == nil {
					// for k := range pkts[:n] {
					// 	nbytes += len(pkts[k].Buffers[0])
					// }
					// npkts += n
					pkts = pkts[n:]
				} else {
					// compatibility issue:
					// for linux kernel<=2.6.32, support for sendmmsg is not available
					// an error of type os.SyscallError will be returned
					// if operr, ok := err.(*net.OpError); ok {
					// 	if se, ok := operr.Err.(*os.SyscallError); ok {
					// 		if se.Syscall == "sendmmsg" {
					// 			// sendmmsg not available
					// 			// s.xconnWriteError = se
					// 			// s.defaultTx(txqueue)
					// 			return
					// 		}
					// 	}
					// }
					server.Printf("batch send exception: %v", err)

					// s.notifyWriteError(errors.WithStack(err))
					break
				}
			}
		}(iface, batch[iface], &wg)
	}

	wg.Wait()

	// garbage collect
	// for iface, _ := range batch {
	// 	for i := range batch[iface] {
	// 		xmitBuf.Put(batch[iface][i].Buffers[0])
	// 	}
	// }

	return
}

func (server *Server) handleUDPMOTD(tmp32 uint32, rand uint64) (buffer *bytes.Buffer) {
	buffer = bytes.NewBuffer(make([]byte, 0, 24))
	_ = binary.Write(buffer, binary.BigEndian, uint32(verProtover))
	_ = binary.Write(buffer, binary.BigEndian, rand)
	_ = binary.Write(buffer, binary.BigEndian, uint32(server.clients.Len()))
	if server.cfg.MaxUsers > 0 {
		_ = binary.Write(buffer, binary.BigEndian, uint32(server.cfg.MaxUsers))
	} else {
		_ = binary.Write(buffer, binary.BigEndian, uint32(4294967295))
	}
	_ = binary.Write(buffer, binary.BigEndian, uint32(server.cfg.MaxBandwidth))
	return
}

// Listen for and handle UDP packets.
func (server *Server) udpListenLoop(conn *ipv4.PacketConn) {
	server.netwg.Add(1)
	defer server.netwg.Done()

	msgs := make([]ipv4.Message, batchSize)
	for k := range msgs {
		msgs[k].Buffers = [][]byte{(*(xmitBuf.Get().(*[]byte)))[0:mtuLimit]}
	}

	for {
		if !server.running {
			return
		}

		// buf := make([]byte, UDPPacketSize)

		if count, err := conn.ReadBatch(msgs, 0); err == nil {
			for i := 0; i < count; i++ {
				msg := &msgs[i]
				// if src == "" { // set source address if nil
				// 	src = msg.Addr.String()
				// } else if msg.Addr.String() != src {
				// 	atomic.AddUint64(&DefaultSnmp.InErrs, 1)
				// 	continue
				// }

				//udpaddr := msg.Addr.(*net.UDPAddr)
				// copy a udpaddr
				oudpaddr := msg.Addr.(*net.UDPAddr)

				dupIP := make(net.IP, len(oudpaddr.IP))
				copy(dupIP, oudpaddr.IP)

				udpaddr := &net.UDPAddr{
					IP:   dupIP,
					Port: oudpaddr.Port,
					Zone: oudpaddr.Zone,
				}

				buf := msg.Buffers[0][:msg.N]
				msg.Buffers = [][]byte{(*(xmitBuf.Get().(*[]byte)))[0:mtuLimit]}
				// buf := xmitBuf.Get().([]byte)[:msg.N]
				// copy(buf, msg.Buffers[0][:msg.N])

				// Length 12 is for ping datagrams from the ConnectDialog.
				if msg.N == 12 {
					if !server.cfg.AllowPing {
						continue
					}
					readbuf := bytes.NewReader(buf)
					var (
						tmp32 uint32
						rand  uint64
					)
					_ = binary.Read(readbuf, binary.BigEndian, &tmp32)
					_ = binary.Read(readbuf, binary.BigEndian, &rand)

					readbuf = nil
					xmitBuf.Put(&buf)

					buffer := server.handleUDPMOTD(tmp32, rand)
					// err = server.SendUDP(buffer.Bytes(), udpaddr)
					_, err = conn.WriteTo(buffer.Bytes(), nil, udpaddr)
					if err != nil {
						server.Printf("Error occurred sending UDP ping-back packet: %+v\n", xerrors.WithStack(err))
						continue
					}
				} else if server.cfg.AllowUDPVoice {
					// Safe, as cleanupPerInitData calls pretty late.

					server.udpIncomingQueue <- &udpAddressPacket{
						addr: udpaddr,
						data: buf, // buf[0:nread]
					}
				}
			}
		} else {
			// compatibility issue:
			// for linux kernel<=2.6.32, support for sendmmsg is not available
			// an error of type os.SyscallError will be returned
			if isTimeout(err) {
				continue
			} else {
				if server.running {
					panic(fmt.Sprintf("Error occurred on UDP listener: %v\n", err))
				} else {
					return
				}
				// return
			}
		}

		// nread, _, remote, err := conn.ReadFrom(buf)
		// if err != nil {
		// 	if isTimeout(err) {
		// 		continue
		// 	} else {
		// 		return
		// 	}
		// }

		// udpaddr, ok := remote.(*net.UDPAddr)
		// if !ok {
		// 	server.Printf("No UDPAddr in read packet. Disabling UDP. (Windows?)")
		// 	return
		// }
	}
}

func (server *Server) udpRecvLoop() {
	defer server.recover()

	for packet := range server.udpIncomingQueue {
		server.handleUDPPacket(packet.addr, packet.data)
	}
}

func (server *Server) handleUDPPacket(udpaddr *net.UDPAddr, buf []byte) {
	defer server.nonFatalRecover()
	defer xmitBuf.Put(&buf)

	var match *Client
	// plain := make([]byte, len(buf))
	plain := (*(xmitBuf.Get().(*[]byte)))[:len(buf)]

	// Determine which client sent the the packet.  First, we
	// check the map 'hpclients' in the server struct. It maps
	// a hort-post combination to a client.
	//
	// If we don't find any matches, we look in the 'hclients',
	// which maps a host address to a slice of clients.

	c, ok := server.hpclients.Load(udpaddr.String())
	if ok {
		client := c.(*Client)
		err := client.crypt.Decrypt(plain, buf)
		if err != nil {
			client.Debugf("HPMatch: unable to decrypt incoming packet, requesting resync: %v", err)
			client.cryptResync()
			// delete(server.hpclients, udpaddr.String())
			return
		}
		match = client
	} else {
		host := udpaddr.IP.String()

		server.hmutex.Lock()
		hostclients := server.hclients[host]
		server.hmutex.Unlock()
		for _, client := range hostclients {
			if client.disconnected || client.state > StateClientReady || client.state < StateClientAuthenticated {
				continue
			}
			err := client.crypt.Decrypt(plain[0:], buf)
			if err != nil {
				// client.Debugf("HMatch:  decrypt incoming packet, requesting resync: %v", err)
				// client.cryptResync()
				// return
				server.Debugf("Failed match %s to %d", udpaddr.String(), client.Session())
				continue
			} else {
				server.Debugf("Succeed match %s to %d", udpaddr.String(), client.Session())
				match = client
			}
		}

		if match != nil {
			match.udpaddr = udpaddr
			server.hpclients.Store(udpaddr.String(), match)
		} else {
			server.Debugf("Unable to match any client on UDP Address: %s", udpaddr.String())
		}
	}

	if match == nil {
		return
	}

	if match.disconnected {
		return
	}

	atomic.AddUint64(&match.UDPTotalPackets, 1)
	atomic.AddUint64(&match.UDPVolume, uint64(len(buf)))

	// Resize the plaintext slice now that we know
	// the true encryption overhead.
	plain = plain[:len(plain)-match.crypt.Overhead()]

	match.udp = true

	// Safe, as panics are recovered in this function
	match.udprecv <- plain

	return
}

// ClearCaches clears the Server's caches
func (server *Server) ClearCaches() {

	// Clear ACL Cache
	server.aclQueryCache.Purge()
	server.channelCache.Purge()

	// Clear VoiceTarget Cache
	for _, client := range server.Clients() {
		client.ClearCaches()
	}

	query := &mumbleproto.PermissionQuery{
		Flush: proto.Bool(true),
	}

	server.broadcastProtoMessage(query)
}

func (server *Server) ClearVTCache() {
	for _, client := range server.Clients() {
		client.ClearCaches()
	}
}

// ClearCachesByUser clear cache of a user
func (server *Server) ClearCachesByUser(client *Client) {
	prefix := fmt.Sprintf("%d:", client.Session())

	server.aclQueryCache.RemoveWithCallback(func(key interface{}) bool {
		return strings.HasPrefix(key.(string), prefix)
	})

	// Clear VoiceTarget Cache
	for _, client := range server.Clients() {
		client.ClearCaches()
	}

	query := &mumbleproto.PermissionQuery{
		Flush: proto.Bool(true),
	}

	err := client.sendMessage(query)
	if err != nil {
		client.Panic(err)
	}
}

func (server *Server) clearACLStoreCache() {
	server.aclStoreCache.Purge()
}

// Helper method for users entering new channels
func (server *Server) userEnterChannel(client *Client, channel *Channel, userstate *mumbleproto.UserState) {

	// log
	if client.channel != nil {
		oldName := client.channel.Name
		oldID := client.channel.ID
		newName := channel.Name
		newID := channel.ID
		server.Logger.Printf("User %s(%d, %d) moved from %s(%d) to %s(%d)", client.ShownName(), client.Session(), client.UserId(), oldName, oldID, newName, newID)
	} else {
		newName := channel.Name
		newID := channel.ID
		server.Logger.Printf("User %s(%d, %d) joined %s(%d)", client.ShownName(), client.Session(), client.UserId(), newName, newID)
	}

	if client.channelID != channel.ID {
		client.assignChannel(channel)
	}

	// oldchan := client.Channel
	// if oldchan != nil {
	// 	oldchan.RemoveClient(client)
	// 	if oldchan.IsTemporary() && oldchan.IsEmpty() {
	// 		server.tempRemove <- oldchan
	// 	}
	// }

	client.SetLastChannel(channel.ID)

	server.ClearCachesByUser(client)

	// server.UpdateFrozenUserLastChannel(client)

	canspeak := HasPermission(channel, client, SpeakPermission, []string{})
	if canspeak == client.Suppress {
		client.Suppress = !canspeak
		userstate.Suppress = proto.Bool(client.Suppress)
	}

	server.sendClientPermissions(client, channel)
	if channel.ParentID > -1 {
		server.sendClientPermissions(client, channel.Parent())
	}
}

func (server *Server) refreshChannelPermission(channel *Channel) {
	for _, client := range channel.Clients() {
		canSpeak := HasPermission(channel, client, SpeakPermission, []string{})
		if canSpeak == client.Suppress {
			client.Suppress = !canSpeak
			server.sendClientPermissions(client, channel)
			userstate := &mumbleproto.UserState{}
			userstate.Session = proto.Uint32(client.Session())
			userstate.Suppress = proto.Bool(client.Suppress)
			server.broadcastUserState(userstate)
		}

		chanstate := &mumbleproto.ChannelState{}
		chanstate.ChannelId = proto.Uint32(uint32(channel.ID))
		chanstate.IsEnterRestricted = proto.Bool(HasSomehowRestricted(channel, EnterPermission))
		chanstate.CanEnter = proto.Bool(HasPermission(channel, client, EnterPermission, []string{}))
		client.queueMessage(&waitableMessage{
			wg:  nil,
			msg: chanstate,
		})
	}
}

// RegisterClient register a client on the server.
func (server *Server) RegisterClient(client *Client) (uid uint32, err error) {
	// Increment nextUserId only if registration succeeded.
	// defer func() {
	// 	if err == nil {
	// 		s.nextUserId += 1
	// 	}
	// }()

	// user, err := NewUser(s.nextUserId, client.Username)
	// if err != nil {
	// 	return 0, err
	// }

	// // Grumble can only register users with certificates.
	// if !client.HasCertificate() {
	// 	return 0, errors.New("no cert hash")
	// }

	// user.Email = client.Email
	// user.CertHash = client.CertHash()

	// uid = s.nextUserId
	// s.Users[uid] = user
	// s.UserCertMap[client.CertHash()] = user
	// s.UserNameMap[client.Username] = user

	// return uid, nil
	return 0, errors.New("registration is disabled")
}

// RemoveRegistration removes a registered user.
func (server *Server) RemoveRegistration(uid uint32) (err error) {
	// user, ok := s.Users[uid]
	// if !ok {
	// 	return errors.New("Unknown user ID")
	// }

	// // Remove from user maps
	// delete(s.Users, uid)
	// delete(s.UserCertMap, user.CertHash)
	// delete(s.UserNameMap, user.Name)

	// // Remove from groups and ACLs.
	// s.removeRegisteredUserFromChannel(uid, s.RootChannel())

	return nil
}

// Remove references for user id uid from channel. Traverses subchannels.
func (server *Server) removeRegisteredUserFromChannel(uid uint32, channel *Channel) {

	// newACL := []acl.ACL{}
	// for _, chanacl := range channel.ACL.ACLs {
	// 	if chanacl.UserId == int(uid) {
	// 		continue
	// 	}
	// 	newACL = append(newACL, chanacl)
	// }
	// channel.ACL.ACLs = newACL

	// for _, grp := range channel.ACL.Groups {
	// 	if _, ok := grp.Add[int(uid)]; ok {
	// 		delete(grp.Add, int(uid))
	// 	}
	// 	if _, ok := grp.Remove[int(uid)]; ok {
	// 		delete(grp.Remove, int(uid))
	// 	}
	// 	if _, ok := grp.Temporary[int(uid)]; ok {
	// 		delete(grp.Temporary, int(uid))
	// 	}
	// }

	// for _, subChan := range channel.children {
	// 	s.removeRegisteredUserFromChannel(uid, subChan)
	// }

	return
}

// RemoveChannel removes a channel
func (server *Server) RemoveChannel(channel *Channel) {
	// Can't remove root
	if channel.ID == 0 {
		return
	}

	// Remove all links
	// for _, linkedChannel := range channel.GetLinks() {
	// 	// delete(linkedChannel.Links, channel.Id)
	// 	server.UnlinkChannels(channel, linkedChannel)
	// }

	// Remove all subchannels
	for _, subChannel := range channel.Childrens() {
		server.RemoveChannel(&subChannel)
	}

	// Remove all clients

	target := server.DefaultChannel()
	for _, client := range channel.Clients() {
		func(server *Server, client *Client, target *Channel) {
			// Lock userEnterChannel into a closure to prevent panic leak
			defer client.recover(nil)
			client.MoveChannel(target, nil)
			// userstate := &mumbleproto.UserState{}
			// userstate.Session = proto.Uint32(client.Session())
			// userstate.ChannelId = proto.Uint32(uint32(target.ID))
			// server.userEnterChannel(client, target, userstate)
			// server.broadcastUserState(userstate)
		}(server, client, target)

	}

	// Remove the channel itself
	channel.RemoveChannel()
	chanremove := &mumbleproto.ChannelRemove{
		ChannelId: proto.Uint32(uint32(channel.ID)),
	}
	server.broadcastProtoMessage(chanremove)
}

// FilterText Filter incoming text according to the server's current rules.
func (server *Server) FilterText(text string) (filtered string, err error) {
	options := &htmlfilter.Options{
		StripHTML:             !server.cfg.AllowHTML,
		MaxTextMessageLength:  server.cfg.MaxTextMessageLength,
		MaxImageMessageLength: server.cfg.MaxImageMessageLength,
	}
	return htmlfilter.Filter(text, options)
}

// The accept loop of the server.
func (server *Server) acceptLoop(listener net.Listener) {
	server.netwg.Add(1)
	defer server.netwg.Done()

	for {
		if !server.running {
			return
		}

		// New client connected
		conn, err := listener.Accept()
		if err != nil {
			if isTimeout(err) {
				continue
			} else if !server.running {
				return
			} else {
				server.Panicf("Unable to accept new connections: %v", err)
				return
			}
		}

		go server.handleNewConnection(conn)
	}
}

func (server *Server) handleNewConnection(conn net.Conn) {
	// GOROUTINE START
	defer server.nonFatalRecover()

	conn.SetDeadline(time.Now().Add(time.Duration(server.cfg.Timeout) * time.Second))

	var realip *net.TCPAddr

	addr := conn.RemoteAddr()
	if addr == nil {
		server.Debugf("%s", "Unable to extract address for client.")
		conn.SetDeadline(time.Now().Add(1 * time.Second))
		conn.Close()
		return
	}

	tcpaddr := addr.(*net.TCPAddr)

	laddr := conn.LocalAddr().(*net.TCPAddr).IP

	server.Printf("Incoming connection: %v", tcpaddr)

	if server.cfg.AcceptProxyProtocol {
		if CheckIpInRangeList(tcpaddr.IP, server.cfg.TrustedProxies) {
			err := conn.(*proxyProtocol.TCPConn).ProxyHandshake()
			if err == io.EOF {
				err := conn.Close()
				if err != nil {
					server.Printf("Unable to close connection: %v", err)
				}
				return
			} else if err != nil {
				server.Printf("Unable to recognize PROXY Protocol on connection %v: %v", addr, err)
				err := conn.Close()
				if err != nil {
					server.Printf("Unable to close connection: %v", err)
				}
				return
			}
		}

		realaddr := conn.(*proxyProtocol.TCPConn).RealRemoteAddr().(*net.TCPAddr)
		realip = &net.TCPAddr{
			IP:   realaddr.IP,
			Port: realaddr.Port,
		}
	} else {
		realip = &net.TCPAddr{
			IP:   tcpaddr.IP,
			Port: tcpaddr.Port,
			Zone: tcpaddr.Zone,
		}
	}

	// Remove expired bans
	// server.RemoveExpiredBans()

	// Is the client IP-banned?
	if server.IsConnectionBanned(realip.IP) {
		server.Printf("Rejected client %v: Banned", realip)
		err := conn.Close()
		if err != nil {
			server.Printf("Unable to close connection: %v", err)
		}
		return
	}

	// Create a new client connection from our *tls.Conn
	// which wraps net.TCPConn.
	server.handleIncomingClient(conn, realip, laddr)
	return
}

// The isTimeout function checks whether a
// network error is a timeout.
func isTimeout(err error) bool {
	if e, ok := err.(net.Error); ok {
		return e.Timeout()
	}
	return false
}

// Initialize the per-launch data
func (server *Server) initPerLaunchData() {
	server.pool = sessionpool.New()
	server.clients = NewClientStorage(server.maxUsers())
	server.hclients = make(map[string][]*Client, server.maxUsers())

	server.bye = make(chan bool)
	// server.incoming = make(chan *Message)
	// server.voicebroadcast = make(chan *VoiceBroadcast)
	server.udpIncomingQueue = make(chan *udpAddressPacket, 65536)
	server.udpBatchSendQueue = make(chan map[string][]ipv4.Message, 65536)
	// server.tempRemove = make(chan *Channel, 1)
	server.afterAuth = make(chan *Client, 5000)
}

// Clean per-launch data
func (server *Server) cleanPerLaunchData() {
	server.pool = nil
	// server.clients = nil
	server.clients = nil
	server.hclients = nil
	// server.hpclients = nil

	server.bye = nil
	// server.incoming = nil
	// server.voicebroadcast = nil
	close(server.udpIncomingQueue)
	close(server.udpBatchSendQueue)
	close(server.afterAuth)
	server.udpIncomingQueue = nil
	// server.tempRemove = nil
	server.afterAuth = nil
}

// Port returns the port the native server will listen on when it is
// started.
func (server *Server) Port() int {
	port := server.cfg.Port
	if port == 0 {
		return DefaultPort + int(server.ID) - 1
	}
	return port
}

// WebPort returns the port the web server will listen on when it is
// started.
// func (server *Server) WebPort() int {
// 	port := server.cfg.IntValue("WebPort")
// 	if port == 0 {
// 		return DefaultWebPort + int(server.Id) - 1
// 	}
// 	return port
// }

// CurrentPort returns the port the native server is currently listening
// on.  If called when the server is not running,
// this function returns -1.
func (server *Server) CurrentPort() int {
	if !server.running {
		return -1
	}
	tcpaddr := server.tcpl.Addr().(*net.TCPAddr)
	return tcpaddr.Port
}

// HostAddress returns the host address the server will listen on when
// it is started. This must be an IP address, either IPv4
// or IPv6.
func (server *Server) HostAddress() string {
	host := server.cfg.Host
	if host == "" {
		return "0.0.0.0"
	}
	return host
}

// Start the server.
func (server *Server) Start() (err error) {
	if server.running {
		return errors.New("already running")
	}

	// Reset the server's per-launch data to
	// a clean state.
	server.initPerLaunchData()

	host := server.HostAddress()
	port := server.Port()
	// webport := server.WebPort()

	// var timeout int
	// if server.cfg.Timeout == 0 {
	// 	timeout = server.cfg.Timeout
	// } else {
	// 	timeout = 30000
	// }

	// Set up our TCP connection
	tcpl, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP(host), Port: port})
	if err != nil {
		return err
	}
	server.tcpl = &proxyProtocol.TCPProxyListener{
		Listener:           tcpl,
		ProxyHeaderTimeout: 30 * time.Second,
	}

	/*
	   err = server.tcpl.SetTimeout(server.cfg.Timeout)
	   if err != nil {
	       return err
	   }
	*/

	// Wrap a TLS listener around the TCP connection
	certFn := filepath.Join(server.dataDir, server.cfg.SSLCert)
	keyFn := filepath.Join(server.dataDir, server.cfg.SSLKey)
	//cert, err := tls.LoadX509KeyPair(certFn, keyFn)
	cm, err := certman.New(certFn, keyFn)
	if err != nil {
		return err
	}
	cm.Logger(server)
	if err := cm.Watch(); err != nil {
		return err
	}
	server.tlscfg = &tls.Config{
		GetCertificate:           cm.GetCertificate,
		ClientAuth:               tls.RequestClientCert,
		PreferServerCipherSuites: true,
		CurvePreferences: []tls.CurveID{
			tls.CurveP256,
			tls.X25519, // Go 1.8 only
		},
		MinVersion: tls.VersionTLS12,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
	// server.tlsl = tls.NewListener(server.tcpl, server.tlscfg)

	// Create HTTP server and WebSocket "listener"
	// webaddr := &net.TCPAddr{IP: net.ParseIP(host), Port: webport}
	// server.webtlscfg = &tls.Config{
	// 	Certificates: []tls.Certificate{cert},
	// 	ClientAuth:   tls.NoClientCert,
	// 	NextProtos:   []string{"http/1.1"},
	// }
	// server.webwsl = web.NewListener(webaddr, server.Logger)
	// mux := http.NewServeMux()
	// mux.Handle("/", server.webwsl)
	// server.webhttp = &http.Server{
	// 	Addr:      webaddr.String(),
	// 	Handler:   mux,
	// 	TLSConfig: server.webtlscfg,
	// 	ErrorLog:  server.Logger,

	// 	// Set sensible timeouts, in case no reverse proxy is in front of Grumble.
	// 	// Non-conforming (or malicious) clients may otherwise block indefinitely and cause
	// 	// file descriptors (or handles, depending on your OS) to leak and/or be exhausted
	// 	ReadTimeout: 5 * time.Second,
	// 	WriteTimeout: 10 * time.Second,
	// 	IdleTimeout: 2 * time.Minute,
	// }
	// go func() {
	// 	err := server.webhttp.ListenAndServeTLS("", "")
	// 	if err != http.ErrServerClosed {
	// 		server.Fatalf("Fatal HTTP server error: %v", err)
	// 	}
	// }()

	// server.Printf("Started: listening on %v and %v", server.tcpl.Addr(), server.webwsl.Addr())

	server.Printf("Started: listening on %v", server.tcpl.Addr())
	server.running = true

	// Launch the event handler goroutine
	go server.handlerLoop()
	go server.afterAuthLoop()
	go server.udpRecvLoop()
	go server.udpQueueLoop()

	// Add the three network receiver goroutines to the net waitgroup
	// and launch them.
	//
	// We use the waitgroup to provide a blocking Stop() method
	// for the servers. Each network goroutine defers a call to
	// netwg.Done(). In the Stop() we close all the connections
	// and call netwg.Wait() to wait for the goroutines to end.
	// server.netwg.Add(3)

	go server.acceptLoop(server.tcpl)
	// go server.acceptLoop(server.webwsl)

	// Setup our UDP connection pool
	if server.cfg.AllowUDP {
		server.udpconnpool, err = NewPacketConnPool(0, server.udpConnFactory, server.udpConnDestory)
		if err != nil {
			return err
		}
	}

	// Schedule a server registration update (if needed)
	if server.cfg.Publish {
		go func() {
			time.Sleep(1 * time.Minute)
			server.RegisterPublicServer()
		}()
	}

	return nil
}

// Stop the server.
func (server *Server) Stop() {
	if !server.running {
		return
	}

	server.Printf("Handling gracefully exit...")

	server.stopOnce.Do(func() { server.stop() })
}

func (server *Server) stop() {
	if !server.running {
		return
	}

	server.running = false
	server.bye <- true

	for _, client := range server.clients.Snapshot() {
		client.ForceDisconnect()
	}

	// Wait for the HTTP server to shutdown gracefully
	// A client could theoretically block the server from ever stopping by
	// never letting the HTTP connection go idle, so we give 15 seconds of grace time.
	// This does not apply to opened WebSockets, which were forcibly closed when
	// all clients were disconnected.
	// ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(15*time.Second))
	// err = server.webhttp.Shutdown(ctx)
	// cancel()
	// if err == context.DeadlineExceeded {
	// 	server.Println("Forcibly shutdown HTTP server while stopping")
	// } else if err != nil {
	// 	return err
	// }

	server.Printf("Closing listeners...")

	// Close the UDP connection
	if server.cfg.AllowUDP {
		server.udpconnpool.Destory()
	}

	// Close the listeners
	err := server.tcpl.Close()
	if err != nil {
		server.Fatal(err)
	}

	// if err != nil {
	// 	server.Fatal(err)
	// }

	server.Printf("Waiting for handlers to exit cleanly...")

	// Wait for the three network receiver
	// goroutines end.
	server.netwg.Wait()

	server.cleanPerLaunchData()
	db, _ := server.db.DB()
	if db != nil {
		_ = db.Close()
	}
	// server.running = false
	server.Printf("Stopped")

	return
}
