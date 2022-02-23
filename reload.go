package main

import (
	"github.com/wfjsw/hall/mumbleproto"
	"google.golang.org/protobuf/proto"
)

func (server *Server) ReloadConfig(newCfg ServerConfig) {
	defer server.recover()

	serverConfig := &mumbleproto.ServerConfig{}
	doSendServerConfigUpdate := false

	var err error

	if server.cfg.Debug != newCfg.Debug {
		server.cfg.Debug = newCfg.Debug
	}

	if server.cfg.WelcomeText != newCfg.WelcomeText {
		server.cfg.WelcomeText = newCfg.WelcomeText
		serverConfig.WelcomeText = proto.String(newCfg.WelcomeText)
		doSendServerConfigUpdate = true
	}

	if server.cfg.AcceptProxyProtocol != newCfg.AcceptProxyProtocol {
		server.cfg.AcceptProxyProtocol = newCfg.AcceptProxyProtocol
	}

	if server.cfg.MaxBandwidth != newCfg.MaxBandwidth {
		server.cfg.MaxBandwidth = newCfg.MaxBandwidth
		serverConfig.MaxBandwidth = proto.Uint32(uint32(newCfg.MaxBandwidth))
		doSendServerConfigUpdate = true
	}

	if server.cfg.MaxUsers != newCfg.MaxUsers {
		server.cfg.MaxUsers = newCfg.MaxUsers
		serverConfig.MaxUsers = proto.Uint32(uint32(newCfg.MaxUsers))
		doSendServerConfigUpdate = true
	}

	if server.cfg.MaxChannelUsers != newCfg.MaxChannelUsers {
		server.cfg.MaxChannelUsers = newCfg.MaxChannelUsers
	}

	if server.cfg.MaxMultipleLoginCount != newCfg.MaxMultipleLoginCount {
		server.cfg.MaxMultipleLoginCount = newCfg.MaxMultipleLoginCount
	}

	if server.cfg.MultiLoginLimitSameIP != newCfg.MultiLoginLimitSameIP {
		server.cfg.MultiLoginLimitSameIP = newCfg.MultiLoginLimitSameIP
	}

	if server.cfg.AllowUDP != newCfg.AllowUDP {
		if newCfg.AllowUDP == true {
			server.udpconnpool, err = NewPacketConnPool(0, server.udpConnFactory, server.udpConnDestory)
			if err != nil {
				panic(err)
			}
		} else {
			server.udpconnpool.Destory()
			server.udpconnpool = nil
			for _, client := range server.clients.Snapshot() {
				client.udp = false
			}
		}
	}

	if server.cfg.AllowUDPVoice != newCfg.AllowUDPVoice {
		server.cfg.AllowUDPVoice = newCfg.AllowUDPVoice
		if newCfg.AllowUDPVoice == false {
			for _, client := range server.clients.Snapshot() {
				client.udp = false
			}
		}
	}

	if server.cfg.AllowPing != newCfg.AllowPing {
		server.cfg.AllowPing = newCfg.AllowPing
	}

	if server.cfg.MaxTextMessageLength != newCfg.MaxTextMessageLength {
		server.cfg.MaxTextMessageLength = newCfg.MaxTextMessageLength
		serverConfig.MessageLength = proto.Uint32(uint32(newCfg.MaxTextMessageLength))
		doSendServerConfigUpdate = true
	}

	if server.cfg.MaxImageMessageLength != newCfg.MaxImageMessageLength {
		server.cfg.MaxImageMessageLength = newCfg.MaxImageMessageLength
		serverConfig.ImageMessageLength = proto.Uint32(uint32(newCfg.MaxImageMessageLength))
		doSendServerConfigUpdate = true
	}

	if server.cfg.AllowHTML != newCfg.AllowHTML {
		server.cfg.AllowHTML = newCfg.AllowHTML
		serverConfig.AllowHtml = proto.Bool(newCfg.AllowHTML)
		doSendServerConfigUpdate = true
	}

	if server.cfg.CertRequired != newCfg.CertRequired {
		server.cfg.CertRequired = newCfg.CertRequired
	}

	if server.cfg.SendVersion != newCfg.SendVersion {
		server.cfg.SendVersion = newCfg.SendVersion
	}

	if server.cfg.Timeout != newCfg.Timeout {
		server.cfg.Timeout = newCfg.Timeout
	}

	if server.cfg.DirectVoiceBehavior != newCfg.DirectVoiceBehavior {
		server.cfg.DirectVoiceBehavior = newCfg.DirectVoiceBehavior
	}

	if server.cfg.MinClientVersion != newCfg.MinClientVersion {
		server.cfg.MinClientVersion = newCfg.MinClientVersion
	}

	if server.cfg.RequireClientPlatformInfo != newCfg.RequireClientPlatformInfo {
		server.cfg.RequireClientPlatformInfo = newCfg.RequireClientPlatformInfo
	}

	if server.cfg.SendBuildInfo != newCfg.SendBuildInfo {
		server.cfg.SendBuildInfo = newCfg.SendBuildInfo
	}

	if server.cfg.APIUrl != newCfg.APIUrl {
		server.cfg.APIUrl = newCfg.APIUrl
	}

	if server.cfg.APIKey != newCfg.APIKey {
		server.cfg.APIKey = newCfg.APIKey
	}

	if server.cfg.APIInsecure != newCfg.APIInsecure {
		server.cfg.APIInsecure = newCfg.APIInsecure
	}

	if server.cfg.DefaultChannel != newCfg.DefaultChannel {
		server.cfg.DefaultChannel = newCfg.DefaultChannel
	}

	if server.cfg.OpusThreshold != newCfg.OpusThreshold {
		server.cfg.OpusThreshold = newCfg.OpusThreshold
	}

	if server.cfg.SuggestVersion != newCfg.SuggestVersion {
		server.cfg.SuggestVersion = newCfg.SuggestVersion
	}

	if server.cfg.SuggestPositional != newCfg.SuggestPositional {
		server.cfg.SuggestPositional = newCfg.SuggestPositional
	}

	if server.cfg.SuggestPushToTalk != newCfg.SuggestPushToTalk {
		server.cfg.SuggestPushToTalk = newCfg.SuggestPushToTalk
	}

	if server.cfg.CheckLastChannelPermission != newCfg.CheckLastChannelPermission {
		server.cfg.CheckLastChannelPermission = newCfg.CheckLastChannelPermission
	}

	if server.cfg.AllowGuest != newCfg.AllowGuest {
		server.cfg.AllowGuest = newCfg.AllowGuest
	}

	if server.cfg.UDPMarkUnstableRate != newCfg.UDPMarkUnstableRate {
		server.cfg.UDPMarkUnstableRate = newCfg.UDPMarkUnstableRate
	}

	if server.cfg.UseOfflineCache != newCfg.UseOfflineCache {
		server.cfg.UseOfflineCache = newCfg.UseOfflineCache
	}

	if server.cfg.Publish != newCfg.Publish {
		server.cfg.Publish = newCfg.Publish
	}

	if server.cfg.RegisterName != newCfg.RegisterName {
		server.cfg.RegisterName = newCfg.RegisterName
	}

	if server.cfg.RegisterUrl != newCfg.RegisterUrl {
		server.cfg.RegisterUrl = newCfg.RegisterUrl
	}

	if server.cfg.RegisterHostname != newCfg.RegisterHostname {
		server.cfg.RegisterHostname = newCfg.RegisterHostname
	}

	if server.cfg.RegisterPassword != newCfg.RegisterPassword {
		server.cfg.RegisterPassword = newCfg.RegisterPassword
	}

	if server.cfg.AllowRecording != newCfg.AllowRecording {
		server.cfg.AllowRecording = newCfg.AllowRecording
		serverConfig.RecordingAllowed = proto.Bool(newCfg.AllowRecording)
		doSendServerConfigUpdate = true
	}

	if doSendServerConfigUpdate {
		for _, client := range server.clients.Snapshot() {
			func() {
				client.recover(nil)
				err := client.sendMessage(serverConfig)
				if err != nil {
					panic(err)
				}
			}()
		}
	}

	if !server.cfg.AllowGuest {
		guests := server.clients.SnapshotWithFilter(func(sessionID uint32, c *Client) bool {
			return c.state >= StateClientAuthenticated && !c.IsRegistered()
		}, 1)

		for _, g := range guests {
			g.Disconnect()
		}
	}

	server.Println("Config Reloaded.")
}
