package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/wfjsw/hall/mumbleproto"
	"google.golang.org/protobuf/proto"
)

// TODO

type authenticatorResult struct {
	Status   int      `json:"status"`
	UserID   int      `json:"user_id"`
	Nickname string   `json:"nickname"`
	Groups   []string `json:"groups"`
}

type authenticatorUser struct {
	Password string   `json:"pw"`
	Username string   `json:"name"`
	Groups   []string `json:"groups"`
}

type AuthenticatorUsers map[string]authenticatorUser

func (server *Server) saveUserCache() {
	if server.userCache == nil {
		return
	}
	userList, err := json.Marshal(server.userCache)
	if err != nil {
		server.Logger.Printf("Unable to save user list: %v", err)
		return
	}

	strUserCachePath := filepath.Join(server.dataDir, "users.json")
	err = ioutil.WriteFile(strUserCachePath, userList, 0600)
	if err != nil {
		server.Logger.Printf("Unable to save user list: %v", err)
		return
	}

	return
}

func (server *Server) loadUserCache() {
	strUserCachePath := filepath.Join(server.dataDir, "users.json")

	bufUserList, err := ioutil.ReadFile(strUserCachePath)
	if err != nil {
		server.Logger.Printf("Unable to read user list (%v): %v", strUserCachePath, err)
		return
	}

	userList := make(AuthenticatorUsers)
	err = json.Unmarshal(bufUserList, &userList)
	if err != nil {
		server.Logger.Printf("Unable to decode user list (%v): %v", strUserCachePath, err)
		return
	}

	server.userCache = userList
	return
}

func (server *Server) PullUserList() {
	if !server.cfg.UseOfflineCache {
		return
	}

	apiURL := server.cfg.APIUrl
	apiKey := server.cfg.APIKey
	apiInsecure := server.cfg.APIInsecure
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: apiInsecure},
	}

	client := &http.Client{
		Transport: tr,
	}
	req, _ := http.NewRequest("POST", apiURL+"/data", nil)
	req.Header.Add("X-Token", apiKey)
	// req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", "0")
	resp, err := client.Do(req)
	if err != nil {
		server.Logger.Println("Authenticator connectivity error ", err.Error())
		return
	}

	defer resp.Body.Close()

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		server.Logger.Println("Authenticator reading error ", err.Error())
		return
	}

	userList := make(AuthenticatorUsers)
	err = json.Unmarshal(content, &userList)
	if err != nil {
		server.Logger.Println("Authenticator decoding error ", err.Error())
		return
	}

	server.userCache = userList

	go server.saveUserCache()
	return
}

func (server *Server) Authenticate(username string, password string, certificateHash string, sessionId uint32, ip string, version uint32, release string, os string, osversion string) (status int, userId int, nickname string, groups []string, err error) {

	status = -3

	if server.cfg.UseOfflineCache {
		resultdata, found := server.userCache[username]
		if !found {
			status = -2
			// return
		}

		if found && resultdata.Password != password {
			status = -2
			// return
		}

		if found && status != -2 {
			status = 0
			userId, _ = strconv.Atoi(username)
			nickname = resultdata.Username
			groups = resultdata.Groups
		}
	}

	if status == -3 || status == -2 {
		status, userId, nickname, groups, err = server.onlineAuthenticate(username, password, certificateHash, sessionId, ip, version, release, os, osversion)
	}

	return
}

func (server *Server) onlineAuthenticate(username string, password string, certificateHash string, sessionId uint32, ip string, version uint32, release string, os string, osversion string) (status int, userId int, nickname string, groups []string, err error) {
	apiURL := server.cfg.APIUrl
	apiKey := server.cfg.APIKey
	apiInsecure := server.cfg.APIInsecure
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: apiInsecure},
	}

	data := &url.Values{}
	data.Set("username", username)
	data.Set("password", password)
	data.Set("certificate_hash", certificateHash)
	data.Set("session_id", strconv.Itoa(int(sessionId)))
	data.Set("ip", ip)
	data.Set("version", strconv.Itoa(int(version)))
	data.Set("release", release)
	data.Set("os", os)
	data.Set("osversion", osversion)

	client := &http.Client{
		Transport: tr,
		Timeout:   time.Second * 5,
	}
	req, _ := http.NewRequest("POST", apiURL+"/authenticate", strings.NewReader(data.Encode()))
	req.Header.Add("X-Token", apiKey)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	req.Header.Add("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		server.Logger.Println("Authenticator connectivity error ", err.Error())
		status = -3
		return
	}

	defer resp.Body.Close()

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		server.Logger.Println("Authenticator reading error ", err.Error())
		status = -3
		return
	}

	resultdata := new(authenticatorResult)
	err = json.Unmarshal(content, resultdata)
	if err != nil {
		server.Logger.Println("Authenticator decoding error ", err.Error())
		status = -3
		return
	}

	status = resultdata.Status
	userId = resultdata.UserID
	nickname = resultdata.Nickname
	groups = resultdata.Groups
	return
}

func (server *Server) EndSession(sessionID uint32, userID int, logoutTime time.Time) {
	apiURL := server.cfg.APIUrl
	apiKey := server.cfg.APIKey
	apiInsecure := server.cfg.APIInsecure
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: apiInsecure},
	}

	data := &url.Values{}
	data.Set("session_id", strconv.Itoa(int(sessionID)))
	data.Set("group_id", strconv.Itoa(userID))
	data.Set("logout_time", logoutTime.Format(time.RFC3339))

	client := &http.Client{
		Transport: tr,
	}
	req, _ := http.NewRequest("POST", apiURL+"/logout", strings.NewReader(data.Encode()))
	req.Header.Add("X-Token", apiKey)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(data.Encode())))
	req.Header.Add("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		server.Logger.Println("Authenticator connectivity error ", err.Error())
		return
	}

	_ = resp.Body.Close()
}

type syncPayload struct {
	Users []syncPayloadUser `json:"users"`
}

type syncPayloadUser struct {
	SessionID uint32   `json:"session_id"`
	UserID    int      `json:"user_id"`
	Password  string   `json:"password"`
	Nickname  string   `json:"nickname"`
	Groups    []string `json:"groups"`
	ChannelID int      `json:"channel_id"`
}

type syncResponseItem struct {
	SessionID uint32    `json:"session_id"`
	Action    string    `json:"action"`
	Nickname  *string   `json:"nickname,omitempty"`
	Groups    *[]string `json:"groups,omitempty"`
}

func (server *Server) doSyncChannelUserList(userList []syncPayloadUser) {
	apiURL := server.cfg.APIUrl
	apiKey := server.cfg.APIKey
	apiInsecure := server.cfg.APIInsecure
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: apiInsecure},
	}

	payload := syncPayload{
		Users: userList,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		server.Logger.Println("Error marshalling sync payload: ", err.Error())
		return
	}

	client := &http.Client{
		Transport: tr,
	}
	req, _ := http.NewRequest("POST", apiURL+"/sync?type=1", bytes.NewReader(data))
	req.Header.Add("X-Token", apiKey)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Content-Length", strconv.Itoa(len(data)))
	req.Header.Add("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		server.Logger.Println("Error syncing user list: connectivity error ", err.Error())
		return
	}

	_ = resp.Body.Close()
}

func (server *Server) doSyncUserDetail(userList []syncPayloadUser) {
	apiURL := server.cfg.APIUrl
	apiKey := server.cfg.APIKey
	apiInsecure := server.cfg.APIInsecure
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: apiInsecure},
	}

	payload := syncPayload{
		Users: userList,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		server.Logger.Println("Error marshalling sync payload: ", err.Error())
		return
	}

	client := &http.Client{
		Transport: tr,
	}
	req, _ := http.NewRequest("POST", apiURL+"/sync?type=2", bytes.NewReader(data))
	req.Header.Add("X-Token", apiKey)
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Content-Length", strconv.Itoa(len(data)))
	req.Header.Add("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		server.Logger.Println("Error syncing user list: connectivity error ", err.Error())
		return
	}

	defer resp.Body.Close()

	content, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		server.Logger.Println("Error reading sync packet ", err.Error())
		return
	}

	var response []syncResponseItem
	err = json.Unmarshal(content, &response)
	if err != nil {
		server.Logger.Println("Error decoding sync packet ", err.Error())
		return
	}

	for _, item := range response {
		func() {
			defer server.nonFatalRecover()

			client, ok := server.clients.Get(item.SessionID)
			if !ok {
				server.Logger.Println("Error finding client for sync response ", item.SessionID)
				return
			}

			if item.Action == "kick" {
				client.Disconnect()
			} else if item.Action == "update" {
				userstate := &mumbleproto.UserState{}
				userstate.Session = proto.Uint32(item.SessionID)
				needBroadcast := false
				permChanged := false
				if item.Nickname != nil {
					client.Username = *item.Nickname
					userstate.Name = proto.String(*item.Nickname)
					needBroadcast = true
				}
				if item.Groups != nil {
					client.groups = *item.Groups
					permChanged = true
				}
				server.ClearCachesByUser(client)
				if !HasPermission(client.Channel(), client, EnterPermission, []string{}) {
					client.channelID = server.DefaultChannel().ID
					userstate.ChannelId = proto.Uint32(uint32(client.channelID))
					needBroadcast = true
				}
				if needBroadcast {
					server.broadcastUserState(userstate)
					server.ClearCachesByUser(client)
				}
				if permChanged && server.cfg.SendPermissionInfo {
					go client.sendChannelPermissions()
				}
			}
		}()
	}
}

func (server *Server) doSync() {

	userList := make([]syncPayloadUser, 0, server.clients.Len())
	// loop over clients
	for _, client := range server.clients.Snapshot() {
		user := syncPayloadUser{
			SessionID: client.Session(),
			UserID:    client.UserId(),
			Password:  client.Password,
			Nickname:  client.Username,
			Groups:    client.groups,
			ChannelID: client.channelID,
		}
		userList = append(userList, user)
	}

	server.doSyncChannelUserList(userList)

	// paginate by 50
	for i := 0; i < len(userList); i += 50 {
		if i+50 < len(userList) {
			go server.doSyncUserDetail(userList[i : i+50])
		} else {
			go server.doSyncUserDetail(userList[i:])
		}
	}

}
