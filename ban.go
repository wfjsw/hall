package main

import (
	"net"
	"time"

	"gorm.io/gorm"
)

const (
	isoDate = "2006-01-02T15:04:05"
)

type Ban struct {
	gorm.Model

	Address  []byte `gorm:"not null"`
	Mask     int    `gorm:"not null"`
	Name     string
	Hash     string
	Reason   string
	Start    int64
	Duration int
}

func (server *Server) GetAllBanList() []Ban {
	var bans []Ban
	server.db.Model(&Ban{}).Where("start + duration > ? OR duration = 0", time.Now().Unix()).Find(&bans)
	return bans
}

func (server *Server) PurgeBanList() {
	server.db.Exec("DELETE FROM bans;")
	server.db.Exec("UPDATE sqlite_sequence SET seq = 0 WHERE name = 'bans';")
	server.db.Exec("VACUUM")
	return
}

func (server *Server) OverrideBanList(banList []Ban) {
	server.PurgeBanList()
	for _, b := range banList {
		server.db.Create(&b)
	}
	return
}

// AppendBan append a ban to the banlist
func (server *Server) AppendBan(ban *Ban) {
	server.db.Create(ban)
	return
}

// IsCertHashBanned Is the certificate hash banned?
func (server *Server) IsCertHashBanned(hash string) bool {
	var count int64

	server.db.Model(&Ban{}).Where("hash = ? AND (start + duration > ? OR duration = 0)", hash, time.Now().Unix()).Count(&count)

	return count > 0
}

func (ban Ban) IPMask() (mask net.IPMask) {
	allbits := ban.Mask
	for i := 0; i < 16; i++ {
		bits := allbits
		if bits > 0 {
			if bits > 8 {
				bits = 8
			}
			mask = append(mask, byte((1<<uint(bits))-1))
		} else {
			mask = append(mask, byte(0))
		}
		allbits -= 8
	}
	return
}

// Match checks whether an IP matches a Ban
func (ban Ban) Match(ip net.IP) bool {
	bannedIP := net.IP(ban.Address)
	banned := bannedIP.Mask(ban.IPMask())
	masked := ip.Mask(ban.IPMask())
	return banned.Equal(masked)
}

// IsConnectionBanned Is the incoming connection conn banned?
func (server *Server) IsConnectionBanned(IP net.IP) bool {
	bans := server.GetAllBanList()
	// addr := conn.RemoteAddr().(*net.TCPAddr)

	for _, ban := range bans {
		if ban.Match(IP) {
			return true
		}
	}

	if r, o := server.tempIPBan.Get(IP.String()); o == true && time.Now().Unix()-r.(int64) < 10*60 {
		return true
	}

	return false
}

// SetISOStartDate Set Start date from an ISO 8601 date (in UTC)
func (ban *Ban) SetISOStartDate(isodate string) {
	startTime, err := time.Parse(isoDate, isodate)
	if err != nil {
		ban.Start = 0
	} else {
		ban.Start = startTime.Unix()
	}
}

// ISOStartDate returns the currently set start date as an ISO 8601-formatted
// date (in UTC).
func (ban Ban) ISOStartDate() string {
	startTime := time.Unix(ban.Start, 0).UTC()
	return startTime.Format(isoDate)
}
