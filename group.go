package main

import (
	"net"
	"strconv"
	"strings"
)

const (
	IPGroupMaskDisable = iota
	IPGroupMaskFullMatch
	IPGroupMaskCIDR
	IPGroupMaskASN
	IPGroupMaskCountryCode
	IPGroupMaskOrganization
)

// GroupMemberCheck checks whether a user is a member
// of the group as defined in the given context.
//
// The 'current' context is the context that group
// membership is currently being evaluated for.
//
// The 'acl' context is the context of the ACL that
// that group membership is being evaluated for.
//
// The acl context will always be either equal to
// current, or be an ancestor.
func GroupMemberCheck(current *Channel, acl *Channel, name string, client *Client, temporaryTokens []string) (ok bool) {
	valid := true
	invert := false
	token := false
	hash := false
	ipmask := IPGroupMaskDisable

	// Returns the 'correct' return value considering the value
	// of the invert flag.
	defer func() {
		if valid && invert {
			ok = !ok
		}
	}()

	channel := current

	for {
		// Empty group name are not valid.
		if len(name) == 0 {
			valid = false
			return false
		}
		// Invert
		if name[0] == '!' {
			invert = true
			name = name[1:]
			continue
		}
		// Evaluate in target channel (not current channel)
		if name[0] == '~' {
			channel = acl
			name = name[1:]
			continue
		}
		// Token
		if name[0] == '#' {
			token = true
			name = name[1:]
			break
		}
		// Hash
		if name[0] == '$' {
			hash = true
			name = name[1:]
			break
		}
		// IP Mask
		if name[0] == '%' {
			if name[1] == '!' {
				ipmask = IPGroupMaskCIDR
			} else if name[1] == '@' {
				ipmask = IPGroupMaskASN
			} else if name[1] == '#' {
				ipmask = IPGroupMaskCountryCode
			} else if name[1] == '$' {
				ipmask = IPGroupMaskOrganization
			} else {
				ipmask = IPGroupMaskFullMatch
			}
			name = name[2:]
			break
		}
		break
	}

	if token {
		// The user is part of this group if the remaining name is part of
		// his access token list. The name check is case-insensitive.
		for _, token := range client.Tokens() {
			if strings.ToLower(name) == strings.ToLower(token) {
				return true
			}
		}

		for _, token := range temporaryTokens {
			if strings.ToLower(name) == strings.ToLower(token) {
				return true
			}
		}
		return false
	} else if hash {
		// The client is part of this group if the remaining name matches the
		// client's cert hash.
		if strings.ToLower(name) == strings.ToLower(client.CertHash()) {
			return true
		}
		return false
	} else if ipmask > IPGroupMaskDisable {
		if ipmask == IPGroupMaskFullMatch {
			targetIP := net.ParseIP(name)
			if targetIP == nil {
				return false
			}
			return targetIP.Equal(client.realip.IP)
		} else if ipmask == IPGroupMaskCIDR {
			_, subnet, err := LenientParseCIDR(name)
			if err != nil {
				return false
			} else if subnet == nil {
				return false
			}

			return subnet.Contains(client.realip.IP)
		} else if ipmask == IPGroupMaskASN {
			geoip, err := client.GeoIP()
			if err != nil {
				return false
			} else if geoip == nil {
				return false
			}
			targetASN, err := strconv.Atoi(name)
			if err != nil {
				return false
			}
			return geoip.ASNumber == targetASN
		} else if ipmask == IPGroupMaskCountryCode {
			geoip, err := client.GeoIP()
			if err != nil {
				return false
			} else if geoip == nil {
				return false
			}
			return strings.ToLower(geoip.CountryCode) == strings.ToLower(name)
		} else if ipmask == IPGroupMaskOrganization {
			geoip, err := client.GeoIP()
			if err != nil {
				return false
			} else if geoip == nil {
				return false
			}
			return strings.Contains(strings.ToLower(geoip.Organization), strings.ToLower(name))
		}
	} else if name == "none" {
		// None
		return false
	} else if name == "all" {
		// Everyone
		return true
	} else if name == "auth" {
		// The user is part of the auth group is he is authenticated. That is,
		// his UserId is >= 0.
		return client.IsRegistered()
	} else if name == "strong" {
		// The user is part of the strong group if he is authenticated to the server
		// via a strong certificate (i.e. non-self-signed, trusted by the server's
		// trusted set of root CAs).
		return client.IsVerified()
	} else if name == "in" {
		// Is the user in the currently evaluated channel?
		return client.channelID == channel.ID
	} else if name == "out" {
		// Is the user not in the currently evaluated channel?
		return client.channelID != channel.ID
	} else {
		groups := client.Groups()

		for _, g := range groups {
			if strings.TrimSpace(strings.ToLower(g)) == strings.TrimSpace(strings.ToLower(name)) {
				return true
			}
		}

		return false
	}
	return false
}
