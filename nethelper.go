package main

import (
	"fmt"
	"net"
	"strings"
)

// LenientParseCIDR parses CIDR just like net.ParseCIDR but also accept /32 IP.
func LenientParseCIDR(input string) (net.IP, *net.IPNet, error) {
	if !strings.Contains(input, "/") {
		if strings.Contains(input, ":") {
			// IPv6
			input += "/64"
		} else {
			// IPv4
			input += "/32"
		}
	}

	return net.ParseCIDR(input)
}

func CheckIpInRangeList(needle net.IP, haystack []string) bool {
	for _, r := range haystack {
		_, subnet, err := LenientParseCIDR(r)
		if err != nil {
			fmt.Print(err)
			return false
		}
		if subnet.Contains(needle) {
			return true
		}
	}
	return false
}
