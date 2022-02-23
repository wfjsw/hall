//go:build !linux && !windows && !darwin
// +build !linux,!windows,!darwin

package main

import (
	"syscall"
)

func reuseControl(network, address string, c syscall.RawConn) error {
	return nil
}
