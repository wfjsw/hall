// Copyright (c) 2012 The Grumble Authors
// The use of this source code is goverened by a BSD-style
// license that can be found in the LICENSE-file.

//go:build !windows
// +build !windows

package replacefile

import (
	"errors"
)

var (
	errOnlyWindows              = errors.New("replacefile: only implemented on Windows")
	ErrUnableToMoveReplacement  = errOnlyWindows
	ErrUnableToMoveReplacement2 = errOnlyWindows
	ErrUnableToRemoveReplaced   = errOnlyWindows
)

func ReplaceFile(replaced string, replacement string, backup string, flags Flag) error {
	return errOnlyWindows
}
