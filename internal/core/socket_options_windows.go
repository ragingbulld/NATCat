//go:build windows

package core

import (
	"syscall"
)

func socketControl(_ string, _ uint32) func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var err error
		controlErr := c.Control(func(fd uintptr) {
			err = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		})
		if controlErr != nil {
			return controlErr
		}
		return err
	}
}
