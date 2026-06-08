//go:build !windows

package core

import (
	"runtime"
	"syscall"
)

func socketControl(iface string, mark uint32) func(string, string, syscall.RawConn) error {
	return func(_, _ string, c syscall.RawConn) error {
		var err error
		controlErr := c.Control(func(fd uintptr) {
			err = setReuse(int(fd))
			if err != nil {
				return
			}
			if iface != "" {
				if bindErr := bindToDevice(int(fd), iface); bindErr != nil {
					err = bindErr
					return
				}
			}
			if mark != 0 {
				if markErr := setFwmark(int(fd), mark); markErr != nil {
					err = markErr
					return
				}
			}
		})
		if controlErr != nil {
			return controlErr
		}
		return err
	}
}

func setReuse(fd int) error {
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		return err
	}
	if runtime.GOOS != "darwin" {
		const soReusePort = 0x0F
		_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, soReusePort, 1)
	}
	return nil
}

func bindToDevice(fd int, iface string) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	const soBindToDevice = 25
	return syscall.SetsockoptString(fd, syscall.SOL_SOCKET, soBindToDevice, iface)
}

func setFwmark(fd int, mark uint32) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	const soMark = 36
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, soMark, int(mark))
}
