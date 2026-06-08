//go:build linux

package core

import (
	"net"

	"golang.org/x/sys/unix"
)

func currentTCPRTTMilliseconds(conn *net.TCPConn) (int64, bool) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, false
	}

	var rttUs uint32
	var syscallErr error
	if err := raw.Control(func(fd uintptr) {
		info, err := unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		if err != nil {
			syscallErr = err
			return
		}
		rttUs = info.Rtt
	}); err != nil || syscallErr != nil || rttUs == 0 {
		return 0, false
	}

	return maxInt64(1, int64(rttUs+999)/1000), true
}
