//go:build !linux && !windows

package core

import "net"

func currentTCPRTTMilliseconds(_ *net.TCPConn) (int64, bool) {
	return 0, false
}
