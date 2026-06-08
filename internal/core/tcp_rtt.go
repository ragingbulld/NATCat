package core

import "net"

func tcpRTTMilliseconds(conn *net.TCPConn, fallbackMs int64) int64 {
	if rtt, ok := currentTCPRTTMilliseconds(conn); ok {
		return rtt
	}
	if fallbackMs > 0 {
		return fallbackMs
	}
	return 0
}
