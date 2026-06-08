//go:build windows

package core

import (
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

const sioTCPInfo = 0xd8000027

type tcpInfoV0 struct {
	State             uint32
	Mss               uint32
	ConnectionTimeMs  uint64
	TimestampsEnabled byte
	RttUs             uint32
	MinRttUs          uint32
	BytesInFlight     uint32
	Cwnd              uint32
	SndWnd            uint32
	RcvWnd            uint32
	RcvBuf            uint32
	BytesOut          uint64
	BytesIn           uint64
	BytesReordered    uint32
	BytesRetrans      uint32
	FastRetrans       uint32
	DupAcksIn         uint32
	TimeoutEpisodes   uint32
	SynRetrans        byte
}

func currentTCPRTTMilliseconds(conn *net.TCPConn) (int64, bool) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0, false
	}

	var info tcpInfoV0
	var syscallErr error
	if err := raw.Control(func(fd uintptr) {
		version := uint32(0)
		var returned uint32
		syscallErr = windows.WSAIoctl(
			windows.Handle(fd),
			sioTCPInfo,
			(*byte)(unsafe.Pointer(&version)),
			uint32(unsafe.Sizeof(version)),
			(*byte)(unsafe.Pointer(&info)),
			uint32(unsafe.Sizeof(info)),
			&returned,
			nil,
			0,
		)
	}); err != nil || syscallErr != nil || info.RttUs == 0 {
		return 0, false
	}

	return maxInt64(1, int64(info.RttUs+999)/1000), true
}
