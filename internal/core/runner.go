package core

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	quicInitialConnectTimeout   = 8 * time.Second
	quicKeepAliveRequestTimeout = 2 * time.Second
	tcpKeepAliveRequestTimeout  = 2 * time.Second
	tcpPublicProbeDialTimeout   = 5 * time.Second
	reconnectVisibleDuration    = 1500 * time.Millisecond
	udpSTUNResponseTimeout      = 1200 * time.Millisecond
	udpSTUNRetries              = 3
)

var publicProbeConfirmDelay = 500 * time.Millisecond

type Runner struct {
	cfg               InstanceConfig
	report            func(string, RuntimeStatus)
	done              chan struct{}
	cancelMu          sync.Mutex
	cancelRun         context.CancelFunc
	picker            *portPicker
	portMu            sync.Mutex
	currentPort       int
	failedPort        int
	hasPort           bool
	advancePort       bool
	activeMu          sync.Mutex
	active            map[io.Closer]struct{}
	mapMu             sync.Mutex
	lastMap           *mappingEvent
	mappingLogEmitted bool
	udpQueries        int
	publicStableSince time.Time
	publicUpdatedAt   time.Time
	serverMu          sync.Mutex
	serverCursor      map[string]int
}

type mappingEvent struct {
	PublicIP    net.IP
	PublicPort  int
	PrivateIP   net.IP
	PrivatePort int
	Protocol    string
}

func NewRunner(cfg InstanceConfig, report func(string, RuntimeStatus)) *Runner {
	picker, _ := newPortPicker(cfg.BindPort)
	return &Runner{
		cfg:          cfg,
		report:       report,
		done:         make(chan struct{}),
		picker:       picker,
		failedPort:   -1,
		active:       map[io.Closer]struct{}{},
		serverCursor: map[string]int{},
	}
}

func (r *Runner) seedRuntime(st RuntimeStatus) {
	if st.PublicAddress == "" || st.PublicPort == 0 {
		return
	}
	publicIP := net.ParseIP(st.PublicAddress)
	if publicIP == nil {
		return
	}

	r.mapMu.Lock()
	defer r.mapMu.Unlock()

	protocol := st.Protocol
	if protocol == "" {
		protocol = r.cfg.Protocol
	}
	privateIP := net.ParseIP(st.PrivateAddress)
	if privateIP == nil {
		privateIP = net.IP{}
	}
	r.lastMap = &mappingEvent{
		PublicIP:    append(net.IP(nil), publicIP...),
		PublicPort:  st.PublicPort,
		PrivateIP:   append(net.IP(nil), privateIP...),
		PrivatePort: st.PrivatePort,
		Protocol:    protocol,
	}
	r.publicStableSince = st.PublicStableSince
	r.publicUpdatedAt = st.PublicUpdatedAt
}

func (r *Runner) Run(parent context.Context) {
	defer close(r.done)

	ctx, cancel := context.WithCancel(parent)
	r.cancelMu.Lock()
	r.cancelRun = cancel
	r.cancelMu.Unlock()
	defer cancel()

	startedAt := time.Now()
	r.emit(RuntimeStatus{
		State:     StateStarting,
		StartedAt: &startedAt,
		Protocol:  r.cfg.Protocol,
		Logs:      []LogEntry{{At: time.Now(), Level: "info", Message: "instance starting"}},
	})

	for {
		if ctx.Err() != nil {
			r.emit(RuntimeStatus{State: StateStopped, Logs: []LogEntry{{At: time.Now(), Level: "info", Message: "instance stopped"}}})
			return
		}

		err := r.runOnce(ctx)
		if ctx.Err() != nil {
			r.emit(RuntimeStatus{State: StateStopped, Logs: []LogEntry{{At: time.Now(), Level: "info", Message: "instance stopped"}}})
			return
		}
		if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, errStopped) {
			r.emit(RuntimeStatus{State: StateStopped, Logs: []LogEntry{{At: time.Now(), Level: "info", Message: "instance stopped"}}})
			return
		}
		if errors.Is(err, errSessionClosed) {
			r.emit(RuntimeStatus{State: StateStarting, Logs: []LogEntry{{At: time.Now(), Level: "info", Message: "rebuilding session"}}})
			select {
			case <-ctx.Done():
				r.emit(RuntimeStatus{State: StateStopped})
				return
			case <-time.After(1 * time.Second):
			}
			continue
		}

		userMessage := r.describeRunError(err)
		r.emit(RuntimeStatus{
			State:     StateError,
			LastError: userMessage,
			Logs:      []LogEntry{{At: time.Now(), Level: "error", Message: userMessage}},
		})

		r.emit(RuntimeStatus{Logs: []LogEntry{{At: time.Now(), Level: "info", Message: "retrying in 5s"}}})
		select {
		case <-ctx.Done():
			r.emit(RuntimeStatus{State: StateStopped})
			return
		case <-time.After(5 * time.Second):
			r.emit(RuntimeStatus{State: StateStarting})
		}
	}
}

func (r *Runner) Stop() {
	r.cancelMu.Lock()
	cancel := r.cancelRun
	r.cancelMu.Unlock()

	if cancel != nil {
		cancel()
	}
	r.closeActive()
}

func (r *Runner) Done() <-chan struct{} {
	return r.done
}

func (r *Runner) runOnce(ctx context.Context) error {
	if r.cfg.Protocol == "udp" {
		return r.runUDP(ctx)
	}
	return r.runTCP(ctx)
}

func (r *Runner) runTCP(ctx context.Context) error {
	network := networkFor("tcp")

	bindIP := parseBindIP(r.cfg.BindAddress)
	bindPort := r.bindPort()
	mapping, actualLocal, err := r.confirmedInitialTCPPublicProbe(ctx, network, bindIP, bindPort, stunServers(r.cfg))
	if err != nil {
		if isLocalPortUnavailable(err) {
			r.advanceBindPort()
		}
		return err
	}
	r.keepBindPort(actualLocal.Port)

	privateIP := actualLocal.IP
	privatePort := actualLocal.Port
	if privateIP == nil || privateIP.IsUnspecified() {
		privateIP = bindIP
	}

	r.emit(RuntimeStatus{
		State:          StateStarting,
		PrivateAddress: privateIP.String(),
		PrivatePort:    privatePort,
		Logs:           []LogEntry{{At: time.Now(), Level: "info", Message: fmt.Sprintf("tcp bound on %s", actualLocal.String())}},
	})

	keepEndpoint, httpAddr, keepConn, actualKeepLocal, untrackKeep, connectLatency, err := r.openTCPKeepAliveFromServers(ctx, network, privateIP, privatePort, keepAliveServers(r.cfg))
	if err != nil {
		if isLocalPortUnavailable(err) {
			r.advanceBindPort()
		}
		localAddr := &net.TCPAddr{IP: privateIP, Port: privatePort}
		remote := "configured servers"
		if httpAddr != nil {
			remote = httpAddr.String()
		}
		return fmt.Errorf("tcp keep-alive connect from %s to %s: %w", localAddr.String(), remote, err)
	}
	if actualKeepLocal != nil {
		r.keepBindPort(actualKeepLocal.Port)
	}
	tcpLatency := connectLatency
	r.emitKeepAlive(KeepAliveConnected, "tcp", httpAddr, fmt.Sprintf("tcp rtt %dms", tcpLatency), tcpLatency)
	closeKeep := func(abort bool) {
		if keepConn == nil {
			return
		}
		untrackKeep()
		closeTCP(keepConn, abort)
		keepConn = nil
	}

	event := mappingEvent{
		PublicIP:    mapping.IP,
		PublicPort:  mapping.Port,
		PrivateIP:   privateIP,
		PrivatePort: privatePort,
		Protocol:    "tcp",
	}
	r.publishMapping(event)

	for {
		keepErr := r.tcpKeepAlive(ctx, keepConn, keepEndpoint, tcpLatency)
		closeKeep(true)
		if !errors.Is(keepErr, errSessionClosed) {
			r.emitKeepAlive(KeepAliveDisconnected, "tcp", httpAddr, keepErr.Error(), 0)
			return keepErr
		}
		reconnectingAt := time.Now()
		r.emitKeepAlive(KeepAliveReconnecting, "tcp", httpAddr, keepErr.Error(), 0)
		if ctx.Err() != nil {
			return errStopped
		}

		nextEndpoint, nextAddr, nextConn, nextUntrack, nextLatency, err := r.reconnectTCPKeepAliveBeforePublicCheck(ctx, network, privateIP, privatePort, keepEndpoint, keepAliveServers(r.cfg))
		if err != nil {
			return err
		}
		closeNextKeep := func() {
			if nextUntrack != nil {
				nextUntrack()
			}
			if nextConn != nil {
				closeTCP(nextConn, true)
			}
		}
		if err := waitMinimumReconnectVisible(ctx, reconnectingAt); err != nil {
			closeNextKeep()
			return err
		}
		r.emitKeepAlive(KeepAliveConnected, "tcp", nextAddr, fmt.Sprintf("tcp rtt %dms", nextLatency), nextLatency)

		check, reachable, err := r.checkCurrentTCPMapping(ctx, event)
		if check.State != "" {
			r.emit(RuntimeStatus{PortCheck: check})
		}
		if err != nil {
			closeNextKeep()
			return err
		}
		if !reachable {
			r.emitKeepAlive(KeepAliveConnected, "tcp", nextAddr, "current public tcp mapping is not reachable; querying public mapping", nextLatency)
			mapping, err := r.confirmedTCPPublicProbe(ctx, network, privateIP, privatePort, stunServers(r.cfg))
			if err != nil {
				closeNextKeep()
				r.emitKeepAlive(KeepAliveReconnecting, "tcp", nextAddr, "tcp public probe failed after keep-alive reconnect; rebuilding session", 0)
				r.emit(RuntimeStatus{
					State: StateStarting,
					Logs: []LogEntry{{
						At:      time.Now(),
						Level:   "info",
						Message: fmt.Sprintf("tcp public probe failed after keep-alive reconnect; rebuilding session and running a new public probe: %v", err),
					}},
				})
				return fmt.Errorf("%w: tcp public probe failed after keep-alive reconnect: %v", errSessionClosed, err)
			}
			event = mappingEvent{
				PublicIP:    mapping.IP,
				PublicPort:  mapping.Port,
				PrivateIP:   privateIP,
				PrivatePort: privatePort,
				Protocol:    "tcp",
			}
			r.publishMapping(event)
			r.emit(RuntimeStatus{
				Logs: []LogEntry{{At: time.Now(), Level: "info", Message: "tcp public mapping refreshed after keep-alive reconnect"}},
			})
		}

		keepEndpoint = nextEndpoint
		httpAddr = nextAddr
		keepConn = nextConn
		untrackKeep = nextUntrack
		tcpLatency = nextLatency
		r.emitKeepAlive(KeepAliveConnected, "tcp", httpAddr, fmt.Sprintf("tcp rtt %dms", tcpLatency), tcpLatency)
		logMessage := "keep-alive reconnected; current public mapping is reachable"
		if !reachable {
			logMessage = "keep-alive reconnected; public mapping refreshed"
		}
		r.emit(RuntimeStatus{
			State: StateRunning,
			Logs:  []LogEntry{{At: time.Now(), Level: "info", Message: logMessage}},
		})
	}
}

func (r *Runner) confirmedInitialTCPPublicProbe(ctx context.Context, network string, bindIP net.IP, bindPort int, endpoints []ServerEndpoint) (stunResult, *net.TCPAddr, error) {
	privateIP := bindIP
	privatePort := bindPort
	var actualLocal *net.TCPAddr

	mapping, err := r.confirmPublicProbe(ctx, len(endpoints), func() (stunResult, error) {
		result, local, err := r.tcpPublicProbe(ctx, network, privateIP, privatePort, endpoints)
		if err != nil {
			return stunResult{}, err
		}
		if local != nil {
			actualLocal = local
			if privateIP == nil || privateIP.IsUnspecified() {
				privateIP = local.IP
			}
			privatePort = local.Port
		}
		return result, nil
	})
	if err != nil {
		return stunResult{}, nil, err
	}
	if actualLocal == nil {
		actualLocal = &net.TCPAddr{IP: privateIP, Port: privatePort}
	}
	return mapping, actualLocal, nil
}

func (r *Runner) reconnectTCPKeepAliveBeforePublicCheck(ctx context.Context, network string, privateIP net.IP, privatePort int, current ServerEndpoint, endpoints []ServerEndpoint) (ServerEndpoint, *net.TCPAddr, *net.TCPConn, func(), int64, error) {
	attempt := 0
	for {
		if ctx.Err() != nil {
			return ServerEndpoint{}, nil, nil, nil, 0, errStopped
		}

		r.emit(RuntimeStatus{
			State: StateStarting,
			Logs:  []LogEntry{{At: time.Now(), Level: "info", Message: "reconnecting keep-alive before public mapping check"}},
		})

		var lastErr error
		for _, endpoint := range r.orderedServerEndpoints("http", endpoints, &current) {
			addr, err := net.ResolveTCPAddr(network, endpointHostPort(endpoint))
			if err != nil {
				lastErr = err
				continue
			}
			started := time.Now()
			nextConn, _, nextUntrack, err := r.openTCPKeepAlive(ctx, network, privateIP, privatePort, addr)
			if err == nil {
				connectMs := maxInt64(1, time.Since(started).Milliseconds())
				latency := tcpRTTMilliseconds(nextConn, connectMs)
				return endpoint, addr, nextConn, nextUntrack, latency, nil
			}
			if ctx.Err() != nil {
				return ServerEndpoint{}, nil, nil, nil, 0, errStopped
			}
			lastErr = err
			if isLocalPortUnavailable(err) {
				r.advanceBindPort()
				r.emit(RuntimeStatus{
					State: StateStarting,
					Logs:  []LogEntry{{At: time.Now(), Level: "info", Message: "local bind port is unavailable; rebuilding with a new bind port"}},
				})
				return ServerEndpoint{}, nil, nil, nil, 0, fmt.Errorf("%w: local bind port unavailable: %v", errSessionClosed, err)
			}
		}
		if lastErr == nil {
			lastErr = errors.New("no tcp keep-alive servers configured")
		}

		attempt++
		if attempt >= 3 && len(endpoints) > 1 {
			return ServerEndpoint{}, nil, nil, nil, 0, fmt.Errorf("%w: keep-alive server reconnect failed; rebuilding with another server: %v", errSessionClosed, lastErr)
		}
		r.emit(RuntimeStatus{
			State: StateStarting,
			Logs: []LogEntry{{
				At:      time.Now(),
				Level:   "error",
				Message: fmt.Sprintf("keep-alive reconnect before public mapping check failed (attempt %d): %s", attempt, lastErr.Error()),
			}},
		})

		select {
		case <-ctx.Done():
			return ServerEndpoint{}, nil, nil, nil, 0, errStopped
		case <-time.After(1 * time.Second):
		}
	}
}

func waitMinimumReconnectVisible(ctx context.Context, since time.Time) error {
	remaining := reconnectVisibleDuration - time.Since(since)
	if remaining <= 0 {
		return nil
	}
	timer := time.NewTimer(remaining)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return errStopped
	case <-timer.C:
		return nil
	}
}

func (r *Runner) checkCurrentTCPMapping(ctx context.Context, event mappingEvent) (PortCheck, bool, error) {
	check := PortCheck{
		Protocol:  "tcp",
		CheckedAt: time.Now(),
	}
	if event.PublicIP == nil || event.PublicPort <= 0 {
		check.State = "unknown"
		check.Message = "tcp public mapping is not ready"
		return check, false, nil
	}

	target := net.JoinHostPort(event.PublicIP.String(), strconv.Itoa(event.PublicPort))
	checkCtx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	started := time.Now()
	dialer := net.Dialer{
		Timeout: 2500 * time.Millisecond,
		Control: socketControl(r.cfg.Interface, r.cfg.FWMark),
	}
	conn, err := dialer.DialContext(checkCtx, "tcp4", target)
	check.CheckedAt = time.Now()
	if err != nil {
		if ctx.Err() != nil {
			return check, false, errStopped
		}
		check.State = classifyTCPCheckError(err)
		check.Message = err.Error()
		return check, false, nil
	}
	_ = conn.Close()
	check.State = "open"
	check.LatencyMs = maxInt64(1, time.Since(started).Milliseconds())
	check.Message = "tcp connect succeeded after keep-alive reconnect"
	return check, true, nil
}

func (r *Runner) openTCPKeepAliveFromServers(ctx context.Context, network string, bindIP net.IP, bindPort int, endpoints []ServerEndpoint) (ServerEndpoint, *net.TCPAddr, *net.TCPConn, *net.TCPAddr, func(), int64, error) {
	if len(endpoints) == 0 {
		return ServerEndpoint{}, nil, nil, nil, nil, 0, errors.New("no tcp keep-alive servers configured")
	}

	var lastErr error
	for _, endpoint := range r.orderedServerEndpoints("http", endpoints, nil) {
		addr, err := net.ResolveTCPAddr(network, endpointHostPort(endpoint))
		if err != nil {
			lastErr = err
			continue
		}
		started := time.Now()
		keepConn, actualLocal, untrackKeep, err := r.openTCPKeepAlive(ctx, network, bindIP, bindPort, addr)
		if err == nil {
			connectMs := maxInt64(1, time.Since(started).Milliseconds())
			return endpoint, addr, keepConn, actualLocal, untrackKeep, tcpRTTMilliseconds(keepConn, connectMs), nil
		}
		lastErr = err
		if isLocalPortUnavailable(err) || ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no tcp keep-alive servers configured")
	}
	return ServerEndpoint{}, nil, nil, nil, nil, 0, fmt.Errorf("tcp keep-alive server selection failed: %w", lastErr)
}

func (r *Runner) tcpPublicProbe(ctx context.Context, network string, privateIP net.IP, privatePort int, endpoints []ServerEndpoint) (stunResult, *net.TCPAddr, error) {
	if len(endpoints) == 0 {
		return stunResult{}, nil, errors.New("no tcp public probe servers configured")
	}

	stunDialer := &net.Dialer{
		Timeout:   tcpPublicProbeDialTimeout,
		LocalAddr: &net.TCPAddr{IP: privateIP, Port: privatePort},
		Control:   socketControl(r.cfg.Interface, r.cfg.FWMark),
	}

	var lastErr error
	for _, endpoint := range r.orderedServerEndpoints("stun", endpoints, nil) {
		stunAddr, err := net.ResolveTCPAddr(network, endpointHostPort(endpoint))
		if err != nil {
			lastErr = err
			continue
		}
		stunConn, err := r.dialTCP(ctx, stunDialer, network, stunAddr.String())
		if err != nil {
			lastErr = fmt.Errorf("tcp public probe connect from %s to %s: %w", stunDialer.LocalAddr.String(), stunAddr.String(), err)
			if isLocalPortUnavailable(err) || ctx.Err() != nil {
				break
			}
			continue
		}
		actualLocal, _ := stunConn.LocalAddr().(*net.TCPAddr)
		untrackStun := r.track(stunConn)
		mapping, err := stunTCP(stunConn)
		untrackStun()
		closeTCP(stunConn, true)
		if err == nil {
			return mapping, actualLocal, nil
		}
		lastErr = fmt.Errorf("tcp public probe query %s: %w", stunAddr.String(), err)
	}
	if lastErr == nil {
		lastErr = errors.New("no tcp public probe servers configured")
	}
	return stunResult{}, nil, lastErr
}

func (r *Runner) confirmedTCPPublicProbe(ctx context.Context, network string, privateIP net.IP, privatePort int, endpoints []ServerEndpoint) (stunResult, error) {
	return r.confirmPublicProbe(ctx, len(endpoints), func() (stunResult, error) {
		result, _, err := r.tcpPublicProbe(ctx, network, privateIP, privatePort, endpoints)
		return result, err
	})
}

func (r *Runner) openTCPKeepAlive(ctx context.Context, network string, bindIP net.IP, bindPort int, httpAddr *net.TCPAddr) (*net.TCPConn, *net.TCPAddr, func(), error) {
	localAddr := &net.TCPAddr{IP: bindIP, Port: bindPort}
	keepDialer := &net.Dialer{
		Timeout:   30 * time.Second,
		LocalAddr: localAddr,
		Control:   socketControl(r.cfg.Interface, r.cfg.FWMark),
	}
	keepConn, err := r.dialTCP(ctx, keepDialer, network, httpAddr.String())
	if err != nil {
		return nil, nil, nil, err
	}
	untrackKeep := r.track(keepConn)
	return keepConn, keepConn.LocalAddr().(*net.TCPAddr), untrackKeep, nil
}

func (r *Runner) dialTCP(ctx context.Context, dialer *net.Dialer, network, address string) (*net.TCPConn, error) {
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error

	for {
		raw, err := dialer.DialContext(ctx, network, address)
		if err == nil {
			return raw.(*net.TCPConn), nil
		}
		lastErr = err

		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if !isLocalAddressBusy(err) || time.Now().After(deadline) {
			return nil, lastErr
		}

		timer := time.NewTimer(300 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func isLocalAddressBusy(err error) bool {
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "cannot assign requested address") ||
		strings.Contains(text, "address already in use") ||
		strings.Contains(text, "only one usage of each socket address") ||
		strings.Contains(text, "forbidden by its access permissions") ||
		strings.Contains(text, "eaddrnotavail") ||
		strings.Contains(text, "eaddrinuse")
}

func isLocalPortUnavailable(err error) bool {
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "address already in use") ||
		strings.Contains(text, "only one usage of each socket address") ||
		strings.Contains(text, "forbidden by its access permissions") ||
		strings.Contains(text, "eaddrinuse") ||
		strings.Contains(text, "wsaeaddrinuse")
}

func closeTCP(conn *net.TCPConn, abort bool) {
	if abort {
		_ = conn.SetLinger(0)
	}
	_ = conn.Close()
}

func (r *Runner) tcpKeepAlive(ctx context.Context, conn *net.TCPConn, endpoint ServerEndpoint, lastLatency int64) error {
	host := endpoint.Host
	if endpoint.Port != 80 {
		host = net.JoinHostPort(endpoint.Host, strconv.Itoa(endpoint.Port))
	}
	request := "HEAD / HTTP/1.1\r\nHost: " + host + "\r\nConnection: keep-alive\r\n\r\n"
	keep := time.Duration(r.cfg.KeepAliveSeconds) * time.Second
	interval := time.Duration(0)
	reader := bufio.NewReader(conn)

	for {
		if interval > 0 {
			if err := r.waitTCPKeepAliveInterval(ctx, conn, reader, interval); err != nil {
				return err
			}
		} else if ctx.Err() != nil {
			return errStopped
		}
		if err := conn.SetWriteDeadline(time.Now().Add(30 * time.Second)); err != nil {
			return fmt.Errorf("%w: tcp keep-alive write deadline: %v", errSessionClosed, err)
		}
		if _, err := io.WriteString(conn, request); err != nil {
			if ctx.Err() != nil {
				return errStopped
			}
			return fmt.Errorf("%w: tcp keep-alive write: %v", errSessionClosed, err)
		}

		if err := conn.SetReadDeadline(time.Now().Add(tcpKeepAliveRequestTimeout)); err != nil {
			return fmt.Errorf("%w: tcp keep-alive read deadline: %v", errSessionClosed, err)
		}
		resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodHead})
		if err != nil {
			if ctx.Err() != nil {
				return errStopped
			}
			if errors.Is(err, io.EOF) {
				return fmt.Errorf("%w: tcp keep-alive closed by peer", errSessionClosed)
			}
			return fmt.Errorf("%w: tcp keep-alive read response: %v", errSessionClosed, err)
		}
		if resp.Body != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
		interval = keep

		if resp.Close {
			return fmt.Errorf("%w: tcp keep-alive response requested close", errSessionClosed)
		}
		latency := tcpRTTMilliseconds(conn, lastLatency)
		lastLatency = latency
		r.emitKeepAlive(KeepAliveConnected, "tcp", conn.RemoteAddr(), fmt.Sprintf("tcp rtt %dms", latency), latency)
	}
}

func (r *Runner) waitTCPKeepAliveInterval(ctx context.Context, conn *net.TCPConn, reader *bufio.Reader, interval time.Duration) error {
	deadline := time.Now().Add(interval)
	for {
		if ctx.Err() != nil {
			return errStopped
		}
		now := time.Now()
		if !now.Before(deadline) {
			return nil
		}
		readDeadline := deadline
		if deadline.Sub(now) > time.Second {
			readDeadline = now.Add(time.Second)
		}
		if err := conn.SetReadDeadline(readDeadline); err != nil {
			return fmt.Errorf("%w: tcp keep-alive read deadline: %v", errSessionClosed, err)
		}

		if _, err := reader.Peek(1); err != nil {
			if ctx.Err() != nil {
				return errStopped
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			if errors.Is(err, io.EOF) {
				return fmt.Errorf("%w: tcp keep-alive closed by peer", errSessionClosed)
			}
			return fmt.Errorf("%w: tcp keep-alive read: %v", errSessionClosed, err)
		}
		buffered := reader.Buffered()
		if buffered <= 0 {
			_, _ = reader.ReadByte()
			continue
		}
		_, _ = reader.Discard(buffered)
	}
}

func (r *Runner) runUDP(ctx context.Context) error {
	network := networkFor("udp")

	bindIP := parseBindIP(r.cfg.BindAddress)
	bindPort := r.bindPort()
	conn, err := r.listenUDP(network, &net.UDPAddr{IP: bindIP, Port: bindPort})
	if err != nil {
		if isLocalPortUnavailable(err) {
			r.advanceBindPort()
		}
		return fmt.Errorf("udp bind on %s:%d: %w", bindIP.String(), bindPort, err)
	}
	untrackUDP := r.track(conn)
	actualLocal := conn.LocalAddr().(*net.UDPAddr)
	r.keepBindPort(actualLocal.Port)
	closeConn := func() {
		if conn == nil {
			return
		}
		if untrackUDP != nil {
			untrackUDP()
			untrackUDP = nil
		}
		_ = conn.Close()
		conn = nil
	}
	defer closeConn()

	privateIP := actualLocal.IP
	if privateIP == nil || privateIP.IsUnspecified() {
		privateIP = bindIP
	}
	privatePort := actualLocal.Port

	sharedConn := newSharedUDPConn(conn)
	defer sharedConn.Close()

	if ctx.Err() != nil {
		return errStopped
	}

	r.emit(RuntimeStatus{
		State:          StateStarting,
		PrivateAddress: privateIP.String(),
		PrivatePort:    privatePort,
		Logs:           []LogEntry{{At: time.Now(), Level: "info", Message: fmt.Sprintf("udp bound on %s", actualLocal.String())}},
	})

	result, err := r.confirmedInitialUDPPublicProbe(ctx, network, conn, stunServers(r.cfg))
	if err != nil {
		return fmt.Errorf("udp public probe query: %w", err)
	}

	keepEndpoint, quicAddr, quicTransport, connectLatency, err := r.openQUICKeepAliveFromServers(ctx, sharedConn, network, keepAliveServers(r.cfg), quicInitialConnectTimeout)
	if err != nil {
		if isLocalPortUnavailable(err) {
			r.advanceBindPort()
		}
		remote := "configured servers"
		if quicAddr != nil {
			remote = quicAddr.String()
		}
		return fmt.Errorf("udp quic keep-alive connect from %s to %s: %w", actualLocal.String(), remote, err)
	}
	defer func() {
		if quicTransport != nil {
			_ = quicTransport.Close()
		}
	}()
	r.emitKeepAlive(KeepAliveConnected, "udp", quicAddr, fmt.Sprintf("quic rtt %dms", connectLatency), connectLatency)

	event := mappingEvent{
		PublicIP:    result.IP,
		PublicPort:  result.Port,
		PrivateIP:   privateIP,
		PrivatePort: privatePort,
		Protocol:    "udp",
	}
	r.publishMapping(event)

	for {
		latency, keepErr := r.quicKeepAliveOnce(ctx, quicTransport, keepEndpoint, quicAddr)
		if !errors.Is(keepErr, errSessionClosed) {
			if keepErr == nil {
				_ = latency
				continue
			}
			r.emitKeepAlive(KeepAliveDisconnected, "udp", quicAddr, keepErr.Error(), 0)
			return keepErr
		}
		_ = quicTransport.Close()
		reconnectingAt := time.Now()
		r.emitKeepAlive(KeepAliveReconnecting, "udp", quicAddr, keepErr.Error(), 0)
		if ctx.Err() != nil {
			return errStopped
		}

		nextEndpoint, nextAddr, nextTransport, nextLatency, err := r.reconnectQUICKeepAliveBeforePublicProbe(ctx, sharedConn, network, keepEndpoint, keepAliveServers(r.cfg))
		if err != nil {
			return err
		}
		closeNextKeep := func() {
			if nextTransport != nil {
				_ = nextTransport.Close()
			}
		}
		if err := waitMinimumReconnectVisible(ctx, reconnectingAt); err != nil {
			closeNextKeep()
			return err
		}
		r.emitKeepAlive(KeepAliveConnected, "udp", nextAddr, fmt.Sprintf("quic rtt %dms", nextLatency), nextLatency)

		result, err := r.confirmedUDPPublicProbe(ctx, network, conn, sharedConn.stunResponses, stunServers(r.cfg))
		if err != nil {
			closeNextKeep()
			r.emitKeepAlive(KeepAliveReconnecting, "udp", nextAddr, "udp public probe failed after quic keep-alive reconnect; rebuilding session", 0)
			r.emit(RuntimeStatus{
				State: StateStarting,
				Logs: []LogEntry{{
					At:      time.Now(),
					Level:   "info",
					Message: fmt.Sprintf("udp public probe failed after quic keep-alive reconnect; rebuilding session and running a new public probe: %v", err),
				}},
			})
			return fmt.Errorf("%w: udp public probe failed after quic keep-alive reconnect: %v", errSessionClosed, err)
		}

		keepEndpoint = nextEndpoint
		quicAddr = nextAddr
		quicTransport = nextTransport
		r.emitKeepAlive(KeepAliveConnected, "udp", quicAddr, fmt.Sprintf("quic rtt %dms", nextLatency), nextLatency)
		event = mappingEvent{
			PublicIP:    result.IP,
			PublicPort:  result.Port,
			PrivateIP:   privateIP,
			PrivatePort: privatePort,
			Protocol:    "udp",
		}
		r.publishMapping(event)
		r.emit(RuntimeStatus{
			State: StateRunning,
			Logs:  []LogEntry{{At: time.Now(), Level: "info", Message: "quic keep-alive reconnected; public mapping confirmed"}},
		})
	}
}

type sharedUDPConn struct {
	conn          *net.UDPConn
	stunResponses chan stunResult
	closed        chan struct{}
}

func newSharedUDPConn(conn *net.UDPConn) *sharedUDPConn {
	return &sharedUDPConn{
		conn:          conn,
		stunResponses: make(chan stunResult, 8),
		closed:        make(chan struct{}),
	}
}

func (r *Runner) listenUDP(network string, localAddr *net.UDPAddr) (*net.UDPConn, error) {
	listener := net.ListenConfig{
		Control: socketControl(r.cfg.Interface, r.cfg.FWMark),
	}
	raw, err := listener.ListenPacket(context.Background(), network, localAddr.String())
	if err != nil {
		return nil, err
	}
	conn, ok := raw.(*net.UDPConn)
	if !ok {
		_ = raw.Close()
		return nil, fmt.Errorf("unexpected udp listener %T", raw)
	}
	return conn, nil
}

func (c *sharedUDPConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *sharedUDPConn) ReadFrom(b []byte) (int, net.Addr, error) {
	buf := make([]byte, 2048)
	for {
		n, addr, err := c.conn.ReadFrom(buf)
		if err != nil {
			return 0, nil, err
		}
		packet := buf[:n]
		if result, err := parseSTUN(packet); err == nil {
			if addr != nil {
				result.Source = addr.String()
			}
			select {
			case c.stunResponses <- result:
			default:
			}
			continue
		}
		if n > len(b) {
			n = len(b)
		}
		copy(b[:n], packet[:n])
		return n, addr, nil
	}
}

func (c *sharedUDPConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	return c.conn.WriteTo(b, addr)
}

func (c *sharedUDPConn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *sharedUDPConn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *sharedUDPConn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *sharedUDPConn) Close() error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}

type quicKeepAliveTransport struct {
	transport *http3.Transport
	connMu    sync.RWMutex
	conn      *quic.Conn
}

func (t *quicKeepAliveTransport) setConn(conn *quic.Conn) {
	t.connMu.Lock()
	t.conn = conn
	t.connMu.Unlock()
}

func (t *quicKeepAliveTransport) Close() error {
	if t == nil || t.transport == nil {
		return nil
	}
	return t.transport.Close()
}

func (t *quicKeepAliveTransport) done() <-chan struct{} {
	t.connMu.RLock()
	conn := t.conn
	t.connMu.RUnlock()
	if conn == nil {
		return nil
	}
	return conn.Context().Done()
}

func (t *quicKeepAliveTransport) closeCause() error {
	t.connMu.RLock()
	conn := t.conn
	t.connMu.RUnlock()
	if conn == nil {
		return nil
	}
	return context.Cause(conn.Context())
}

func (t *quicKeepAliveTransport) rttMilliseconds(fallback time.Duration) int64 {
	t.connMu.RLock()
	conn := t.conn
	t.connMu.RUnlock()
	if conn != nil {
		stats := conn.ConnectionStats()
		switch {
		case stats.LatestRTT > 0:
			return maxInt64(1, stats.LatestRTT.Milliseconds())
		case stats.SmoothedRTT > 0:
			return maxInt64(1, stats.SmoothedRTT.Milliseconds())
		case stats.MinRTT > 0:
			return maxInt64(1, stats.MinRTT.Milliseconds())
		}
	}
	if fallback > 0 {
		return maxInt64(1, fallback.Milliseconds())
	}
	return 0
}

func (r *Runner) openQUICKeepAliveFromServers(ctx context.Context, conn net.PacketConn, network string, endpoints []ServerEndpoint, timeout time.Duration) (ServerEndpoint, *net.UDPAddr, *quicKeepAliveTransport, int64, error) {
	if len(endpoints) == 0 {
		return ServerEndpoint{}, nil, nil, 0, errors.New("no udp quic keep-alive servers configured")
	}

	var lastErr error
	for _, endpoint := range r.orderedServerEndpoints("quic", endpoints, nil) {
		addr, err := net.ResolveUDPAddr(network, endpointHostPort(endpoint))
		if err != nil {
			lastErr = err
			continue
		}
		transport, latency, err := r.openQUICKeepAlive(ctx, conn, endpoint, addr, timeout)
		if err == nil {
			return endpoint, addr, transport, latency, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no udp quic keep-alive servers configured")
	}
	return ServerEndpoint{}, nil, nil, 0, fmt.Errorf("udp quic keep-alive server selection failed: %w", lastErr)
}

func (r *Runner) openQUICKeepAlive(ctx context.Context, conn net.PacketConn, endpoint ServerEndpoint, addr *net.UDPAddr, timeout time.Duration) (*quicKeepAliveTransport, int64, error) {
	host := endpoint.Host
	if timeout <= 0 {
		timeout = quicInitialConnectTimeout
	}
	keepTransport := &quicKeepAliveTransport{}
	transport := &http3.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: host,
		},
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: timeout,
			MaxIdleTimeout:       maxDuration(30*time.Second, 3*time.Duration(r.cfg.KeepAliveSeconds)*time.Second),
			KeepAlivePeriod:      time.Duration(r.cfg.KeepAliveSeconds) * time.Second,
		},
		Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
			qconn, err := quic.Dial(ctx, conn, addr, tlsCfg, cfg)
			if err == nil {
				keepTransport.setConn(qconn)
			}
			return qconn, err
		},
	}
	keepTransport.transport = transport
	started := time.Now()
	if err := r.http3KeepAliveRequest(ctx, keepTransport, endpoint, timeout); err != nil {
		_ = keepTransport.Close()
		return nil, 0, err
	}
	latency := keepTransport.rttMilliseconds(time.Since(started))
	return keepTransport, latency, nil
}

func (r *Runner) http3KeepAliveRequest(ctx context.Context, transport *quicKeepAliveTransport, endpoint ServerEndpoint, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = quicKeepAliveRequestTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	url := "https://" + endpointHostPort(endpoint) + "/"
	req, err := http.NewRequestWithContext(reqCtx, http.MethodHead, url, nil)
	if err != nil {
		return err
	}
	resp, err := transport.transport.RoundTrip(req)
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

func (r *Runner) quicKeepAliveOnce(ctx context.Context, transport *quicKeepAliveTransport, endpoint ServerEndpoint, remote net.Addr) (int64, error) {
	keep := time.Duration(r.cfg.KeepAliveSeconds) * time.Second
	timer := time.NewTimer(keep)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return 0, errStopped
	case <-transport.done():
		if ctx.Err() != nil {
			return 0, errStopped
		}
		cause := transport.closeCause()
		if cause == nil {
			cause = errors.New("connection closed")
		}
		return 0, fmt.Errorf("%w: udp quic keep-alive closed: %v", errSessionClosed, cause)
	case <-timer.C:
	}
	started := time.Now()
	if err := r.http3KeepAliveRequest(ctx, transport, endpoint, quicKeepAliveRequestTimeout); err != nil {
		if ctx.Err() != nil {
			return 0, errStopped
		}
		return 0, fmt.Errorf("%w: udp quic keep-alive request: %v", errSessionClosed, err)
	}
	latency := transport.rttMilliseconds(time.Since(started))
	r.emitKeepAlive(KeepAliveConnected, "udp", remote, fmt.Sprintf("quic rtt %dms", latency), latency)
	return latency, nil
}

func (r *Runner) reconnectQUICKeepAliveBeforePublicProbe(ctx context.Context, conn net.PacketConn, network string, current ServerEndpoint, endpoints []ServerEndpoint) (ServerEndpoint, *net.UDPAddr, *quicKeepAliveTransport, int64, error) {
	attempt := 0
	for {
		if ctx.Err() != nil {
			return ServerEndpoint{}, nil, nil, 0, errStopped
		}

		r.emit(RuntimeStatus{
			State: StateStarting,
			Logs:  []LogEntry{{At: time.Now(), Level: "info", Message: "reconnecting quic keep-alive before public probe"}},
		})

		var lastErr error
		for _, endpoint := range r.orderedServerEndpoints("quic", endpoints, &current) {
			addr, err := net.ResolveUDPAddr(network, endpointHostPort(endpoint))
			if err != nil {
				lastErr = err
				continue
			}
			nextTransport, latency, err := r.openQUICKeepAlive(ctx, conn, endpoint, addr, quicKeepAliveRequestTimeout)
			if err == nil {
				return endpoint, addr, nextTransport, latency, nil
			}
			if ctx.Err() != nil {
				return ServerEndpoint{}, nil, nil, 0, errStopped
			}
			lastErr = err
		}
		if lastErr == nil {
			lastErr = errors.New("no udp quic keep-alive servers configured")
		}

		attempt++
		if attempt >= 3 && len(endpoints) > 1 {
			return ServerEndpoint{}, nil, nil, 0, fmt.Errorf("%w: quic keep-alive reconnect failed; rebuilding with another server: %v", errSessionClosed, lastErr)
		}
		r.emit(RuntimeStatus{
			State: StateStarting,
			Logs: []LogEntry{{
				At:      time.Now(),
				Level:   "error",
				Message: fmt.Sprintf("quic keep-alive reconnect before public probe failed (attempt %d): %s", attempt, lastErr.Error()),
			}},
		})

		select {
		case <-ctx.Done():
			return ServerEndpoint{}, nil, nil, 0, errStopped
		case <-time.After(1 * time.Second):
		}
	}
}

func (r *Runner) orderedServerEndpoints(kind string, endpoints []ServerEndpoint, after *ServerEndpoint) []ServerEndpoint {
	if len(endpoints) <= 1 {
		return endpoints
	}

	start := -1
	if after != nil {
		if idx := indexOfServerEndpoint(endpoints, *after); idx >= 0 {
			start = (idx + 1) % len(endpoints)
		}
	}
	if start < 0 {
		start = r.nextServerCursor(kind, len(endpoints))
	} else {
		r.setServerCursor(kind, start+1)
	}
	return rotateServerEndpoints(endpoints, start)
}

func (r *Runner) nextServerCursor(kind string, length int) int {
	if length <= 0 {
		return 0
	}
	r.serverMu.Lock()
	defer r.serverMu.Unlock()
	start := r.serverCursor[kind] % length
	r.serverCursor[kind] = start + 1
	return start
}

func (r *Runner) setServerCursor(kind string, next int) {
	r.serverMu.Lock()
	r.serverCursor[kind] = next
	r.serverMu.Unlock()
}

func rotateServerEndpoints(endpoints []ServerEndpoint, start int) []ServerEndpoint {
	if len(endpoints) == 0 {
		return nil
	}
	start = start % len(endpoints)
	out := make([]ServerEndpoint, 0, len(endpoints))
	out = append(out, endpoints[start:]...)
	out = append(out, endpoints[:start]...)
	return out
}

func indexOfServerEndpoint(endpoints []ServerEndpoint, target ServerEndpoint) int {
	for i, endpoint := range endpoints {
		if sameServerEndpoint(endpoint, target) {
			return i
		}
	}
	return -1
}

func sameServerEndpoint(a, b ServerEndpoint) bool {
	return strings.EqualFold(a.Host, b.Host) && a.Port == b.Port
}

func (r *Runner) udpPublicProbe(ctx context.Context, network string, conn *net.UDPConn, responses <-chan stunResult, endpoints []ServerEndpoint) (stunResult, error) {
	if len(endpoints) == 0 {
		return stunResult{}, errors.New("no udp public probe servers configured")
	}

	var lastErr error
	for _, endpoint := range r.orderedServerEndpoints("stun", endpoints, nil) {
		addr, err := net.ResolveUDPAddr(network, endpointHostPort(endpoint))
		if err != nil {
			lastErr = err
			continue
		}
		var result stunResult
		if responses == nil {
			result, err = r.stunUDPDirect(ctx, conn, addr)
		} else {
			result, err = r.stunUDPShared(ctx, conn, addr, responses)
		}
		if err == nil {
			return result, nil
		}
		lastErr = fmt.Errorf("%s: %w", addr.String(), err)
		if ctx.Err() != nil {
			break
		}
	}
	if lastErr == nil {
		lastErr = errors.New("no udp public probe servers configured")
	}
	return stunResult{}, lastErr
}

func (r *Runner) confirmedInitialUDPPublicProbe(ctx context.Context, network string, conn *net.UDPConn, endpoints []ServerEndpoint) (stunResult, error) {
	return r.confirmPublicProbe(ctx, len(endpoints), func() (stunResult, error) {
		return r.udpPublicProbe(ctx, network, conn, nil, endpoints)
	})
}

func (r *Runner) confirmedUDPPublicProbe(ctx context.Context, network string, conn *net.UDPConn, responses <-chan stunResult, endpoints []ServerEndpoint) (stunResult, error) {
	return r.confirmPublicProbe(ctx, len(endpoints), func() (stunResult, error) {
		return r.udpPublicProbe(ctx, network, conn, responses, endpoints)
	})
}

func (r *Runner) confirmPublicProbe(ctx context.Context, endpointCount int, probe func() (stunResult, error)) (stunResult, error) {
	confirmations := r.cfg.MappingConfirmations
	if confirmations <= 1 {
		return probe()
	}

	maxAttempts := publicProbeMaxAttempts(confirmations, endpointCount)
	var candidate stunResult
	candidateCount := 0
	var lastErr error

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		result, err := probe()
		if err != nil {
			lastErr = err
			candidate = stunResult{}
			candidateCount = 0
		} else {
			lastErr = nil
			if candidateCount == 0 || !samePublicProbeResult(candidate, result) {
				candidate = result
				candidateCount = 1
			} else {
				candidateCount++
			}
			if candidateCount >= confirmations {
				return result, nil
			}
		}

		if ctx.Err() != nil {
			return stunResult{}, ctx.Err()
		}
		if attempt < maxAttempts {
			timer := time.NewTimer(publicProbeConfirmDelay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return stunResult{}, ctx.Err()
			case <-timer.C:
			}
		}
	}

	if candidateCount > 0 {
		return stunResult{}, fmt.Errorf("public probe confirmation failed: %s confirmed %d/%d times", formatPublicProbeResult(candidate), candidateCount, confirmations)
	}
	if lastErr != nil {
		return stunResult{}, fmt.Errorf("public probe confirmation failed after %d attempts: %w", maxAttempts, lastErr)
	}
	return stunResult{}, fmt.Errorf("public probe confirmation failed after %d attempts", maxAttempts)
}

func publicProbeMaxAttempts(confirmations, endpointCount int) int {
	if confirmations <= 1 {
		return 1
	}
	if endpointCount < 1 {
		endpointCount = 1
	}
	attempts := confirmations * endpointCount * 2
	minAttempts := confirmations + 2
	if attempts < minAttempts {
		return minAttempts
	}
	return attempts
}

func samePublicProbeResult(a, b stunResult) bool {
	return a.Port == b.Port && a.IP.Equal(b.IP)
}

func formatPublicProbeResult(result stunResult) string {
	if result.IP == nil || result.Port <= 0 {
		return "-"
	}
	return net.JoinHostPort(result.IP.String(), strconv.Itoa(result.Port))
}

func (r *Runner) udpSTUNProbeTiming() (time.Duration, int) {
	timeout := udpSTUNResponseTimeout
	retries := udpSTUNRetries
	if runtime.GOOS == "windows" {
		timeout = 100 * time.Millisecond
		retries = udpSTUNRetries
		if r.udpQueries == 0 {
			retries = 30
		}
	}
	r.udpQueries++
	return timeout, retries
}

func (r *Runner) stunUDPDirect(ctx context.Context, conn *net.UDPConn, addr *net.UDPAddr) (stunResult, error) {
	request, tid, err := stunRequest()
	if err != nil {
		return stunResult{}, err
	}

	timeout, retries := r.udpSTUNProbeTiming()
	buf := make([]byte, 2048)
	defer conn.SetReadDeadline(time.Time{})

	for attempt := 0; attempt < retries; attempt++ {
		if ctx.Err() != nil {
			return stunResult{}, ctx.Err()
		}
		if _, err := conn.WriteToUDP(request, addr); err != nil {
			if ctx.Err() != nil {
				return stunResult{}, ctx.Err()
			}
			return stunResult{}, err
		}

		deadline := time.Now().Add(timeout)
		for {
			if ctx.Err() != nil {
				return stunResult{}, ctx.Err()
			}
			if err := conn.SetReadDeadline(deadline); err != nil {
				return stunResult{}, err
			}
			n, source, err := conn.ReadFromUDP(buf)
			if err != nil {
				if ctx.Err() != nil {
					return stunResult{}, ctx.Err()
				}
				if ne, ok := err.(net.Error); ok && ne.Timeout() {
					break
				}
				return stunResult{}, err
			}
			result, err := parseSTUN(buf[:n])
			if err != nil {
				continue
			}
			if source != nil {
				result.Source = source.String()
			}
			if result.TID == tid && stunSourceMatches(result.Source, addr) {
				return result, nil
			}
		}
	}

	return stunResult{}, errors.New("stun response timeout")
}

func (r *Runner) stunUDPShared(ctx context.Context, conn *net.UDPConn, addr *net.UDPAddr, responses <-chan stunResult) (stunResult, error) {
	request, tid, err := stunRequest()
	if err != nil {
		return stunResult{}, err
	}

	timeout, retries := r.udpSTUNProbeTiming()

	for attempt := 0; attempt < retries; attempt++ {
		if ctx.Err() != nil {
			return stunResult{}, ctx.Err()
		}
		if _, err := conn.WriteToUDP(request, addr); err != nil {
			if ctx.Err() != nil {
				return stunResult{}, ctx.Err()
			}
			return stunResult{}, err
		}

		timer := time.NewTimer(timeout)
		for {
			select {
			case <-ctx.Done():
				timer.Stop()
				return stunResult{}, ctx.Err()
			case result := <-responses:
				if result.TID == tid && stunSourceMatches(result.Source, addr) {
					timer.Stop()
					return result, nil
				}
			case <-timer.C:
				goto retry
			}
		}
	retry:
	}

	return stunResult{}, errors.New("stun response timeout")
}

func stunSourceMatches(source string, expected *net.UDPAddr) bool {
	if source == "" || expected == nil {
		return true
	}
	actual, err := net.ResolveUDPAddr("udp", source)
	if err != nil {
		return false
	}
	return actual.Port == expected.Port && actual.IP.Equal(expected.IP)
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func (r *Runner) publishMapping(event mappingEvent) {
	changed, stableSince, updatedAt := r.updateMapping(event)
	logs := []LogEntry{}
	if changed || !r.mappingLogEmitted {
		logs = append(logs, LogEntry{
			At:      time.Now(),
			Level:   "info",
			Message: fmt.Sprintf("mapped %s:%d -> %s:%d", event.PublicIP.String(), event.PublicPort, event.PrivateIP.String(), event.PrivatePort),
		})
		r.mappingLogEmitted = true
	}

	r.emit(RuntimeStatus{
		State:             StateRunning,
		PublicAddress:     event.PublicIP.String(),
		PublicPort:        event.PublicPort,
		PublicStableSince: stableSince,
		PublicUpdatedAt:   updatedAt,
		PrivateAddress:    event.PrivateIP.String(),
		PrivatePort:       event.PrivatePort,
		Protocol:          event.Protocol,
		Logs:              logs,
	})
	if changed {
		r.runNotify(event)
	}
}

func (r *Runner) runNotify(event mappingEvent) {
	if r.cfg.NotifyScript == "" {
		return
	}

	cmd := notifyExecCommand(r.cfg, event, r.cfg.NotifyScript)
	if err := cmd.Start(); err != nil {
		r.emit(RuntimeStatus{
			LastError: err.Error(),
			Logs:      []LogEntry{{At: time.Now(), Level: "error", Message: "notify script failed: " + err.Error()}},
		})
		return
	}

	go func() {
		if err := cmd.Wait(); err != nil {
			r.emit(RuntimeStatus{
				LastError: err.Error(),
				Logs:      []LogEntry{{At: time.Now(), Level: "error", Message: "notify script exited: " + err.Error()}},
			})
		}
	}()
}

func RunNotifyScriptTest(ctx context.Context, cfg InstanceConfig, st RuntimeStatus, script string) (NotifyTestResult, error) {
	script = strings.TrimSpace(script)
	if script == "" {
		return NotifyTestResult{}, errors.New("通知脚本为空")
	}
	if st.PublicAddress == "" || st.PublicPort <= 0 {
		return NotifyTestResult{}, errors.New("当前实例还没有公网映射，无法传入公网变量")
	}
	publicIP := net.ParseIP(st.PublicAddress)
	if publicIP == nil {
		return NotifyTestResult{}, errors.New("当前公网 IP 无效")
	}
	protocol := st.Protocol
	if protocol == "" {
		protocol = cfg.Protocol
	}
	privateIP := net.ParseIP(st.PrivateAddress)
	if privateIP == nil {
		privateIP = net.IPv4zero
	}
	event := mappingEvent{
		PublicIP:    publicIP,
		PublicPort:  st.PublicPort,
		PrivateIP:   privateIP,
		PrivatePort: st.PrivatePort,
		Protocol:    protocol,
	}
	result, err := runNotifyScriptCommand(ctx, cfg, event, script)
	if err != nil {
		return NotifyTestResult{}, err
	}
	return result, nil
}

func runNotifyScriptCommand(ctx context.Context, cfg InstanceConfig, event mappingEvent, script string) (NotifyTestResult, error) {
	expanded := expandNotifyScript(script, notifyTemplateVars(event))
	cmd := notifyCommandContext(ctx, expanded)
	cmd.Env = notifyEnv(cfg, event)
	started := time.Now()
	output, err := cmd.CombinedOutput()
	outputText := strings.TrimRight(string(output), "\r\n")
	result := NotifyTestResult{
		OK:         err == nil,
		DurationMs: maxInt64(1, time.Since(started).Milliseconds()),
		Output:     outputText,
		Command:    expanded,
	}
	if ctx.Err() != nil {
		result.OK = false
		result.ExitCode = -1
		if result.Output == "" {
			result.Output = "通知脚本测试超时"
		}
		return result, nil
	}
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	} else if err != nil {
		result.ExitCode = -1
	}
	if err != nil && result.Output == "" {
		result.Output = err.Error()
	}
	return result, nil
}

func notifyExecCommand(cfg InstanceConfig, event mappingEvent, script string) *exec.Cmd {
	expanded := expandNotifyScript(script, notifyTemplateVars(event))
	cmd := notifyCommand(expanded)
	cmd.Env = notifyEnv(cfg, event)
	return cmd
}

func notifyCommand(script string) *exec.Cmd {
	return notifyCommandContext(context.Background(), script)
}

func notifyCommandContext(ctx context.Context, script string) *exec.Cmd {
	if notifyScriptIsFile(script) {
		if runtime.GOOS == "windows" && strings.HasSuffix(strings.ToLower(script), ".ps1") {
			return exec.CommandContext(ctx, "powershell", "-ExecutionPolicy", "Bypass", "-File", script)
		}
		return exec.CommandContext(ctx, script)
	}

	if runtime.GOOS == "windows" {
		return exec.CommandContext(ctx, "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script)
	}
	return exec.CommandContext(ctx, "sh", "-c", script)
}

func notifyScriptIsFile(script string) bool {
	if strings.ContainsAny(script, "\r\n") {
		return false
	}
	info, err := os.Stat(script)
	return err == nil && !info.IsDir()
}

func notifyEnv(cfg InstanceConfig, event mappingEvent) []string {
	vars := notifyEnvVars(cfg, event)
	return append(os.Environ(),
		"NATCAT_INSTANCE_ID="+vars["NATCAT_INSTANCE_ID"],
		"NATCAT_INSTANCE_NAME="+vars["NATCAT_INSTANCE_NAME"],
		"NATCAT_PROTOCOL="+vars["NATCAT_PROTOCOL"],
		"NATCAT_PUBLIC_ADDRESS="+vars["NATCAT_PUBLIC_ADDRESS"],
		"NATCAT_PUBLIC_IP="+vars["NATCAT_PUBLIC_IP"],
		"NATCAT_PUBLIC_PORT="+vars["NATCAT_PUBLIC_PORT"],
		"NATCAT_PUBLIC_ENDPOINT="+vars["NATCAT_PUBLIC_ENDPOINT"],
		"NATCAT_PRIVATE_ADDRESS="+vars["NATCAT_PRIVATE_ADDRESS"],
		"NATCAT_PRIVATE_PORT="+vars["NATCAT_PRIVATE_PORT"],
	)
}

func notifyEnvVars(cfg InstanceConfig, event mappingEvent) map[string]string {
	publicIP := event.PublicIP.String()
	publicPort := strconv.Itoa(event.PublicPort)
	publicEndpoint := net.JoinHostPort(publicIP, publicPort)
	return map[string]string{
		"NATCAT_INSTANCE_ID":     cfg.ID,
		"NATCAT_INSTANCE_NAME":   cfg.Name,
		"NATCAT_PROTOCOL":        event.Protocol,
		"NATCAT_PUBLIC_ADDRESS":  publicIP,
		"NATCAT_PUBLIC_IP":       publicIP,
		"NATCAT_PUBLIC_PORT":     publicPort,
		"NATCAT_PUBLIC_ENDPOINT": publicEndpoint,
		"NATCAT_PRIVATE_ADDRESS": event.PrivateIP.String(),
		"NATCAT_PRIVATE_PORT":    strconv.Itoa(event.PrivatePort),
	}
}

func notifyTemplateVars(event mappingEvent) map[string]string {
	publicIP := event.PublicIP.String()
	publicPort := strconv.Itoa(event.PublicPort)
	publicEndpoint := net.JoinHostPort(publicIP, publicPort)
	return map[string]string{
		"NATCAT_PUBLIC_ADDRESS":  publicIP,
		"NATCAT_PUBLIC_IP":       publicIP,
		"NATCAT_PUBLIC_PORT":     publicPort,
		"NATCAT_PUBLIC_ENDPOINT": publicEndpoint,
	}
}

func expandNotifyScript(script string, vars map[string]string) string {
	var out strings.Builder
	for i := 0; i < len(script); {
		if script[i] != '$' {
			out.WriteByte(script[i])
			i++
			continue
		}

		if i+2 < len(script) && script[i+1] == '{' {
			end := strings.IndexByte(script[i+2:], '}')
			if end >= 0 {
				name := script[i+2 : i+2+end]
				if value, ok := vars[name]; ok {
					out.WriteString(value)
					i += end + 3
					continue
				}
			}
		}

		start := i + 1
		if start >= len(script) || !isShellVarStart(script[start]) {
			out.WriteByte(script[i])
			i++
			continue
		}
		end := start + 1
		for end < len(script) && isShellVarChar(script[end]) {
			end++
		}
		name := script[start:end]
		if value, ok := vars[name]; ok {
			out.WriteString(value)
		} else {
			out.WriteString(script[i:end])
		}
		i = end
	}
	return out.String()
}

func isShellVarStart(c byte) bool {
	return c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isShellVarChar(c byte) bool {
	return isShellVarStart(c) || (c >= '0' && c <= '9')
}

func (r *Runner) emit(update RuntimeStatus) {
	update.LastChange = time.Now()
	r.report(r.cfg.ID, update)
}

func (r *Runner) emitKeepAlive(state, protocol string, remote net.Addr, message string, latencyMs int64) {
	host := ""
	port := 0
	switch addr := remote.(type) {
	case *net.TCPAddr:
		host = addr.IP.String()
		port = addr.Port
	case *net.UDPAddr:
		host = addr.IP.String()
		port = addr.Port
	default:
		if remote != nil {
			host, port = splitAddr(remote.String())
		}
	}

	now := time.Now()
	keep := KeepAlive{
		State:      state,
		Protocol:   protocol,
		Address:    host,
		Port:       port,
		LatencyMs:  latencyMs,
		LastSeenAt: now,
		Message:    message,
	}
	if state == KeepAliveConnected {
		keep.ConnectedAt = now
	}
	r.emit(RuntimeStatus{KeepAlive: keep})
}

func splitAddr(value string) (string, int) {
	host, rawPort, err := net.SplitHostPort(value)
	if err != nil {
		return value, 0
	}
	port, err := strconv.Atoi(rawPort)
	if err != nil {
		return host, 0
	}
	return host, port
}

func (r *Runner) bindPort() int {
	r.portMu.Lock()
	defer r.portMu.Unlock()

	if !r.hasPort || r.advancePort {
		r.currentPort = r.picker.NextExcept(r.failedPort)
		r.failedPort = -1
		r.hasPort = true
		r.advancePort = false
	}
	return r.currentPort
}

func (r *Runner) advanceBindPort() {
	r.portMu.Lock()
	r.failedPort = r.currentPort
	r.advancePort = true
	r.portMu.Unlock()
}

func (r *Runner) keepBindPort(actualPort int) {
	r.portMu.Lock()
	if actualPort > 0 {
		r.currentPort = actualPort
		r.failedPort = -1
		r.hasPort = true
	}
	r.advancePort = false
	r.portMu.Unlock()
}

func (r *Runner) track(c io.Closer) func() {
	r.activeMu.Lock()
	r.active[c] = struct{}{}
	r.activeMu.Unlock()

	return func() {
		r.activeMu.Lock()
		delete(r.active, c)
		r.activeMu.Unlock()
	}
}

func (r *Runner) closeActive() {
	r.activeMu.Lock()
	closers := make([]io.Closer, 0, len(r.active))
	for closer := range r.active {
		closers = append(closers, closer)
	}
	r.activeMu.Unlock()

	for _, closer := range closers {
		if conn, ok := closer.(*net.TCPConn); ok {
			closeTCP(conn, true)
			continue
		}
		_ = closer.Close()
	}
}

func (r *Runner) updateMapping(event mappingEvent) (bool, time.Time, time.Time) {
	r.mapMu.Lock()
	defer r.mapMu.Unlock()

	now := time.Now()
	publicChanged := r.lastMap == nil ||
		r.lastMap.PublicPort != event.PublicPort ||
		r.lastMap.Protocol != event.Protocol ||
		!r.lastMap.PublicIP.Equal(event.PublicIP)
	if publicChanged || r.publicStableSince.IsZero() {
		r.publicStableSince = now
	}
	if publicChanged || r.publicUpdatedAt.IsZero() {
		r.publicUpdatedAt = now
	}

	if r.lastMap != nil &&
		r.lastMap.PublicPort == event.PublicPort &&
		r.lastMap.PrivatePort == event.PrivatePort &&
		r.lastMap.Protocol == event.Protocol &&
		r.lastMap.PublicIP.Equal(event.PublicIP) &&
		r.lastMap.PrivateIP.Equal(event.PrivateIP) {
		return false, r.publicStableSince, r.publicUpdatedAt
	}

	copied := event
	if event.PublicIP != nil {
		copied.PublicIP = append(net.IP(nil), event.PublicIP...)
	}
	if event.PrivateIP != nil {
		copied.PrivateIP = append(net.IP(nil), event.PrivateIP...)
	}
	r.lastMap = &copied
	return true, r.publicStableSince, r.publicUpdatedAt
}

func (r *Runner) describeRunError(err error) string {
	raw := err.Error()
	lower := strings.ToLower(raw)
	if strings.Contains(lower, "only one usage of each socket address") ||
		strings.Contains(lower, "address already in use") ||
		strings.Contains(lower, "eaddrinuse") {
		return fmt.Sprintf("本地端口 %s 已被占用或还在系统保留状态。请换一个绑定端口，或停止占用该端口的程序后再启动。原始错误：%s", r.cfg.BindPort, raw)
	}
	if strings.Contains(lower, "cannot assign requested address") ||
		strings.Contains(lower, "eaddrnotavail") {
		return fmt.Sprintf("无法使用绑定地址/端口 %s:%s。请检查绑定地址是否属于本机，或等待上一条连接释放。原始错误：%s", emptyAsAny(r.cfg.BindAddress), r.cfg.BindPort, raw)
	}
	if strings.Contains(lower, "no such host") {
		return fmt.Sprintf("域名解析失败。请检查 HTTP/QUIC 保活目标或公网探测服务。原始错误：%s", raw)
	}
	if strings.Contains(lower, "timeout") || strings.Contains(lower, "timed out") {
		return fmt.Sprintf("连接超时。请检查网络、HTTP/QUIC 保活目标、公网探测服务和防火墙。原始错误：%s", raw)
	}
	return raw
}

func emptyAsAny(value string) string {
	if value == "" {
		return "自动"
	}
	return value
}
