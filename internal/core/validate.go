package core

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"strconv"
	"strings"
)

const (
	defaultProbeHost            = "turn.cloudflare.com"
	defaultProbePort            = 3478
	defaultMappingConfirmations = 3
	maxMappingConfirmations     = 20
)

func normalizeConfig(cfg *InstanceConfig) {
	cfg.Name = strings.TrimSpace(cfg.Name)
	cfg.Protocol = strings.ToLower(strings.TrimSpace(cfg.Protocol))
	cfg.BindAddress = strings.TrimSpace(cfg.BindAddress)
	cfg.BindPort = strings.TrimSpace(cfg.BindPort)
	cfg.STUNMode = strings.ToLower(strings.TrimSpace(cfg.STUNMode))
	cfg.STUNGroupID = strings.TrimSpace(cfg.STUNGroupID)
	cfg.STUNHost = strings.TrimSpace(cfg.STUNHost)
	cfg.KeepAliveMode = strings.ToLower(strings.TrimSpace(cfg.KeepAliveMode))
	cfg.KeepAliveGroupID = strings.TrimSpace(cfg.KeepAliveGroupID)
	cfg.HTTPHost = strings.TrimSpace(cfg.HTTPHost)
	cfg.Interface = strings.TrimSpace(cfg.Interface)
	cfg.NotifyScript = strings.TrimSpace(cfg.NotifyScript)

	if cfg.Name == "" {
		cfg.Name = "NATCat Instance"
	}
	if cfg.Protocol == "" {
		cfg.Protocol = "tcp"
	}
	if cfg.BindPort == "" {
		cfg.BindPort = "0"
	}
	if cfg.STUNMode == "" {
		cfg.STUNMode = "custom"
	}
	if cfg.KeepAliveMode == "" {
		cfg.KeepAliveMode = "custom"
	}
	if cfg.HTTPPort <= 0 {
		if cfg.Protocol == "udp" {
			cfg.HTTPPort = 443
		} else {
			cfg.HTTPPort = 80
		}
	}
	if cfg.KeepAliveSeconds <= 0 {
		if cfg.Protocol == "udp" {
			cfg.KeepAliveSeconds = 10
		} else {
			cfg.KeepAliveSeconds = 30
		}
	}
	if cfg.UDPSTUNCycle <= 0 {
		cfg.UDPSTUNCycle = 10
	}
	if cfg.MappingConfirmations <= 0 {
		cfg.MappingConfirmations = defaultMappingConfirmations
	}
}

func validateConfig(cfg InstanceConfig) error {
	if cfg.Protocol != "tcp" && cfg.Protocol != "udp" {
		return errors.New("protocol must be tcp or udp")
	}
	if cfg.STUNMode != "custom" && cfg.STUNMode != "group" {
		return errors.New("stunMode must be custom or group")
	}
	if cfg.KeepAliveMode != "custom" && cfg.KeepAliveMode != "group" {
		return errors.New("keepAliveMode must be custom or group")
	}
	if cfg.KeepAliveMode == "custom" && cfg.HTTPHost == "" {
		if cfg.Protocol == "udp" {
			return errors.New("quic host is required for udp")
		}
		return errors.New("httpHost is required for tcp")
	}
	if cfg.STUNPort < 0 || cfg.STUNPort > 65535 {
		return errors.New("public probe port must be 1-65535")
	}
	if cfg.HTTPPort < 0 || cfg.HTTPPort > 65535 {
		return errors.New("httpPort must be 0-65535")
	}
	if cfg.UDPSTUNCycle <= 0 || cfg.UDPSTUNCycle > 10000 {
		return errors.New("udpStunCycle must be 1-10000")
	}
	if cfg.MappingConfirmations <= 0 || cfg.MappingConfirmations > maxMappingConfirmations {
		return errors.New("mappingConfirmations must be 1-20")
	}
	if cfg.BindAddress != "" {
		ip := net.ParseIP(cfg.BindAddress)
		if ip == nil || ip.To4() == nil {
			return errors.New("bindAddress must be an IPv4 address")
		}
	}
	if _, err := newPortPicker(cfg.BindPort); err != nil {
		return err
	}
	return nil
}

func validPort(port int) bool {
	return port > 0 && port <= 65535
}

func networkFor(protocol string) string {
	if protocol == "udp" {
		return "udp4"
	}
	return "tcp4"
}

func parseBindIP(value string) net.IP {
	if value == "" {
		return net.IPv4zero
	}

	ip := net.ParseIP(value)
	if ip == nil || ip.To4() == nil {
		return net.IPv4zero
	}
	return ip.To4()
}

func hostPort(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
}

func endpointHostPort(endpoint ServerEndpoint) string {
	return hostPort(endpoint.Host, endpoint.Port)
}

func publicProbeHostPort(cfg InstanceConfig) string {
	host := cfg.STUNHost
	if host == "" {
		host = defaultProbeHost
	}
	port := cfg.STUNPort
	if port <= 0 {
		port = defaultProbePort
	}
	return hostPort(host, port)
}

func normalizeServerEndpoints(servers []ServerEndpoint, defaultPort int) []ServerEndpoint {
	out := make([]ServerEndpoint, 0, len(servers))
	seen := map[string]struct{}{}
	for _, server := range servers {
		server.Host = normalizeServerHost(server.Host)
		if server.Port <= 0 {
			server.Port = defaultPort
		}
		if server.Host == "" {
			continue
		}
		key := strings.ToLower(endpointHostPort(server))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, server)
	}
	return out
}

func normalizeServerHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "http://")
	host = strings.TrimPrefix(host, "https://")
	host = strings.Trim(host, "/")
	return host
}

func validateServerEndpoints(servers []ServerEndpoint, kind string) error {
	if len(servers) == 0 {
		return errors.New(kind + " server list must contain at least one server")
	}
	for _, server := range servers {
		if strings.TrimSpace(server.Host) == "" {
			return errors.New(kind + " server host is required")
		}
		if !validPort(server.Port) {
			return errors.New(kind + " server port must be 1-65535")
		}
	}
	return nil
}

func defaultSTUNServers() []ServerEndpoint {
	return []ServerEndpoint{
		{Host: "stun.miwifi.com", Port: 3478},
		{Host: "stun.cloudflare.com", Port: 3478},
		{Host: "stun.l.google.com", Port: 19302},
		{Host: defaultProbeHost, Port: defaultProbePort},
	}
}

func defaultHTTPServers() []ServerEndpoint {
	return []ServerEndpoint{
		{Host: "qq.com", Port: 80},
		{Host: "223.5.5.5", Port: 80},
	}
}

func defaultQUICServers() []ServerEndpoint {
	return []ServerEndpoint{
		{Host: "zhuanlan.zhihu.com", Port: 443},
	}
}

func customSTUNServers(cfg InstanceConfig) []ServerEndpoint {
	host := cfg.STUNHost
	if host == "" {
		host = defaultProbeHost
	}
	port := cfg.STUNPort
	if port <= 0 {
		port = defaultProbePort
	}
	return []ServerEndpoint{{Host: host, Port: port}}
}

func customKeepAliveServers(cfg InstanceConfig) []ServerEndpoint {
	return []ServerEndpoint{{Host: cfg.HTTPHost, Port: cfg.HTTPPort}}
}

func stunServers(cfg InstanceConfig) []ServerEndpoint {
	if len(cfg.resolvedSTUNServers) > 0 {
		return cfg.resolvedSTUNServers
	}
	return customSTUNServers(cfg)
}

func keepAliveServers(cfg InstanceConfig) []ServerEndpoint {
	if len(cfg.resolvedKeepAliveServers) > 0 {
		return cfg.resolvedKeepAliveServers
	}
	return customKeepAliveServers(cfg)
}

func newID() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return strconv.FormatInt(int64(len(buf)), 36)
	}
	return hex.EncodeToString(buf)
}
