package core

import "time"

type Database struct {
	Version int                               `json:"version"`
	Admin   AdminCredential                   `json:"admin"`
	Options SystemOptions                     `json:"options"`
	Items   []InstanceConfig                  `json:"instances"`
	Runtime map[string]PersistedRuntimeStatus `json:"runtime,omitempty"`
}

type SystemOptions struct {
	SessionHours    int              `json:"sessionHours"`
	STUNServers     []ServerEndpoint `json:"stunServers"`
	HTTPServers     []ServerEndpoint `json:"httpServers"`
	QUICServers     []ServerEndpoint `json:"quicServers"`
	STUNGroups      []ServerGroup    `json:"stunGroups,omitempty"`
	KeepAliveGroups []ServerGroup    `json:"keepAliveGroups,omitempty"`
}

type ServerGroup struct {
	ID      string           `json:"id"`
	Name    string           `json:"name"`
	Servers []ServerEndpoint `json:"servers"`
}

type ServerEndpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

type ServerGroupsConfig struct {
	STUNServers     []ServerEndpoint `json:"stunServers"`
	HTTPServers     []ServerEndpoint `json:"httpServers"`
	QUICServers     []ServerEndpoint `json:"quicServers"`
	STUNGroups      []ServerGroup    `json:"stunGroups,omitempty"`
	KeepAliveGroups []ServerGroup    `json:"keepAliveGroups,omitempty"`
}

type AdminCredential struct {
	Username     string    `json:"username"`
	Salt         string    `json:"salt"`
	Hash         string    `json:"hash"`
	Iterations   int       `json:"iterations"`
	LastPassword time.Time `json:"lastPassword"`
}

type InstanceConfig struct {
	ID                   string `json:"id"`
	Name                 string `json:"name"`
	Enabled              bool   `json:"enabled"`
	Protocol             string `json:"protocol"`
	BindAddress          string `json:"bindAddress"`
	BindPort             string `json:"bindPort"`
	STUNMode             string `json:"stunMode"`
	STUNGroupID          string `json:"stunGroupId"`
	STUNHost             string `json:"stunHost"`
	STUNPort             int    `json:"stunPort"`
	KeepAliveMode        string `json:"keepAliveMode"`
	KeepAliveGroupID     string `json:"keepAliveGroupId"`
	HTTPHost             string `json:"httpHost"`
	HTTPPort             int    `json:"httpPort"`
	Interface            string `json:"interface"`
	KeepAliveSeconds     int    `json:"keepAliveSeconds"`
	UDPSTUNCycle         int    `json:"udpStunCycle"`
	MappingConfirmations int    `json:"mappingConfirmations"`
	NotifyScript         string `json:"notifyScript"`
	FWMark               uint32 `json:"fwMark"`

	resolvedSTUNServers      []ServerEndpoint
	resolvedKeepAliveServers []ServerEndpoint
}

type RuntimeStatus struct {
	State             string     `json:"state"`
	StartedAt         *time.Time `json:"startedAt,omitempty"`
	LastChange        time.Time  `json:"lastChange"`
	PublicAddress     string     `json:"publicAddress"`
	PublicPort        int        `json:"publicPort"`
	PublicStableSince time.Time  `json:"publicStableSince,omitempty"`
	PublicUpdatedAt   time.Time  `json:"publicUpdatedAt,omitempty"`
	PrivateAddress    string     `json:"privateAddress"`
	PrivatePort       int        `json:"privatePort"`
	Protocol          string     `json:"protocol"`
	LastError         string     `json:"lastError"`
	KeepAlive         KeepAlive  `json:"keepAlive"`
	PortCheck         PortCheck  `json:"portCheck"`
	Logs              []LogEntry `json:"logs"`
}

type PortCheck struct {
	Protocol  string    `json:"protocol"`
	State     string    `json:"state"`
	LatencyMs int64     `json:"latencyMs,omitempty"`
	CheckedAt time.Time `json:"checkedAt,omitempty"`
	Message   string    `json:"message"`
}

type KeepAlive struct {
	State       string    `json:"state"`
	Protocol    string    `json:"protocol"`
	Address     string    `json:"address"`
	Port        int       `json:"port"`
	LatencyMs   int64     `json:"latencyMs,omitempty"`
	LossPercent int       `json:"lossPercent"`
	ProbeCount  int       `json:"probeCount,omitempty"`
	LostProbes  int       `json:"lostProbes,omitempty"`
	ConnectedAt time.Time `json:"connectedAt,omitempty"`
	LastSeenAt  time.Time `json:"lastSeenAt,omitempty"`
	Message     string    `json:"message"`
}

type LogEntry struct {
	At      time.Time `json:"at"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
}

type NotifyTestResult struct {
	OK         bool   `json:"ok"`
	ExitCode   int    `json:"exitCode"`
	DurationMs int64  `json:"durationMs"`
	Output     string `json:"output"`
	Command    string `json:"command"`
}

type PersistedRuntimeStatus struct {
	PublicAddress     string    `json:"publicAddress"`
	PublicPort        int       `json:"publicPort"`
	PublicStableSince time.Time `json:"publicStableSince,omitempty"`
	PublicUpdatedAt   time.Time `json:"publicUpdatedAt,omitempty"`
	PrivateAddress    string    `json:"privateAddress,omitempty"`
	PrivatePort       int       `json:"privatePort,omitempty"`
	Protocol          string    `json:"protocol,omitempty"`
}

type InstanceSnapshot struct {
	Config  InstanceConfig `json:"config"`
	Runtime RuntimeStatus  `json:"runtime"`
}

const (
	StateStopped  = "stopped"
	StateStarting = "starting"
	StateRunning  = "running"
	StateStopping = "stopping"
	StateError    = "error"
)

const (
	KeepAliveUnknown      = "unknown"
	KeepAliveConnected    = "connected"
	KeepAliveReconnecting = "reconnecting"
	KeepAliveDisconnected = "disconnected"
)
