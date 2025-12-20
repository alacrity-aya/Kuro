package control

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	pb "kuro/proto"
)

type hostInfo struct {
	// become true when receiving ApplyNodeConfig ack from data panel
	online       bool
	ip           string
	agentVersion string
	capabilities []string
}

type MemRegistry struct {
	// hostname -> config
	configs map[string]*pb.ApplyNodeConfig

	// hostname -> online_status
	info map[string]*hostInfo

	mu sync.RWMutex
}

func NewMemRegistry(configs map[string]*pb.ApplyNodeConfig) *MemRegistry {
	return &MemRegistry{configs: configs, info: make(map[string]*hostInfo)}
}

// RegisterNode return hostname config
func (m *MemRegistry) RegisterHost(ctx context.Context, hello *pb.Hello) (*pb.ApplyNodeConfig, error) {
	hostName := hello.GetHostName()

	m.mu.Lock()
	defer m.mu.Unlock()

	slog.Debug("RegisterNode", "hostName", hostName, "config", m.configs[hostName], "hello", hello)

	config, exist := m.configs[hostName]
	if !exist {
		return nil, fmt.Errorf("failed to find config for host name: %s", hostName)
	}

	if _, ok := m.info[hostName]; !ok {
		m.info[hostName] = &hostInfo{}
	}

	m.info[hostName].online = false
	m.info[hostName].ip = hello.GetIp()
	m.info[hostName].agentVersion = hello.GetAgentVersion()
	m.info[hostName].capabilities = hello.GetCapabilities()

	return config, nil
}

func (m *MemRegistry) UpdateHostState(ctx context.Context, hostName string, online bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	_, exist := m.info[hostName]
	if !exist {
		return fmt.Errorf("failed to get host statue, host: %s", hostName)
	}

	m.info[hostName].online = online

	slog.Debug("UpdateHostState", "clientName", hostName)
	return nil
}

func (m *MemRegistry) GetInfo(hostName string) (hostInfo, bool) {
	info, exist := m.info[hostName]
	if !exist {
		return hostInfo{}, false
	}

	if info == nil {
		return hostInfo{}, false
	}

	return *info, true
}
