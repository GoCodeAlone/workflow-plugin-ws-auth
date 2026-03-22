package internal

import (
	"context"
	"os"

	"github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

type hmacAuthModule struct {
	name     string
	enforcer *ProtocolEnforcer
}

func newHMACAuthModule(name string, config map[string]any) (sdk.ModuleInstance, error) {
	secret := []byte("ws-auth-secret-v1")
	if v, ok := config["shared_secret"].(string); ok && v != "" {
		secret = []byte(v)
	}
	if v := os.Getenv("SDK_SECRET"); v != "" {
		secret = []byte(v)
	}

	serverID := "ws-auth-server"
	if v, ok := config["server_id"].(string); ok && v != "" {
		serverID = v
	}

	enforcer := NewProtocolEnforcer(secret, serverID)
	SetGlobalEnforcer(enforcer)

	return &hmacAuthModule{
		name:     name,
		enforcer: enforcer,
	}, nil
}

func (m *hmacAuthModule) Init() error  { return nil }
func (m *hmacAuthModule) Start(_ context.Context) error { return nil }

func (m *hmacAuthModule) Stop(_ context.Context) error {
	globalEnforcerMu.Lock()
	if globalEnforcer == m.enforcer {
		globalEnforcer = nil
	}
	globalEnforcerMu.Unlock()
	return nil
}
