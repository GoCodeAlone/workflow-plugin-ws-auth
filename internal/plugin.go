package internal

import (
	"fmt"
	"sync"

	"github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

var (
	globalEnforcer   *ProtocolEnforcer
	globalEnforcerMu sync.RWMutex
)

// GetGlobalEnforcer returns the global protocol enforcer.
func GetGlobalEnforcer() *ProtocolEnforcer {
	globalEnforcerMu.RLock()
	defer globalEnforcerMu.RUnlock()
	return globalEnforcer
}

// SetGlobalEnforcer sets the global protocol enforcer.
func SetGlobalEnforcer(pe *ProtocolEnforcer) {
	globalEnforcerMu.Lock()
	globalEnforcer = pe
	globalEnforcerMu.Unlock()
}

type wsAuthPlugin struct{}

// NewWSAuthPlugin returns the ws-auth SDK plugin provider.
func NewWSAuthPlugin() sdk.PluginProvider {
	return &wsAuthPlugin{}
}

func (p *wsAuthPlugin) Manifest() sdk.PluginManifest {
	return sdk.PluginManifest{
		Name:        "workflow-plugin-ws-auth",
		Version:     "0.1.0",
		Author:      "GoCodeAlone",
		Description: "WebSocket HMAC authentication — challenge-response handshake with per-connection keys",
	}
}

func (p *wsAuthPlugin) ModuleTypes() []string {
	return []string{"ws_auth.hmac"}
}

func (p *wsAuthPlugin) StepTypes() []string {
	return []string{"step.ws_auth_identity"}
}

func (p *wsAuthPlugin) CreateModule(typeName, name string, config map[string]any) (sdk.ModuleInstance, error) {
	switch typeName {
	case "ws_auth.hmac":
		return newHMACAuthModule(name, config)
	default:
		return nil, fmt.Errorf("unknown module type %q", typeName)
	}
}

func (p *wsAuthPlugin) CreateStep(typeName, name string, config map[string]any) (sdk.StepInstance, error) {
	switch typeName {
	case "step.ws_auth_identity":
		return newAuthIdentityStep(name, config)
	default:
		return nil, fmt.Errorf("unknown step type %q", typeName)
	}
}
