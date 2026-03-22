// Package wsauth provides the workflow-plugin-ws-auth SDK plugin.
// It implements HMAC-SHA256 challenge-response authentication for WebSocket connections
// with per-connection key derivation and sequence-based replay protection.
package wsauth

import (
	"github.com/GoCodeAlone/workflow-plugin-ws-auth/internal"
	"github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

// ProtocolEnforcer manages HMAC handshakes and validates signed messages.
type ProtocolEnforcer = internal.ProtocolEnforcer

// NewWSAuthPlugin returns the ws-auth SDK plugin provider.
func NewWSAuthPlugin() sdk.PluginProvider {
	return internal.NewWSAuthPlugin()
}

// GetEnforcer returns the global protocol enforcer once the ws_auth.hmac module
// has initialized. Returns nil if the module has not started yet.
func GetEnforcer() *ProtocolEnforcer {
	return internal.GetGlobalEnforcer()
}

// NewProtocolEnforcer creates a standalone protocol enforcer (useful for testing).
func NewProtocolEnforcer(sdkSecret []byte, serverID string) *ProtocolEnforcer {
	return internal.NewProtocolEnforcer(sdkSecret, serverID)
}
