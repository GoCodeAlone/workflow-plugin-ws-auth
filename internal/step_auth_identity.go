package internal

import (
	"context"

	"github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

type authIdentityStep struct{ name string }

func newAuthIdentityStep(name string, _ map[string]any) (sdk.StepInstance, error) {
	return &authIdentityStep{name: name}, nil
}

func (s *authIdentityStep) Execute(_ context.Context, _ map[string]any,
	_ map[string]map[string]any, current map[string]any,
	_ map[string]any, config map[string]any) (*sdk.StepResult, error) {

	enforcer := GetGlobalEnforcer()
	if enforcer == nil {
		return &sdk.StepResult{Output: map[string]any{
			"player_id":     "",
			"authenticated": false,
			"error":         "ws_auth.hmac not initialized",
		}}, nil
	}

	connID, _ := config["connection_id"].(string)
	if connID == "" {
		connID, _ = current["connectionId"].(string)
	}
	if connID == "" {
		connID, _ = current["connID"].(string)
	}

	playerID := enforcer.GetPlayerID(connID)
	return &sdk.StepResult{Output: map[string]any{
		"player_id":     playerID,
		"authenticated": playerID != "",
	}}, nil
}
