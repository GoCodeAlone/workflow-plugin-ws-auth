package internal

import (
	"context"

	"github.com/GoCodeAlone/workflow-plugin-ws-auth/internal/contracts"
	sdk "github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

func typedAuthIdentity(ctx context.Context, req sdk.TypedStepRequest[*contracts.AuthIdentityConfig, *contracts.AuthIdentityInput]) (*sdk.TypedStepResult[*contracts.AuthIdentityOutput], error) {
	if ctx == nil {
		ctx = context.Background()
	}
	config := mergeMaps(authIdentityConfigToMap(req.Config), authIdentityInputToMap(req.Input))
	step, err := newAuthIdentityStep("", nil)
	if err != nil {
		return nil, err
	}
	result, err := step.Execute(ctx, req.TriggerData, req.StepOutputs, req.Current, req.Metadata, config)
	if err != nil {
		return nil, err
	}
	return &sdk.TypedStepResult[*contracts.AuthIdentityOutput]{Output: authIdentityOutputFromMap(result.Output), StopPipeline: result.StopPipeline}, nil
}

func hmacConfigToMap(cfg *contracts.HMACAuthConfig) map[string]any {
	if cfg == nil {
		return nil
	}
	return compactMap(map[string]any{"shared_secret": cfg.GetSharedSecret(), "server_id": cfg.GetServerId()})
}

func authIdentityConfigToMap(cfg *contracts.AuthIdentityConfig) map[string]any {
	if cfg == nil {
		return nil
	}
	return compactMap(map[string]any{"connection_id": cfg.GetConnectionId()})
}

func authIdentityInputToMap(input *contracts.AuthIdentityInput) map[string]any {
	if input == nil {
		return nil
	}
	return compactMap(map[string]any{"connection_id": input.GetConnectionId()})
}

func authIdentityOutputFromMap(values map[string]any) *contracts.AuthIdentityOutput {
	return &contracts.AuthIdentityOutput{
		PlayerId:      strVal(values, "player_id"),
		Authenticated: boolVal(values, "authenticated"),
		Error:         strVal(values, "error"),
	}
}

func mergeMaps(maps ...map[string]any) map[string]any {
	out := map[string]any{}
	for _, values := range maps {
		for key, value := range values {
			out[key] = value
		}
	}
	return out
}

func compactMap(values map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range values {
		if value == nil {
			continue
		}
		if s, ok := value.(string); ok && s == "" {
			continue
		}
		out[key] = value
	}
	return out
}

func strVal(values map[string]any, key string) string {
	if values == nil {
		return ""
	}
	if value, ok := values[key].(string); ok {
		return value
	}
	return ""
}

func boolVal(values map[string]any, key string) bool {
	if values == nil {
		return false
	}
	value, _ := values[key].(bool)
	return value
}
