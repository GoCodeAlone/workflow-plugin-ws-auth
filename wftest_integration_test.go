package wsauth_test

import (
	"testing"

	"github.com/GoCodeAlone/workflow/wftest"
)

const wsAuthPipelineYAML = `
pipelines:
  ws-auth:
    trigger:
      type: manual
    steps:
      - name: verify
        type: step.ws_auth_identity
        config:
          token_header: X-Auth-Token
`

func TestWSAuth_IdentityVerificationPipeline_Authenticated(t *testing.T) {
	authRec := wftest.RecordStep("step.ws_auth_identity")
	authRec.WithOutput(map[string]any{
		"player_id":     "user-123",
		"authenticated": true,
	})

	h := wftest.New(t, wftest.WithYAML(wsAuthPipelineYAML), authRec)

	result := h.ExecutePipeline("ws-auth", map[string]any{
		"connectionId": "conn-456",
	})
	if result.Error != nil {
		t.Fatalf("pipeline failed: %v", result.Error)
	}
	if authRec.CallCount() != 1 {
		t.Errorf("expected 1 call, got %d", authRec.CallCount())
	}
	if result.Output["authenticated"] != true {
		t.Errorf("expected authenticated=true, got %v", result.Output["authenticated"])
	}
	if result.Output["player_id"] != "user-123" {
		t.Errorf("expected player_id=user-123, got %v", result.Output["player_id"])
	}
}

func TestWSAuth_IdentityVerificationPipeline_Unauthenticated(t *testing.T) {
	authRec := wftest.RecordStep("step.ws_auth_identity")
	authRec.WithOutput(map[string]any{
		"player_id":     "",
		"authenticated": false,
	})

	h := wftest.New(t, wftest.WithYAML(wsAuthPipelineYAML), authRec)

	result := h.ExecutePipeline("ws-auth", map[string]any{
		"connectionId": "conn-unknown",
	})
	if result.Error != nil {
		t.Fatalf("pipeline failed: %v", result.Error)
	}
	if authRec.CallCount() != 1 {
		t.Errorf("expected 1 call, got %d", authRec.CallCount())
	}
	if result.Output["authenticated"] != false {
		t.Errorf("expected authenticated=false, got %v", result.Output["authenticated"])
	}
	if result.Output["player_id"] != "" {
		t.Errorf("expected empty player_id, got %v", result.Output["player_id"])
	}
}

func TestWSAuth_IdentityVerificationPipeline_InputPropagated(t *testing.T) {
	authRec := wftest.RecordStep("step.ws_auth_identity")
	authRec.WithOutput(map[string]any{
		"player_id":     "player-789",
		"authenticated": true,
	})

	h := wftest.New(t, wftest.WithYAML(wsAuthPipelineYAML), authRec)

	result := h.ExecutePipeline("ws-auth", map[string]any{
		"connectionId": "conn-789",
		"session_id":   "session-abc",
	})
	if result.Error != nil {
		t.Fatalf("pipeline failed: %v", result.Error)
	}
	if authRec.CallCount() != 1 {
		t.Errorf("expected 1 call, got %d", authRec.CallCount())
	}

	calls := authRec.Calls()
	if len(calls) == 0 {
		t.Fatal("expected at least one recorded call")
	}
	if calls[0].Input["connectionId"] != "conn-789" {
		t.Errorf("expected connectionId=conn-789 in input, got %v", calls[0].Input["connectionId"])
	}
	if result.Output["player_id"] != "player-789" {
		t.Errorf("expected player_id=player-789, got %v", result.Output["player_id"])
	}
}
