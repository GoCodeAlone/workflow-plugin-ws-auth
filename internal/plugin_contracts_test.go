package internal

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/GoCodeAlone/workflow-plugin-ws-auth/internal/contracts"
	pb "github.com/GoCodeAlone/workflow/plugin/external/proto"
	"github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestPluginImplementsStrictContractProviders(t *testing.T) {
	provider := NewWSAuthPlugin()
	if _, ok := provider.(sdk.TypedModuleProvider); !ok {
		t.Fatal("expected TypedModuleProvider")
	}
	if _, ok := provider.(sdk.TypedStepProvider); !ok {
		t.Fatal("expected TypedStepProvider")
	}
	if _, ok := provider.(sdk.ContractProvider); !ok {
		t.Fatal("expected ContractProvider")
	}
}

func TestContractRegistryDeclaresStrictContracts(t *testing.T) {
	provider := NewWSAuthPlugin().(sdk.ContractProvider)
	registry := provider.ContractRegistry()
	files, err := protodesc.NewFiles(registry.FileDescriptorSet)
	if err != nil {
		t.Fatalf("descriptor set: %v", err)
	}
	manifestContracts := loadManifestContracts(t)
	contractsByKey := map[string]*pb.ContractDescriptor{}
	for _, contract := range registry.Contracts {
		if contract.Mode != pb.ContractMode_CONTRACT_MODE_STRICT_PROTO {
			t.Fatalf("%s mode = %s, want strict", contractKey(contract), contract.Mode)
		}
		key := contractKey(contract)
		if _, exists := contractsByKey[key]; exists {
			t.Fatalf("duplicate runtime contract %q", key)
		}
		contractsByKey[key] = contract
		for _, name := range []string{contract.ConfigMessage, contract.InputMessage, contract.OutputMessage} {
			if name == "" {
				continue
			}
			if _, err := files.FindDescriptorByName(protoreflect.FullName(name)); err != nil {
				t.Fatalf("%s references unknown descriptor %s: %v", key, name, err)
			}
		}
		want, ok := manifestContracts[key]
		if !ok {
			t.Fatalf("%s missing from plugin.contracts.json", key)
		}
		if want.ConfigMessage != contract.ConfigMessage || want.InputMessage != contract.InputMessage || want.OutputMessage != contract.OutputMessage {
			t.Fatalf("%s manifest = %#v runtime = %#v", key, want, contract)
		}
	}
	if len(contractsByKey) != len(manifestContracts) {
		t.Fatalf("runtime contract count = %d, manifest = %d", len(contractsByKey), len(manifestContracts))
	}
}

func TestTypedProvidersValidateConfigAndUseTypedInput(t *testing.T) {
	provider := NewWSAuthPlugin().(interface {
		sdk.TypedModuleProvider
		sdk.TypedStepProvider
	})
	config, err := anypb.New(&contracts.HMACAuthConfig{SharedSecret: "secret", ServerId: "server"})
	if err != nil {
		t.Fatalf("pack module config: %v", err)
	}
	module, err := provider.CreateTypedModule("ws_auth.hmac", "auth", config)
	if err != nil {
		t.Fatalf("CreateTypedModule: %v", err)
	}
	if err := module.Stop(nil); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	wrongConfig, err := anypb.New(&contracts.AuthIdentityConfig{ConnectionId: "conn-1"})
	if err != nil {
		t.Fatalf("pack wrong config: %v", err)
	}
	if _, err := provider.CreateTypedModule("ws_auth.hmac", "auth", wrongConfig); err == nil {
		t.Fatal("CreateTypedModule accepted wrong typed config")
	}

	SetGlobalEnforcer(NewProtocolEnforcer([]byte("secret"), "server"))
	t.Cleanup(func() { SetGlobalEnforcer(nil) })
	stepResult, err := typedAuthIdentity(nil, sdk.TypedStepRequest[*contracts.AuthIdentityConfig, *contracts.AuthIdentityInput]{
		Input: &contracts.AuthIdentityInput{ConnectionId: "conn-1"},
	})
	if err != nil {
		t.Fatalf("typedAuthIdentity: %v", err)
	}
	if stepResult.Output.GetAuthenticated() {
		t.Fatal("expected unauthenticated unknown connection")
	}
}

func TestTypedAuthIdentityInputOverridesStaticConfig(t *testing.T) {
	enforcer := NewProtocolEnforcer([]byte("secret"), "server")
	enforcer.connToPlayer.Store("runtime-conn", "runtime-player")
	SetGlobalEnforcer(enforcer)
	t.Cleanup(func() { SetGlobalEnforcer(nil) })

	stepResult, err := typedAuthIdentity(nil, sdk.TypedStepRequest[*contracts.AuthIdentityConfig, *contracts.AuthIdentityInput]{
		Config: &contracts.AuthIdentityConfig{ConnectionId: "static-conn"},
		Input:  &contracts.AuthIdentityInput{ConnectionId: "runtime-conn"},
	})
	if err != nil {
		t.Fatalf("typedAuthIdentity: %v", err)
	}
	if got := stepResult.Output.GetPlayerId(); got != "runtime-player" {
		t.Fatalf("player_id = %q, want runtime-player", got)
	}
	if !stepResult.Output.GetAuthenticated() {
		t.Fatal("expected authenticated runtime connection")
	}
}

type manifestContract struct {
	Mode          string `json:"mode"`
	ConfigMessage string `json:"config"`
	InputMessage  string `json:"input"`
	OutputMessage string `json:"output"`
}

func loadManifestContracts(t *testing.T) map[string]manifestContract {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "..", "plugin.contracts.json"))
	if err != nil {
		t.Fatalf("read plugin.contracts.json: %v", err)
	}
	var manifest struct {
		Version   string `json:"version"`
		Contracts []struct {
			Kind string `json:"kind"`
			Type string `json:"type"`
			manifestContract
		} `json:"contracts"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("parse plugin.contracts.json: %v", err)
	}
	if manifest.Version != "v1" {
		t.Fatalf("plugin.contracts.json version = %q, want v1", manifest.Version)
	}
	out := make(map[string]manifestContract, len(manifest.Contracts))
	for _, contract := range manifest.Contracts {
		if contract.Mode != "strict" {
			t.Fatalf("%s mode = %q, want strict", contract.Type, contract.Mode)
		}
		key := contract.Kind + ":" + contract.Type
		if _, exists := out[key]; exists {
			t.Fatalf("duplicate manifest contract %q", key)
		}
		out[key] = contract.manifestContract
	}
	return out
}

func contractKey(contract *pb.ContractDescriptor) string {
	switch contract.Kind {
	case pb.ContractKind_CONTRACT_KIND_MODULE:
		return "module:" + contract.ModuleType
	case pb.ContractKind_CONTRACT_KIND_STEP:
		return "step:" + contract.StepType
	default:
		return contract.Kind.String()
	}
}
