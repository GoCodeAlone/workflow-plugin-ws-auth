package internal

import (
	"fmt"
	"sync"

	"github.com/GoCodeAlone/workflow-plugin-ws-auth/internal/contracts"
	pb "github.com/GoCodeAlone/workflow/plugin/external/proto"
	"github.com/GoCodeAlone/workflow/plugin/external/sdk"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/known/anypb"
)

// Version is set at build time via -ldflags
// "-X github.com/GoCodeAlone/workflow-plugin-ws-auth/internal.Version=X.Y.Z".
// Default is a bare semver so plugin loaders that validate semver accept
// unreleased dev builds; goreleaser overrides with the real release tag.
var Version = "0.0.0"

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
		Version:     Version,
		Author:      "GoCodeAlone",
		Description: "WebSocket HMAC authentication — challenge-response handshake with per-connection keys",
	}
}

func (p *wsAuthPlugin) ModuleTypes() []string {
	return append([]string(nil), wsAuthModuleTypes...)
}

func (p *wsAuthPlugin) StepTypes() []string {
	return append([]string(nil), wsAuthStepTypes...)
}

func (p *wsAuthPlugin) TypedModuleTypes() []string { return p.ModuleTypes() }

func (p *wsAuthPlugin) TypedStepTypes() []string { return p.StepTypes() }

func (p *wsAuthPlugin) CreateModule(typeName, name string, config map[string]any) (sdk.ModuleInstance, error) {
	switch typeName {
	case "ws_auth.hmac":
		return newHMACAuthModule(name, config)
	default:
		return nil, fmt.Errorf("unknown module type %q", typeName)
	}
}

func (p *wsAuthPlugin) CreateTypedModule(typeName, name string, config *anypb.Any) (sdk.ModuleInstance, error) {
	switch typeName {
	case "ws_auth.hmac":
		factory := sdk.NewTypedModuleFactory(typeName, &contracts.HMACAuthConfig{}, func(name string, cfg *contracts.HMACAuthConfig) (sdk.ModuleInstance, error) {
			return newHMACAuthModule(name, hmacConfigToMap(cfg))
		})
		return factory.CreateTypedModule(typeName, name, config)
	default:
		return nil, fmt.Errorf("unknown typed module type %q", typeName)
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

func (p *wsAuthPlugin) CreateTypedStep(typeName, name string, config *anypb.Any) (sdk.StepInstance, error) {
	switch typeName {
	case "step.ws_auth_identity":
		factory := sdk.NewTypedStepFactory(typeName, &contracts.AuthIdentityConfig{}, &contracts.AuthIdentityInput{}, typedAuthIdentity)
		return factory.CreateTypedStep(typeName, name, config)
	default:
		return nil, fmt.Errorf("unknown typed step type %q", typeName)
	}
}

func (p *wsAuthPlugin) ContractRegistry() *pb.ContractRegistry {
	return wsAuthContractRegistry
}

var wsAuthModuleTypes = []string{"ws_auth.hmac"}

var wsAuthStepTypes = []string{"step.ws_auth_identity"}

var wsAuthContractRegistry = &pb.ContractRegistry{
	FileDescriptorSet: &descriptorpb.FileDescriptorSet{
		File: []*descriptorpb.FileDescriptorProto{
			protodesc.ToFileDescriptorProto(contracts.File_internal_contracts_ws_auth_proto),
		},
	},
	Contracts: []*pb.ContractDescriptor{
		moduleContract("ws_auth.hmac", "HMACAuthConfig"),
		stepContract("step.ws_auth_identity", "AuthIdentityConfig", "AuthIdentityInput", "AuthIdentityOutput"),
	},
}

func moduleContract(moduleType, configMessage string) *pb.ContractDescriptor {
	const pkg = "workflow.plugins.ws_auth.v1."
	return &pb.ContractDescriptor{
		Kind:          pb.ContractKind_CONTRACT_KIND_MODULE,
		ModuleType:    moduleType,
		ConfigMessage: pkg + configMessage,
		Mode:          pb.ContractMode_CONTRACT_MODE_STRICT_PROTO,
	}
}

func stepContract(stepType, configMessage, inputMessage, outputMessage string) *pb.ContractDescriptor {
	const pkg = "workflow.plugins.ws_auth.v1."
	return &pb.ContractDescriptor{
		Kind:          pb.ContractKind_CONTRACT_KIND_STEP,
		StepType:      stepType,
		ConfigMessage: pkg + configMessage,
		InputMessage:  pkg + inputMessage,
		OutputMessage: pkg + outputMessage,
		Mode:          pb.ContractMode_CONTRACT_MODE_STRICT_PROTO,
	}
}
