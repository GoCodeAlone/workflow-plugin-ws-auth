package main

import (
	"github.com/GoCodeAlone/workflow-plugin-ws-auth/internal"
	"github.com/GoCodeAlone/workflow/plugin/external/sdk"
)

func main() {
	sdk.Serve(internal.NewWSAuthPlugin(), sdk.WithBuildVersion(sdk.ResolveBuildVersion(internal.Version)))
}
