package server

import (
	"github.com/consensys/gnark/frontend"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

const testExtension common.CircuitType = "test-extension"

var validExtensionPayload = []byte(`{"circuitType":"test-extension","x":3}`)

type extensionCircuit struct {
	X frontend.Variable `gnark:",public"`
}

func (c *extensionCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, c.X)
	return nil
}

type extensionRequest struct {
	X int `json:"x"`
}

func (r *extensionRequest) Assignment() (frontend.Circuit, error) {
	return &extensionCircuit{X: r.X}, nil
}

func init() {
	common.RegisterExtension(common.ExtensionCircuit{
		Type:    testExtension,
		KeyFile: "test_extension.key",
		Circuit: func() frontend.Circuit { return new(extensionCircuit) },
		Request: func() common.ExtensionRequest { return new(extensionRequest) },
	})
}
