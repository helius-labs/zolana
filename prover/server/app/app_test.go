package app

import (
	"strconv"
	"strings"
	"testing"

	"github.com/consensys/gnark/frontend"
	txcircuit "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover/common"
	"github.com/helius-labs/zolana/prover/server/server"
)

const appTestExtension common.CircuitType = "app-test-extension"

type appTestCircuit struct {
	X frontend.Variable `gnark:",public"`
}

func (c *appTestCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, c.X)
	return nil
}

type appTestRequest struct{}

func (appTestRequest) Assignment() (frontend.Circuit, error) {
	return new(appTestCircuit), nil
}

func init() {
	common.RegisterExtension(common.ExtensionCircuit{
		Type:    appTestExtension,
		KeyFile: "app_test_extension.key",
		Circuit: func() frontend.Circuit { return new(appTestCircuit) },
		Request: func() common.ExtensionRequest { return appTestRequest{} },
	})
}

func TestTransferSetupInputCount(t *testing.T) {
	for _, value := range []uint{1, 2, 3, 4, 5, 51, 60} {
		t.Run(strconv.FormatUint(uint64(value), 10), func(t *testing.T) {
			got, err := transferSetupInputCount(value)
			if err != nil || uint(got) != value {
				t.Fatalf("input count changed or rejected: got %d, err %v", got, err)
			}
			if (txcircuit.Shape{NInputs: int(got), NOutputs: 1}).SignerWidth() < 1 {
				t.Fatal("accepted count leaves no owner signer slot")
			}
		})
	}

	invalid := []uint{0, 61, 62, ^uint(0)}
	// On a 64-bit host, this used to truncate to one input before validation.
	wrapped := uint64(1)<<32 + 1
	if uint64(^uint(0)) >= wrapped {
		invalid = append(invalid, uint(wrapped))
	}
	for _, value := range invalid {
		t.Run(strconv.FormatUint(uint64(value), 10), func(t *testing.T) {
			got, err := transferSetupInputCount(value)
			if err == nil || got != 0 {
				t.Fatalf("invalid count accepted: got %d, err %v", got, err)
			}
		})
	}
}

func TestRedactedURLHidesThePassword(t *testing.T) {
	if got := redactedURL("redis://user:secret@redis.test:6379/0"); strings.Contains(got, "secret") || !strings.Contains(got, "redis.test") {
		t.Fatalf("redacted URL %q", got)
	}
}

func TestExtensionWorkerStartsWhenTheServerServesAnExtensionKey(t *testing.T) {
	for _, tc := range []struct {
		name         string
		circuits     []string
		serve        []string
		enableServer bool
		want         bool
	}{
		{name: "server serving every key", circuits: []string{"transfer"}, enableServer: true, want: true},
		{name: "server serving the extension key", circuits: []string{"transfer"}, serve: []string{"app_test_extension"}, enableServer: true, want: true},
		{name: "server serving no extension key", circuits: []string{"transfer"}, serve: []string{"transfer_*"}, enableServer: true, want: false},
		{name: "queue only without the extension circuit", circuits: []string{"transfer"}, want: false},
		{name: "queue only with the extension circuit", circuits: []string{string(appTestExtension)}, want: true},
		{name: "queue only with every circuit", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			served, err := server.ParseServedKeys(tc.serve)
			if err != nil {
				t.Fatal(err)
			}
			if got := startsExtensionWorker(tc.circuits, tc.enableServer, served); got != tc.want {
				t.Fatalf("extension worker started %v, want %v", got, tc.want)
			}
		})
	}
}
