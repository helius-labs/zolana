package main

import (
	"light/light-prover/prover/spp/protocol"
	txprover "light/light-prover/prover/spp/prover/transaction"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v2"
)

func sppCommand() *cli.Command {
	subcommands := []*cli.Command{
		{
			Name: "setup",
			Flags: []cli.Flag{
				&cli.IntFlag{Name: "inputs", Usage: "fixed input slots", Required: true},
				&cli.IntFlag{Name: "outputs", Usage: "fixed output slots", Required: true},
				&cli.StringFlag{Name: "output", Usage: "proving system output", Required: true},
				&cli.StringFlag{Name: "output-vkey", Usage: "text verifying key output", Required: false},
				&cli.BoolFlag{Name: "solana", Usage: "build the Solana-only circuit variant (no P256 ECDSA gadget, ~7x smaller); omit for the P256-capable circuit", Required: false},
			},
			Action: func(context *cli.Context) error {
				shape, err := protocol.NewShape(context.Int("inputs"), context.Int("outputs"))
				if err != nil {
					return err
				}
				requiresP256 := !context.Bool("solana")
				system, err := txprover.Setup(shape, requiresP256)
				if err != nil {
					return err
				}
				if err := os.MkdirAll(filepath.Dir(context.String("output")), 0755); err != nil {
					return err
				}
				if vkey := context.String("output-vkey"); vkey != "" {
					if err := os.MkdirAll(filepath.Dir(vkey), 0755); err != nil {
						return err
					}
				}
				return txprover.WriteProofSystem(system, context.String("output"), context.String("output-vkey"))
			},
		},
		{
			Name: "export-vk",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "keys-file", Usage: "SPP proving system file", Required: true},
				&cli.StringFlag{Name: "output", Usage: "text verifying key output", Required: true},
			},
			Action: func(context *cli.Context) error {
				system, err := txprover.ReadProofSystem(context.String("keys-file"))
				if err != nil {
					return err
				}
				if err := os.MkdirAll(filepath.Dir(context.String("output")), 0755); err != nil {
					return err
				}
				return txprover.WriteVerifyingKeyText(system.VerifyingKey, context.String("output"))
			},
		},
		{
			Name:  "prove-bundle",
			Usage: "prove an SPP transaction bundle from explicit witness JSON",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "keys-file", Usage: "SPP proving system file", Required: true},
				&cli.StringFlag{Name: "input", Usage: "proof request JSON input", Required: true},
				&cli.StringFlag{Name: "output", Usage: "proof bundle JSON output", Required: true},
			},
			Action: func(context *cli.Context) error {
				system, err := txprover.ReadProofSystem(context.String("keys-file"))
				if err != nil {
					return err
				}
				if err := os.MkdirAll(filepath.Dir(context.String("output")), 0755); err != nil {
					return err
				}
				return txprover.WriteProofBundle(system, context.String("input"), context.String("output"))
			},
		},
		{
			Name:  "signing-payload",
			Usage: "compute SPP private transaction hashes needed for external owner signatures",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "keys-file", Usage: "SPP proving system file", Required: true},
				&cli.StringFlag{Name: "input", Usage: "proof request JSON input", Required: true},
				&cli.StringFlag{Name: "output", Usage: "signing payload JSON output", Required: true},
			},
			Action: func(context *cli.Context) error {
				system, err := txprover.ReadProofSystem(context.String("keys-file"))
				if err != nil {
					return err
				}
				if err := os.MkdirAll(filepath.Dir(context.String("output")), 0755); err != nil {
					return err
				}
				return txprover.WriteProofSigningPayload(system, context.String("input"), context.String("output"))
			},
		},
	}
	subcommands = append(subcommands, sppFixtureCommands()...)
	return &cli.Command{
		Name:        "spp",
		Usage:       "SPP circuit setup and verifying-key export",
		Subcommands: subcommands,
	}
}
