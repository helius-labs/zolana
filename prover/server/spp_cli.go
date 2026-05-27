package main

import (
	"light/light-prover/prover/spp"
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
			},
			Action: func(context *cli.Context) error {
				shape, err := spp.NewShape(context.Int("inputs"), context.Int("outputs"))
				if err != nil {
					return err
				}
				system, err := spp.Setup(shape)
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
				return spp.WriteProofSystem(system, context.String("output"), context.String("output-vkey"))
			},
		},
		{
			Name: "export-vk",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "keys-file", Usage: "SPP proving system file", Required: true},
				&cli.StringFlag{Name: "output", Usage: "text verifying key output", Required: true},
			},
			Action: func(context *cli.Context) error {
				system, err := spp.ReadProofSystem(context.String("keys-file"))
				if err != nil {
					return err
				}
				if err := os.MkdirAll(filepath.Dir(context.String("output")), 0755); err != nil {
					return err
				}
				return spp.WriteVerifyingKeyText(system.VerifyingKey, context.String("output"))
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
				system, err := spp.ReadProofSystem(context.String("keys-file"))
				if err != nil {
					return err
				}
				if err := os.MkdirAll(filepath.Dir(context.String("output")), 0755); err != nil {
					return err
				}
				return spp.WriteProofBundle(system, context.String("input"), context.String("output"))
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
