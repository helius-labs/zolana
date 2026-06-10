//go:build spp_e2e_fixtures

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"light/light-prover/prover/spp"
	"os"
	"path/filepath"

	"github.com/urfave/cli/v2"
)

func sppFixtureCommands() []*cli.Command {
	return []*cli.Command{
		{
			Name:  "e2e-proof-bundle",
			Usage: "generate an SPP E2E proof bundle for program tests",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "keys-file", Usage: "SPP proving system file", Required: true},
				&cli.StringFlag{Name: "output", Usage: "proof-bundle JSON output", Required: true},
				&cli.StringFlag{Name: "solana-signer-seed-hex", Usage: "32-byte ed25519 seed for the real Solana signer used by the test transaction", Required: true},
				&cli.StringFlag{Name: "public-spl-asset-pubkey", Usage: "32-byte public SPL mint pubkey", Required: true},
				&cli.StringFlag{Name: "user-sol-account-hex", Usage: "32-byte SOL recipient/account pubkey for public SOL settlement"},
				&cli.StringFlag{Name: "user-spl-token-account-hex", Usage: "32-byte SPL token account pubkey created by the test", Required: true},
				&cli.StringFlag{Name: "spl-token-interface-hex", Usage: "32-byte SPL vault/interface pubkey created by the test", Required: true},
			},
			Action: func(context *cli.Context) error {
				seed, err := hex.DecodeString(context.String("solana-signer-seed-hex"))
				if err != nil {
					return fmt.Errorf("decode Solana signer seed: %w", err)
				}
				if len(seed) != ed25519.SeedSize {
					return fmt.Errorf("Solana signer seed must be %d bytes", ed25519.SeedSize)
				}
				privateKey := ed25519.NewKeyFromSeed(seed)
				var pubkey [32]byte
				copy(pubkey[:], privateKey[32:])
				userSolAccount, err := optionalHex32(context.String("user-sol-account-hex"))
				if err != nil {
					return fmt.Errorf("decode user SOL account: %w", err)
				}
				userSplToken, err := requiredHex32(context.String("user-spl-token-account-hex"), "user SPL token account")
				if err != nil {
					return err
				}
				splTokenInterface, err := requiredHex32(context.String("spl-token-interface-hex"), "SPL token interface")
				if err != nil {
					return err
				}
				publicSplAssetPubkey, err := requiredHex32(context.String("public-spl-asset-pubkey"), "public SPL asset pubkey")
				if err != nil {
					return err
				}

				if err := os.MkdirAll(filepath.Dir(context.String("output")), 0755); err != nil {
					return err
				}
				options := spp.E2EFixtureOptions{
					SolanaSignerPubkey:   pubkey,
					PublicSplAssetPubkey: publicSplAssetPubkey,
					UserSolAccount:       userSolAccount,
					UserSplToken:         userSplToken,
					SplTokenInterface:    splTokenInterface,
				}
				if err := spp.WriteE2EFixturesFromKeysFile(context.String("keys-file"), context.String("output"), options); err != nil {
					return err
				}
				fmt.Printf("wrote %s\n", context.String("output"))
				return nil
			},
		},
		{
			Name:  "batch-update-fixture",
			Usage: "generate the forester batch-update (address-append) e2e fixture",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "proving-key", Usage: "Light batch_address-append_40_10.key path", Required: true},
				&cli.StringFlag{Name: "output", Usage: "batch-update fixture JSON output", Required: true},
			},
			Action: func(context *cli.Context) error {
				if err := spp.WriteBatchUpdateFixture(context.String("proving-key"), context.String("output")); err != nil {
					return err
				}
				fmt.Printf("wrote %s\n", context.String("output"))
				return nil
			},
		},
	}
}

func requiredHex32(value string, name string) ([32]byte, error) {
	out, err := optionalHex32(value)
	if err != nil {
		return [32]byte{}, fmt.Errorf("decode %s: %w", name, err)
	}
	if out == [32]byte{} {
		return [32]byte{}, fmt.Errorf("%s must be non-zero", name)
	}
	return out, nil
}

func optionalHex32(value string) ([32]byte, error) {
	var out [32]byte
	if value == "" {
		return out, nil
	}
	bytes, err := hex.DecodeString(value)
	if err != nil {
		return out, err
	}
	if len(bytes) != len(out) {
		return out, fmt.Errorf("expected %d bytes, got %d", len(out), len(bytes))
	}
	copy(out[:], bytes)
	return out, nil
}
