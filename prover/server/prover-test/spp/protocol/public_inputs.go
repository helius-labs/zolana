package protocol

import (
	"fmt"
	"math/big"
)

// NPublicSlots mirrors the circuit constant of the same name.
const NPublicSlots = 3

var publicInputNames = [...]string{
	"nullifiers",
	"output_utxo_hashes",
	"utxo_tree_roots",
	"nullifier_tree_roots",
	"private_tx_hash",
	"p256_message_hash",
	"external_data_hash",
	"public_asset_0",
	"public_amount_0",
	"public_asset_1",
	"public_amount_1",
	"public_asset_2",
	"public_amount_2",
	"zone_program_id",
	"payer_pubkey_hash",
	"input_owner_pk_hashes",
}

// PublicInputNames returns the PublicInputHash preimage order.
func PublicInputNames() []string {
	out := make([]string, len(publicInputNames))
	copy(out, publicInputNames[:])
	return out
}

type PublicInputs struct {
	Nullifiers         []*big.Int
	OutputUtxoHashes   []*big.Int
	UtxoTreeRoots      []*big.Int
	NullifierTreeRoots []*big.Int
	PrivateTxHash      *big.Int
	P256MessageHash    *big.Int
	ExternalDataHash   *big.Int
	PublicAssets       [NPublicSlots]*big.Int
	PublicAmounts      [NPublicSlots]*big.Int
	ZoneProgramID      *big.Int
	PayerPubkeyHash    *big.Int
	InputOwnerPkHashes []*big.Int

	// Confidential appends the output owner tag chain and the shared P256 signing
	// key's pk_field to the preimage (see spec circuit-variants).
	Confidential        bool
	OutputOwnerPkHashes []*big.Int
	P256SigningPkField  *big.Int

	// ZoneAuthority omits the input owner pk_field chain from the preimage: the
	// zone-authority variant keeps input owners private (anonymous) since the zone
	// authority controls the UTXOs and no signer check needs them on-chain.
	ZoneAuthority bool
}

func PublicInputHash(inputs PublicInputs) (*big.Int, error) {
	nullifierChain, err := HashChain(inputs.Nullifiers)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash nullifier chain: %w", err)
	}
	outputChain, err := HashChain(inputs.OutputUtxoHashes)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash output chain: %w", err)
	}
	utxoRootChain, err := HashChain(inputs.UtxoTreeRoots)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash UTXO root chain: %w", err)
	}
	nullifierTreeRootChain, err := HashChain(inputs.NullifierTreeRoots)
	if err != nil {
		return nil, fmt.Errorf("spp: public input hash nullifier root chain: %w", err)
	}
	fields := []*big.Int{
		nullifierChain,
		outputChain,
		utxoRootChain,
		nullifierTreeRootChain,
		inputs.PrivateTxHash,
		inputs.ExternalDataHash,
	}
	for i := 0; i < NPublicSlots; i++ {
		fields = append(fields, inputs.PublicAssets[i], inputs.PublicAmounts[i])
	}
	// Everything from here on is variant-dependent, so the preimage keeps it at
	// the end: the P256 message every variant carries (the constant Poseidon(0, 0)
	// on the Solana-only rails), then the owner tags each variant publishes.
	fields = append(fields,
		inputs.ZoneProgramID,
		inputs.PayerPubkeyHash,
		inputs.P256MessageHash,
	)
	// The zone-authority variant keeps input owner pk_fields private; every other
	// variant commits them so SPP can route the per-input signer check.
	if !inputs.ZoneAuthority {
		solanaOwnerChain, err := HashChain(inputs.InputOwnerPkHashes)
		if err != nil {
			return nil, fmt.Errorf("spp: public input hash solana owner chain: %w", err)
		}
		fields = append(fields, solanaOwnerChain)
	}
	if inputs.Confidential {
		outputOwnerChain, err := HashChain(inputs.OutputOwnerPkHashes)
		if err != nil {
			return nil, fmt.Errorf("spp: public input hash output owner chain: %w", err)
		}
		fields = append(fields, outputOwnerChain, inputs.P256SigningPkField)
	}
	return HashChain(fields)
}
