package shared_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	customring "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/custom"
	. "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/protocol"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// structuralRail projects one mutation corpus onto every transfer wrapper.
// Mutations rebuild commitments and the outer statement, and anonymous spends
// are signed again. Rejection therefore exercises the intended relation rather
// than a stale hash or signature. Each rail is compiled once for the corpus.
type structuralRail struct {
	name      string
	new       func(testing.TB) *testAssignment
	statement func(testing.TB, *testAssignment) frontend.Circuit
	ccs       constraint.ConstraintSystem
	anonymous bool
	authority bool
}

func structuralRails(t testing.TB) []structuralRail {
	t.Helper()
	shape := protocol.Shape{NInputs: 2, NOutputs: 2}
	owner := hiddenOwnerKey(0x91)
	key := publicKeyBytes(owner)
	rails := []structuralRail{
		{name: "default", new: func(t testing.TB) *testAssignment {
			return buildDefaultRingConfidentialEddsaAssignment(t, shape)
		}, statement: func(t testing.TB, a *testAssignment) frontend.Circuit {
			refreshDefaultRingPublicInputHash(t, a)
			return asDefaultRingConfidentialEddsa(a)
		}},
		{name: "custom", new: func(t testing.TB) *testAssignment {
			return buildCircuitAssignment(t, shape)
		}, statement: func(t testing.TB, a *testAssignment) frontend.Circuit {
			refreshPublicInputHash(t, a)
			return asCustomRingConfidentialEddsa(a)
		}},
		{name: "anonymous", anonymous: true, new: func(t testing.TB) *testAssignment {
			return eddsaRingAssignment(t, shape, hiddenOwnerIdentity(t, key))
		}, statement: func(t testing.TB, a *testAssignment) frontend.Circuit {
			return asCustomRingAnonymousEddsa(a, authorizeEddsaKey(t, a, key, owner))
		}},
		{name: "authority", authority: true, new: func(t testing.TB) *testAssignment {
			return buildRingAuthorityAssignment(t, shape)
		}, statement: func(t testing.TB, a *testAssignment) frontend.Circuit {
			refreshRingAuthorityPublicInputHash(t, a)
			return asCustomRingAuthority(a)
		}},
	}
	for i := range rails {
		rail := &rails[i]
		if rail.anonymous {
			rail.ccs = compileEddsaRing(t, shape)
			continue
		}
		var c frontend.Circuit
		switch rail.name {
		case "default":
			c = MustNewDefaultRingConfidentialEddsaCircuit(Shape(shape))
		case "custom":
			c = MustNewCustomRingConfidentialEddsaCircuit(Shape(shape))
		case "authority":
			c = MustNewCustomRingAuthorityCircuit(Shape(shape))
		}
		var err error
		rail.ccs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c, frontend.WithCompressThreshold(300))
		if err != nil {
			t.Fatal(err)
		}
	}
	return rails
}

func (r structuralRail) check(t testing.TB, a *testAssignment, valid bool) {
	t.Helper()
	checkCachedWitness(t, r.ccs, r.statement(t, a), valid)
}

func TestTransferStructuralInvariantsAcrossRails(t *testing.T) {
	for _, rail := range structuralRails(t) {
		t.Run(rail.name, func(t *testing.T) {
			t.Run("honest", func(t *testing.T) { rail.check(t, rail.new(t), true) })
			mutations := []struct {
				name    string
				rebuild bool
				mutate  func(*testAssignment)
			}{
				{"unbalanced_output", true, func(a *testAssignment) {
					a.Outputs[0].Utxo.Amount = new(big.Int).Add(spptest.AsBigInt(a.Outputs[0].Utxo.Amount), big.NewInt(1))
				}},
				{"inactive_public_asset", false, func(a *testAssignment) { a.PublicAssets[0] = protocol.SolAsset() }},
				{"duplicate_public_assets_cancel", false, func(a *testAssignment) {
					a.PublicAssets[0], a.PublicAssets[1] = protocol.SolAsset(), protocol.SolAsset()
					a.PublicAmounts[0], a.PublicAmounts[1] = 1, protocol.SignedToField(big.NewInt(-1))
				}},
				{"input_flags_overflow", false, func(a *testAssignment) {
					a.InputFlags = new(big.Int).Add(spptest.AsBigInt(a.InputFlags), new(big.Int).Lsh(big.NewInt(1), uint(1+TreeIndexBits*len(a.Inputs))))
				}},
				{"tree_slot_out_of_range", false, func(a *testAssignment) {
					a.Inputs[1].TreeSlot = InputTrees
					// The packed 3-bit index can represent 5, but there are only
					// five tree slots. Keep the packed and private indices equal.
					a.InputFlags = 1 + (InputTrees << (1 + TreeIndexBits))
				}},
				{"selected_tree_root_zero", false, func(a *testAssignment) { a.TreeSlots[0].UtxoRoot = 0 }},
				{"real_input_compact_nullifier", false, func(a *testAssignment) { a.Inputs[1].Nullifier = 0 }},
				{"real_output_compact_hash", false, func(a *testAssignment) { a.Outputs[1].Hash = 0 }},
				{"output_amount_over_u64", true, func(a *testAssignment) {
					amount := new(big.Int).Lsh(big.NewInt(1), AmountBits)
					a.Outputs[0].Utxo.Amount = amount
					a.PublicAssets[0] = a.Outputs[0].Utxo.Asset
					a.PublicAmounts[0] = new(big.Int).Sub(new(big.Int).Add(amount, spptest.AsBigInt(a.Outputs[1].Utxo.Amount)), structuralInputSum(a))
				}},
				{"input_amount_over_u64", true, func(a *testAssignment) {
					limit := new(big.Int).Lsh(big.NewInt(1), AmountBits)
					a.Inputs[0].Utxo.Amount = limit
					a.Outputs[0].Utxo.Amount = new(big.Int).Sub(limit, big.NewInt(1))
					a.Outputs[1].Utxo.Amount = new(big.Int).Add(spptest.AsBigInt(a.Inputs[1].Utxo.Amount), big.NewInt(1))
				}},
				{"public_deposit_over_u64", true, func(a *testAssignment) {
					limit := new(big.Int).Lsh(big.NewInt(1), AmountBits)
					a.Outputs[0].Utxo.Amount = new(big.Int).Sub(limit, big.NewInt(1))
					a.Outputs[1].Utxo.Amount = new(big.Int).Add(structuralInputSum(a), big.NewInt(1))
					a.PublicAssets[0], a.PublicAmounts[0] = a.Outputs[0].Utxo.Asset, limit
				}},
				{"public_withdrawal_over_u64", true, func(a *testAssignment) {
					half := new(big.Int).Lsh(big.NewInt(1), AmountBits-1)
					a.Inputs[0].Utxo.Amount, a.Inputs[1].Utxo.Amount = half, half
					a.Outputs[0].Utxo.Amount, a.Outputs[1].Utxo.Amount = 0, 0
					a.PublicAssets[0] = a.Inputs[0].Utxo.Asset
					a.PublicAmounts[0] = protocol.SignedToField(new(big.Int).Neg(new(big.Int).Lsh(big.NewInt(1), AmountBits)))
				}},
			}
			for _, mutation := range mutations {
				t.Run(mutation.name, func(t *testing.T) {
					a := rail.new(t)
					mutation.mutate(a)
					if mutation.rebuild {
						rebuildAfterOwnerChange(t, a)
					}
					rail.check(t, a, false)
				})
			}
			t.Run("tree_slot_flags_bind_same_roots", func(t *testing.T) {
				a := rail.new(t)
				// Both slots carry the same tree, so only the packed selector can
				// distinguish the private slot from the published instruction.
				a.TreeSlots[1] = a.TreeSlots[0]
				a.Inputs[0].TreeSlot = 1
				a.InputFlags = testInputFlags(t, true, []*big.Int{big.NewInt(1), big.NewInt(0)})
				rail.check(t, a, true)
				a.InputFlags = testInputFlags(t, true, []*big.Int{big.NewInt(0), big.NewInt(0)})
				rail.check(t, a, false)
			})
			t.Run("data_output_requires_authorized_owner", func(t *testing.T) {
				a := rail.new(t)
				a.Outputs[0].Utxo.DataHash = 7
				a.Outputs[0].Utxo.Owner = a.Inputs[0].Utxo.Owner
				a.Outputs[0].NullifierPk = spptest.MustNullifierPk(t, spptest.AsBigInt(a.Inputs[0].NullifierSecret))
				a.Outputs[0].OwnerPkHash = a.Inputs[0].OwnerPkHash
				if rail.anonymous {
					a.Outputs[0].OwnerPkHash = hiddenOwnerIdentity(t, publicKeyBytes(hiddenOwnerKey(0x91)))
				}
				rebuildAfterOwnerChange(t, a)
				rail.check(t, a, true)
				outsider := testSolanaPkFieldSeed(t, 0x19)
				a.Outputs[0].OwnerPkHash = outsider
				a.Outputs[0].Utxo.Owner = spptest.MustOwnerHash(t, outsider, spptest.AsBigInt(a.Outputs[0].NullifierPk))
				rebuildAfterOwnerChange(t, a)
				rail.check(t, a, false)
			})
			t.Run("compact_input_canonical_fields", func(t *testing.T) {
				a := rail.new(t)
				a.Inputs[1].Utxo.RingProgramID, a.Inputs[1].Utxo.RingDataHash, a.Inputs[1].Utxo.DataHash = 0, 0, 0
				padWithCompactInputs(t, a)
				rail.check(t, a, true)
				a.Inputs[1].Utxo.Owner = 1
				rail.check(t, a, false)
			})
			t.Run("compact_output_canonical_fields", func(t *testing.T) {
				a := rail.new(t)
				structuralCompactOutput(t, a)
				rail.check(t, a, true)
				a.Outputs[1].Utxo.RingDataHash = 1
				rail.check(t, a, false)
			})
			t.Run("nonhidden_input_requires_public_owner", func(t *testing.T) {
				a := rail.new(t)
				if rail.anonymous {
					identity := testSolanaPkField(t)
					a.Inputs[1].OwnerPkHash = identity
					a.Inputs[1].Utxo.Owner = spptest.MustOwnerHash(t, identity, spptest.MustNullifierPk(t, spptest.AsBigInt(a.Inputs[1].NullifierSecret)))
					a.Inputs[1].Utxo.RingProgramID = 0
					a.SignerPkHashes[1] = identity
					rebuildAfterOwnerChange(t, a)
				}
				rail.check(t, a, true)
				for i := range a.SignerPkHashes {
					a.SignerPkHashes[i] = 0
				}
				// Authority is deliberately authorized by the invoking program,
				// not the public owner vector. Its data-output rule still applies.
				rail.check(t, a, rail.authority)
			})
			if rail.anonymous {
				t.Run("message_hash_limb_canonicality", func(t *testing.T) {
					for _, high := range []bool{false, true} {
						a := rail.new(t)
						c := rail.statement(t, a).(*customring.CustomRingAnonymousEddsaCircuit)
						limb := &c.Public.MessageHashLow
						if high {
							limb = &c.Public.MessageHashHigh
						}
						// Retain the signed low 128 bits while supplying an alias.
						*limb = new(big.Int).Add(spptest.AsBigInt(*limb), new(big.Int).Lsh(big.NewInt(1), 128))
						checkCachedWitness(t, rail.ccs, c, false)
					}
				})
			}
		})
	}
}

func structuralInputSum(a *testAssignment) *big.Int {
	sum := new(big.Int)
	for _, input := range a.Inputs {
		sum.Add(sum, spptest.AsBigInt(input.Utxo.Amount))
	}
	return sum
}

func structuralCompactOutput(t testing.TB, a *testAssignment) {
	t.Helper()
	a.Outputs[0].Utxo.Amount = new(big.Int).Add(spptest.AsBigInt(a.Outputs[0].Utxo.Amount), spptest.AsBigInt(a.Outputs[1].Utxo.Amount))
	blinding := a.Outputs[1].Utxo.Blinding
	a.Outputs[1] = testOutput{Utxo: fieldsFromUtxo(emptyOutputUtxo()), Hash: 0, OwnerPkHash: 0, NullifierPk: 0}
	a.Outputs[1].Utxo.Blinding = blinding
	a.Outputs[0].Hash = testUtxoHash(t, circuitFieldsToUtxo(a.Outputs[0].Utxo), a.OutputTreeID)
	inputs := make([]*big.Int, len(a.Inputs))
	for i := range inputs {
		inputs[i] = inputHash(t, a, i)
	}
	a.PrivateTxHash = spptest.MustPrivateTxHash(t, inputs, spptest.ToBigInts(a.OutputHashes()), noAddressNullifiers(len(inputs)), a.privateTxBlinding(t))
}
