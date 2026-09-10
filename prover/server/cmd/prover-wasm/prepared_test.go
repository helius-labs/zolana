package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/backend/groth16"
	native "github.com/consensys/gnark/backend/groth16/bn254"
	cs "github.com/consensys/gnark/constraint/bn254"
	"math/big"
	"os"
	"testing"
	"zolana/prover/prover/common"
	transfer "zolana/prover/prover/transfer_eddsa_only"
)

// Exercise accelerated proof orchestration independently of the browser ABI.
// This reference uses gnark arithmetic; browser tests exercise the Rust kernel.
type referenceKernel struct {
	pk              *native.ProvingKey
	closed          int
	commitmentCalls int
	fail            bool
}

func (k *referenceKernel) close() { k.closed++ }
func (k *referenceKernel) parts(sa, sb, sk, a, b, c []fr.Element) (kernelParts, error) {
	var result kernelParts
	if k.fail {
		return result, errors.New("kernel failure")
	}
	domain := &k.pk.Domain
	pad := make([]fr.Element, int(domain.Cardinality)-len(a))
	a = append(a, pad...)
	b = append(b, pad...)
	c = append(c, pad...)
	for _, v := range [][]fr.Element{a, b, c} {
		domain.FFTInverse(v, fft.DIF)
		domain.FFT(v, fft.DIT, fft.OnCoset())
	}
	var den, one fr.Element
	one.SetOne()
	den.Exp(domain.FrMultiplicativeGen, big.NewInt(int64(domain.Cardinality))).Sub(&den, &one).Inverse(&den)
	for i := range a {
		a[i].Mul(&a[i], &b[i]).Sub(&a[i], &c[i]).Mul(&a[i], &den)
	}
	domain.FFTInverse(a, fft.DIF, fft.OnCoset())
	conf := ecc.MultiExpConfig{}
	if _, err := result.a.MultiExp(k.pk.G1.A, sa, conf); err != nil {
		return result, err
	}
	if _, err := result.b.MultiExp(k.pk.G1.B, sb, conf); err != nil {
		return result, err
	}
	if _, err := result.k.MultiExp(k.pk.G1.K, sk, conf); err != nil {
		return result, err
	}
	if _, err := result.z.MultiExp(k.pk.G1.Z, a[:len(a)-1], conf); err != nil {
		return result, err
	}
	if _, err := result.b2.MultiExp(k.pk.G2.B, sb, conf); err != nil {
		return result, err
	}
	return result, nil
}

func (k *referenceKernel) commitment(index int, knowledge bool, values []fr.Element) (curve.G1Affine, error) {
	k.commitmentCalls++
	if k.fail {
		return curve.G1Affine{}, errors.New("kernel failure")
	}
	if knowledge {
		return k.pk.CommitmentKeys[index].ProveKnowledge(values)
	}
	return k.pk.CommitmentKeys[index].Commit(values)
}

func TestZolanaMoproTransfer(t *testing.T) {
	key, err := os.ReadFile("../../../../poc/web/public/keys/transfer_confidential_2_3.key")
	if os.IsNotExist(err) {
		t.Skip("stage the local demo key and sample first")
	}
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile("../../../../poc/web/public/fixtures/transfer-2x3.json")
	if err != nil {
		t.Fatal(err)
	}
	var ps common.TransferProofSystem
	if _, err := ps.UnsafeReadFrom(bytes.NewReader(key)); err != nil {
		t.Fatal(err)
	}
	var params transfer.TransferParameters
	if err := json.Unmarshal(data, &params); err != nil {
		t.Fatal(err)
	}
	w, err := assignmentWitness(&params)
	if err != nil {
		t.Fatal(err)
	}
	public, err := w.Public()
	if err != nil {
		t.Fatal(err)
	}
	kernel := &referenceKernel{pk: ps.ProvingKey.(*native.ProvingKey)}
	c := &preparedCircuit{cs: ps.ConstraintSystem.(*cs.R1CS), pk: ps.ProvingKey, kernel: kernel}
	kernel.fail = true
	if _, err := c.prove(&params); err == nil {
		t.Fatal("kernel error was ignored")
	}
	kernel.fail = false
	proof, err := c.prove(&params)
	if err != nil {
		t.Fatal(err)
	}
	if err := groth16.Verify(proof.Proof, ps.VerifyingKey, public); err != nil {
		t.Fatal(err)
	}
	if report := os.Getenv("MOPRO_BROWSER_PROOFS"); report != "" {
		raw, err := os.ReadFile(report)
		if err != nil {
			t.Fatal(err)
		}
		var proofs []json.RawMessage
		if err := json.Unmarshal(raw, &proofs); err != nil {
			t.Fatal(err)
		}
		if len(proofs) == 0 {
			t.Fatal("no browser proofs")
		}
		for _, raw := range proofs {
			var p common.Proof
			if err := json.Unmarshal(raw, &p); err != nil {
				t.Fatal(err)
			}
			if err := groth16.Verify(p.Proof, ps.VerifyingKey, public); err != nil {
				t.Fatal(err)
			}
		}
	}
}
