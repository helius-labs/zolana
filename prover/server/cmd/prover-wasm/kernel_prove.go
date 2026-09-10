// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See LICENSE-APACHE.
// Adapted from gnark v0.14.0: solve and assemble as gnark does, delegating
// the quotient and five main MSMs to an optional browser arithmetic kernel.
package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/hash_to_field"
	"github.com/consensys/gnark/backend"
	native "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/constraint/solver"
	fcs "github.com/consensys/gnark/frontend/cs"
	"math/big"
)

type kernelParts struct {
	a, b, k, z curve.G1Affine
	b2         curve.G2Affine
}
type proofKernel interface {
	parts(sa, sb, sk, a, b, c []fr.Element) (kernelParts, error)
	commitment(index int, knowledge bool, values []fr.Element) (curve.G1Affine, error)
	close()
}
type witnessKernel interface {
	solveParts(witness []fr.Element) (kernelParts, bool, error)
}

func proveAccelerated(r1cs *cs.R1CS, pk *native.ProvingKey, kernel proofKernel, fullWitness witness.Witness, opts ...backend.ProverOption) (*native.Proof, error) {
	opt, err := backend.NewProverConfig(opts...)
	if err != nil {
		return nil, fmt.Errorf("new prover config: %w", err)
	}
	if opt.HashToFieldFn == nil {
		opt.HashToFieldFn = hash_to_field.New([]byte(constraint.CommitmentDst))
	}

	commitmentInfo := r1cs.CommitmentInfo.(constraint.Groth16Commitments)

	proof := &native.Proof{Commitments: make([]curve.G1Affine, len(commitmentInfo))}
	if fast, ok := kernel.(witnessKernel); ok && len(commitmentInfo) == 0 && len(opt.SolverOpts) == 0 {
		parts, used, err := fast.solveParts(fullWitness.Vector().(fr.Vector))
		if err != nil {
			return nil, fmt.Errorf("accelerated witness solving: %w", err)
		}
		if used {
			return assembleAcceleratedProof(pk, proof, parts)
		}
	}

	solverOpts := opt.SolverOpts[:len(opt.SolverOpts):len(opt.SolverOpts)]

	privateCommittedValues := make([][]fr.Element, len(commitmentInfo))

	// override hints
	bsb22ID := solver.GetHintID(fcs.Bsb22CommitmentComputePlaceholder)
	solverOpts = append(solverOpts, solver.OverrideHint(bsb22ID, func(_ *big.Int, in []*big.Int, out []*big.Int) error {
		i := int(in[0].Int64())
		in = in[1:]
		privateCommittedValues[i] = make([]fr.Element, len(commitmentInfo[i].PrivateCommitted))
		hashed := in[:len(commitmentInfo[i].PublicAndCommitmentCommitted)]
		committed := in[+len(hashed):]
		for j, inJ := range committed {
			privateCommittedValues[i][j].SetBigInt(inJ)
		}

		var err error
		if len(privateCommittedValues[i]) >= 256 {
			proof.Commitments[i], err = kernel.commitment(i, false, privateCommittedValues[i])
		} else {
			proof.Commitments[i], err = pk.CommitmentKeys[i].Commit(privateCommittedValues[i])
		}
		if err != nil {
			return err
		}

		opt.HashToFieldFn.Write(constraint.SerializeCommitment(proof.Commitments[i].Marshal(), hashed, (fr.Bits-1)/8+1))
		hashBts := opt.HashToFieldFn.Sum(nil)
		opt.HashToFieldFn.Reset()
		nbBuf := fr.Bytes
		if opt.HashToFieldFn.Size() < fr.Bytes {
			nbBuf = opt.HashToFieldFn.Size()
		}
		var res fr.Element
		res.SetBytes(hashBts[:nbBuf])
		res.BigInt(out[0])
		return nil
	}))

	_solution, err := r1cs.Solve(fullWitness, solverOpts...)
	if err != nil {
		return nil, err
	}

	solution := _solution.(*cs.R1CSSolution)
	wireValues := []fr.Element(solution.W)

	poks := make([]curve.G1Affine, len(pk.CommitmentKeys))

	for i := range pk.CommitmentKeys {
		var err error
		if len(privateCommittedValues[i]) >= 256 {
			poks[i], err = kernel.commitment(i, true, privateCommittedValues[i])
		} else {
			poks[i], err = pk.CommitmentKeys[i].ProveKnowledge(privateCommittedValues[i])
		}
		if err != nil {
			return nil, err
		}
	}
	// compute challenge for folding the PoKs from the commitments
	commitmentsSerialized := make([]byte, fr.Bytes*len(commitmentInfo))
	for i := range commitmentInfo {
		copy(commitmentsSerialized[fr.Bytes*i:], wireValues[commitmentInfo[i].CommitmentIndex].Marshal())
	}
	challenge, err := fr.Hash(commitmentsSerialized, []byte("G16-BSB22"), 1)
	if err != nil {
		return nil, err
	}
	if _, err = proof.CommitmentPok.Fold(poks, challenge[0], ecc.MultiExpConfig{NbTasks: 1}); err != nil {
		return nil, err
	}

	filter := func(in []fr.Element, infinity []bool) []fr.Element {
		out := make([]fr.Element, 0, len(in))
		for i, v := range in {
			if !infinity[i] {
				out = append(out, v)
			}
		}
		return out
	}
	removed := make(map[int]bool)
	for _, indices := range commitmentInfo.GetPrivateCommitted() {
		for _, i := range indices {
			removed[i] = true
		}
	}
	for _, i := range commitmentInfo.CommitmentIndexes() {
		removed[i] = true
	}
	sk := make([]fr.Element, 0, len(wireValues))
	for i := r1cs.GetNbPublicVariables(); i < len(wireValues); i++ {
		if !removed[i] {
			sk = append(sk, wireValues[i])
		}
	}
	parts, err := kernel.parts(filter(wireValues, pk.InfinityA), filter(wireValues, pk.InfinityB), sk, solution.A, solution.B, solution.C)
	if err != nil {
		return nil, fmt.Errorf("accelerated proof operations: %w", err)
	}
	return assembleAcceleratedProof(pk, proof, parts)
}

func assembleAcceleratedProof(pk *native.ProvingKey, proof *native.Proof, parts kernelParts) (*native.Proof, error) {
	a, b, k, z, b2 := parts.a, parts.b, parts.k, parts.z, parts.b2
	var r, s big.Int
	var rr, ss, kr fr.Element
	if _, err := rr.SetRandom(); err != nil {
		return nil, err
	}
	if _, err := ss.SetRandom(); err != nil {
		return nil, err
	}
	kr.Mul(&rr, &ss).Neg(&kr)
	rr.BigInt(&r)
	ss.BigInt(&s)
	deltas := curve.BatchScalarMultiplicationG1(&pk.G1.Delta, []fr.Element{rr, ss, kr})
	var ar, bs1, krs, extra, tmp curve.G1Jac
	ar.FromAffine(&a)
	ar.AddMixed(&pk.G1.Alpha)
	ar.AddMixed(&deltas[0])
	bs1.FromAffine(&b)
	bs1.AddMixed(&pk.G1.Beta)
	bs1.AddMixed(&deltas[1])
	krs.FromAffine(&k)
	extra.FromAffine(&z)
	krs.AddAssign(&extra)
	krs.AddMixed(&deltas[2])
	tmp.ScalarMultiplication(&ar, &s)
	krs.AddAssign(&tmp)
	tmp.ScalarMultiplication(&bs1, &r)
	krs.AddAssign(&tmp)
	var bs, deltaS curve.G2Jac
	bs.FromAffine(&b2)
	deltaS.FromAffine(&pk.G2.Delta)
	deltaS.ScalarMultiplication(&deltaS, &s)
	bs.AddAssign(&deltaS)
	bs.AddMixed(&pk.G2.Beta)
	proof.Ar.FromJacobian(&ar)
	proof.Krs.FromJacobian(&krs)
	proof.Bs.FromJacobian(&bs)
	return proof, nil
}
