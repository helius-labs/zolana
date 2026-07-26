import { sha256 } from "@noble/hashes/sha2.js";
import type { Address, Bytes16, Bytes31, Bytes32, Bytes33 } from "@zolana/interface";
import {
  NullifierKey,
  type P256PublicKey,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
} from "@zolana/keypair";
import {
  ProofInputUtxo,
  SOL_MINT,
  SppProofInputs,
  Utxo,
  deriveBlinding,
  prepareZoneAuthority,
  type ProofOutputUtxo,
} from "@zolana/transaction";
import { describe, expect, it } from "vitest";

import { createExternalData } from "../../../transaction/src/instructions/transact.js";
import { createProofOutput } from "../../../transaction/src/utxo.js";
import {
  bigintToBytes,
  bytesToBigInt,
  encodeBase58,
  hashChain,
  poseidon,
} from "../../src/internal.js";
import { proverRequest } from "../../src/prover/client.js";
import {
  assembleZone,
  assembleZoneAuthority,
  assembleZoneAuthorityWitness,
  assembleZoneP256,
} from "../../src/prover/zone.js";
import type { SpendProof } from "../../src/rpc.js";
import { bytes, hex } from "../helpers/prover-vectors.js";
import oracle from "../oracles/zone-v1.json" with { type: "json" };

/// Replays `sdk-libs/client/src/prover/ts_zone_oracle.rs` for rows C13, C14, and
/// C18. Every supported shape of every zone rail is compared as exact request
/// bytes, and the named intermediates are compared first so a failure reports
/// the element that diverged rather than only the final hash.

const ZONE = encodeBase58(bytes(oracle.inputs.zoneProgramIdBytes)) as Address;
const TREE = encodeBase58(bytes(oracle.inputs.treeBytes)) as Address;
const USER_SOL_ACCOUNT = encodeBase58(bytes(oracle.inputs.userSolAccountBytes)) as Address;
const AMOUNT = BigInt(oracle.inputs.inputAmount);

function fieldByte(value: number): Bytes32 {
  const result = new Uint8Array(32);
  result[31] = value;
  return result as Bytes32;
}

function keypair(p256: boolean): Readonly<{ keypair: ShieldedKeypair; signing: SigningKey }> {
  const signing = p256
    ? SigningKey.fromBytes(bytes(oracle.inputs.p256SecretBytes) as Bytes32)
    : SigningKey.fromEd25519Bytes(bytes(oracle.inputs.ed25519SecretBytes) as Bytes32);
  return {
    keypair: ShieldedKeypair.fromKeys(
      signing,
      NullifierKey.fromSigningKey(signing),
      ViewingKey.fromSeed(bytes(oracle.inputs.viewingSeedBytes) as Bytes32, p256 ? 1 : 0),
    ),
    signing,
  };
}

function seed(): Bytes31 {
  return bytes(oracle.inputs.blindingSeedBytes) as Bytes31;
}

/// Rust `SppProofInputs::new` derives the payer hash with `sha256_be`; the
/// oracle pins the address, so the digest is taken here the same way.
function payerHash(): Bytes32 {
  return bytes(oracle.expected.payerPubkeyHashBytes) as Bytes32;
}

function privateMessage(
  inputs: readonly ProofInputUtxo[],
  outputs: readonly ProofOutputUtxo[],
  externalDataHash: Bytes32,
): Bytes32 {
  const inputHashes = inputs.map((input) => (input.isDummy() ? 0n : bytesToBigInt(input.hash())));
  const outputHashes = outputs.map((output) =>
    output.isDummy() ? 0n : bytesToBigInt(output.hash()),
  );
  const privateHash = poseidon([
    hashChain(inputHashes),
    hashChain(outputHashes),
    hashChain(Array.from({ length: inputHashes.length }, () => 0n)),
    bytesToBigInt(externalDataHash),
  ]);
  return new Uint8Array(sha256(bigintToBytes(privateHash))) as Bytes32;
}

/// Mirrors `proof_inputs` in the Rust generator: real inputs in the leading
/// slots (two when the shape is wide enough, so the mirrored-dummy path appears
/// too), a single value-carrying anonymous zone output, and dummy outputs after
/// it. Every real UTXO carries the zone.
function buildInputs(
  p256: boolean,
  shape: Readonly<{ inputs: number; outputs: number }>,
): Readonly<{ proofInputs: SppProofInputs; spendProofs: readonly SpendProof[] }> {
  const { keypair: owner, signing } = keypair(p256);
  const real = shape.inputs >= 2 ? 2 : 1;
  const inputs: ProofInputUtxo[] = Array.from({ length: shape.inputs }, (_, index) =>
    index < real
      ? new ProofInputUtxo({
          utxo: new Utxo({
            owner: owner.signingPublicKey(),
            asset: SOL_MINT,
            amount: AMOUNT,
            blinding: deriveBlinding(seed(), index),
            zoneProgramId: ZONE,
          }),
          nullifierKey: NullifierKey.fromSigningKey(signing),
        })
      : ProofInputUtxo.dummy(deriveBlinding(seed(), index)),
  );
  const outputs = Array.from({ length: shape.outputs }, (_, index) =>
    createProofOutput({
      ownerTag: fieldByte(32 + index),
      asset: SOL_MINT,
      amount: index === 0 ? AMOUNT * BigInt(real) : 0n,
      blinding: deriveBlinding(seed(), 32 + index),
      zoneProgramId: ZONE,
    }),
  );
  const resolvedOwnerTags = outputs.map((output) => {
    if (output.ownerTag === undefined) throw new Error("zone output lacks owner tag");
    return output.ownerTag;
  });
  const externalData = createExternalData({
    instructionDiscriminator: 0,
    expiryUnixTs: 0xffff_ffff_ffff_ffffn,
    relayerFee: 0,
    publicSolAmount: -5n,
    userSolAccount: USER_SOL_ACCOUNT,
    userSplToken: SOL_MINT,
    splTokenInterface: SOL_MINT,
    txViewingPublicKey: {
      toBytes: () => new Uint8Array(33).fill(71) as Bytes33,
    } as P256PublicKey,
    salt: new Uint8Array(16).fill(72) as Bytes16,
    outputs: outputs.map((output, index) => ({
      utxoHash: output.hash(),
      ownerTag: { kind: "inline" as const, value: resolvedOwnerTags[index] as Bytes32 },
      data: Uint8Array.of(1, 2, 3),
    })),
    resolvedOwnerTags,
    messages: [],
  });
  const proofInputs = new SppProofInputs({
    payerPublicKeyHash: payerHash(),
    inputUtxos: inputs,
    outputs,
    externalData,
  });
  if (p256) {
    const signature = signing.sign(privateMessage(inputs, outputs, externalData.hash()));
    proofInputs.applyP256Signature({
      publicKey: signing.publicKey().p256(),
      r: signature.slice(0, 32) as Bytes32,
      s: signature.slice(32) as Bytes32,
    });
  }
  const spendProofs = proofInputs.inputUtxoHashes().map((context, index) => ({
    state: {
      leaf: context.utxoHash,
      merkleContext: { treeType: 1, tree: TREE },
      path: Array.from({ length: 32 }, () => fieldByte(73 + index)),
      leafIndex: BigInt(index),
      root: fieldByte(74 + index),
      rootSeq: 75n,
      rootIndex: 76 + index,
    },
    nullifier: {
      leaf: context.nullifier,
      merkleContext: { treeType: 2, tree: TREE },
      path: Array.from({ length: 40 }, () => fieldByte(77 + index)),
      lowElement: fieldByte(78),
      lowElementIndex: BigInt(index),
      highElement: fieldByte(79),
      highElementIndex: BigInt(index + 1),
      root: fieldByte(80 + index),
      rootSeq: 81n,
      rootIndex: 82 + index,
    },
  }));
  return { proofInputs, spendProofs };
}

interface Case {
  readonly shape: Readonly<{ inputs: number; outputs: number }>;
  readonly requestBodyJson: string;
  readonly publicInputHashBytes: string;
  readonly privateTxHashBytes: string;
  readonly nullifierBytes: readonly string[];
  readonly outputHashBytes: readonly string[];
  readonly inputRootIndices: readonly (readonly number[])[];
  readonly chain: Readonly<Record<string, unknown>>;
}

interface RejectionCase {
  readonly shape: Readonly<{ inputs: number; outputs: number }>;
  readonly errorCode: string;
  readonly details: Readonly<{ nIn: number; nOut: number }>;
}

const rails = [
  {
    name: "transfer-zone",
    p256: false,
    shapes: 10,
    cases: oracle.expected.transferZone as readonly Case[],
    assemble: (shape: Readonly<{ inputs: number; outputs: number }>) => {
      const { proofInputs, spendProofs } = buildInputs(false, shape);
      return assembleZone(proofInputs, spendProofs, ZONE);
    },
  },
  {
    name: "transfer-p256-zone",
    p256: true,
    shapes: 10,
    cases: oracle.expected.transferP256Zone as readonly Case[],
    assemble: (shape: Readonly<{ inputs: number; outputs: number }>) => {
      const { proofInputs, spendProofs } = buildInputs(true, shape);
      return assembleZoneP256(proofInputs, spendProofs, ZONE);
    },
  },
  {
    name: "transfer-zone-authority",
    p256: false,
    // The zone-authority rail has four verifying keys, not ten.
    shapes: 4,
    cases: oracle.expected.transferZoneAuthority as readonly Case[],
    assemble: (shape: Readonly<{ inputs: number; outputs: number }>) => {
      const { proofInputs, spendProofs } = buildInputs(false, shape);
      return assembleZoneAuthority(proofInputs, spendProofs, ZONE);
    },
  },
] as const;

describe("zone prover rails against the Rust oracle", () => {
  for (const rail of rails) {
    describe(rail.name, () => {
      it("covers every supported shape", () => {
        expect(rail.cases.length).toBe(rail.shapes);
      });

      for (const expected of rail.cases) {
        const label = `${String(expected.shape.inputs)}x${String(expected.shape.outputs)}`;
        it(`assembles ${label} as Rust does`, () => {
          const assembled = rail.assemble(expected.shape);
          const payload = assembled.proverInputs.payload;
          // Compare the chain elements before the final hash, so a failure
          // names the first field that moved.
          expect(payload.privateTxHash.toString()).toBe(expected.chain["privateTxHash"]);
          expect(payload.externalDataHash.toString()).toBe(expected.chain["externalDataHash"]);
          expect(payload.zoneProgramId.toString()).toBe(expected.chain["zoneProgramId"]);
          expect(payload.payerPublicKeyHash.toString()).toBe(expected.chain["payerPubkeyHash"]);
          expect(payload.publicSolAmount.toString()).toBe(expected.chain["publicSolAmount"]);
          expect(payload.publicSplAmount.toString()).toBe(expected.chain["publicSplAmount"]);
          expect(payload.publicSplAssetPublicKey.toString()).toBe(
            expected.chain["publicSplAssetPubkey"],
          );
          expect(payload.inputs.map((input) => input.ownerPublicKeyHash.toString())).toEqual(
            expected.chain["inputOwnerPkHashes"],
          );
          expect(hex(assembled.privateTxHash)).toBe(expected.privateTxHashBytes);
          expect(assembled.nullifiers.map(hex)).toEqual(expected.nullifierBytes);
          expect(assembled.outputHashes.map(hex)).toEqual(expected.outputHashBytes);
          expect(assembled.inputRootIndexes.map((pair) => [...pair])).toEqual(
            expected.inputRootIndices,
          );
          expect(hex(assembled.publicInputHash)).toBe(expected.publicInputHashBytes);
        });

        it(`sends the ${label} request body Rust serializes`, () => {
          const body = proverRequest(rail.assemble(expected.shape).proverInputs);
          const want = JSON.parse(expected.requestBodyJson) as Record<string, unknown>;
          expect(body).toEqual(want);
          expect(Object.keys(body)).toEqual(Object.keys(want));
        });
      }
    });
  }

  /// The zone-authority rail has four verifying keys and the specification
  /// lists four shapes, so a request in one of the six non-square shapes is
  /// unprovable. Rust generated these rejections rather than the test asserting
  /// them independently, so a TypeScript refusal that named a different shape
  /// or code would fail here.
  it("refuses the six zone-authority shapes no key can verify", () => {
    const rejected = oracle.expected.transferZoneAuthorityRejected as readonly RejectionCase[];
    expect(rejected.length).toBe(6);
    for (const expected of rejected) {
      const { proofInputs, spendProofs } = buildInputs(false, expected.shape);
      expect(() => assembleZoneAuthority(proofInputs, spendProofs, ZONE)).toThrow(
        expect.objectContaining({ code: expected.errorCode, details: expected.details }),
      );
      // The same shape stays provable on the zone transfer rail, which has all
      // ten keys, so the refusal is the rail's and not the shape resolver's.
      expect(() => assembleZone(proofInputs, spendProofs, ZONE)).not.toThrow();
    }
  });

  /// The zone field is the only value binding a proof to its zone, so a rail
  /// that dropped it would still produce a well-formed request.
  it("moves the public input when the zone changes and never carries the confidential zero", () => {
    const { proofInputs, spendProofs } = buildInputs(false, { inputs: 2, outputs: 2 });
    const other = encodeBase58(bytes(oracle.expected.otherZone.zoneProgramIdBytes)) as Address;
    const bound = assembleZone(proofInputs, spendProofs, ZONE);
    const rebound = assembleZone(proofInputs, spendProofs, other);
    expect(hex(rebound.publicInputHash)).toBe(oracle.expected.otherZone.publicInputHashBytes);
    expect(hex(rebound.publicInputHash)).not.toBe(hex(bound.publicInputHash));
    for (const rail of rails) {
      const request = proverRequest(rail.assemble({ inputs: 2, outputs: 2 }).proverInputs);
      expect(request["zoneProgramId"]).not.toBe("0x0");
    }
  });

  /// The P256 zone rail keeps owner identities private: the shared signing field
  /// rides in the witness, and each P256-owned input contributes the zero
  /// sentinel rather than its own field.
  it("keeps P256 owner identities out of the zone chain", () => {
    const expected = oracle.expected.transferP256Zone[2] as Case;
    const built = buildInputs(true, expected.shape);
    const assembled = assembleZoneP256(built.proofInputs, built.spendProofs, ZONE);
    expect(assembled.proverInputs.payload.inputs.map((input) => input.ownerPublicKeyHash)).toEqual(
      assembled.proverInputs.payload.inputs.map(() => 0n),
    );
    expect(assembled.p256SigningPublicKeyField.toString()).toBe(
      expected.chain["p256SigningPkField"],
    );
    // In the hash it would have been the fourteenth element; the zone rails stop
    // at thirteen, so its presence in the witness must not move the hash.
    expect(hex(assembled.publicInputHash)).toBe(expected.publicInputHashBytes);
  });

  /// The zone-authority rail names no owner at all: its preimage is the twelve
  /// base elements, so it must differ from the zone transfer built over the same
  /// inputs, which appends the owner chain.
  it("gives the zone authority a shorter chain than the zone transfer", () => {
    const shape = { inputs: 2, outputs: 2 } as const;
    const transfer = rails[0].assemble(shape);
    const authority = rails[2].assemble(shape);
    expect(hex(authority.publicInputHash)).not.toBe(hex(transfer.publicInputHash));
    expect(hex(authority.privateTxHash)).toBe(hex(transfer.privateTxHash));
  });

  /// Rust `ZoneAuthorityWitness`: a caller who prepared the transition in
  /// `@zolana/transaction` reaches the same proof the raw proof inputs give,
  /// against the same oracle-pinned hash. The prepared value pins the zone, so
  /// the bridge takes no zone argument and cannot bind the proof elsewhere.
  for (const expected of oracle.expected.transferZoneAuthority as readonly Case[]) {
    const label = `${String(expected.shape.inputs)}x${String(expected.shape.outputs)}`;
    it(`proves a prepared ${label} zone-authority transition`, () => {
      const { proofInputs, spendProofs } = buildInputs(false, expected.shape);
      const prepared = prepareZoneAuthority({
        inputs: proofInputs.inputUtxos,
        outputs: proofInputs.outputs,
        externalData: proofInputs.externalData,
        zoneProgramId: ZONE,
        payerPublicKeyHash: proofInputs.payerPublicKeyHash,
      });
      const assembled = assembleZoneAuthorityWitness(prepared, spendProofs);
      expect(hex(assembled.publicInputHash)).toBe(expected.publicInputHashBytes);
      expect(proverRequest(assembled.proverInputs)).toEqual(JSON.parse(expected.requestBodyJson));
    });
  }

  /// One `SpendProof` per real input, in input order: a short list is the same
  /// refusal at the same index Rust `attach_input_proofs` raises.
  it("refuses a prepared transition with a missing input proof", () => {
    const { proofInputs, spendProofs } = buildInputs(false, { inputs: 2, outputs: 2 });
    const prepared = prepareZoneAuthority({
      inputs: proofInputs.inputUtxos,
      outputs: proofInputs.outputs,
      externalData: proofInputs.externalData,
      zoneProgramId: ZONE,
      payerPublicKeyHash: proofInputs.payerPublicKeyHash,
    });
    expect(() => assembleZoneAuthorityWitness(prepared, spendProofs.slice(0, 1))).toThrow(
      expect.objectContaining({
        code: "CLIENT_MISSING_INPUT_MERKLE_PROOF",
        details: { index: 1 },
      }),
    );
  });
});
