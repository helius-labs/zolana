import type { Address, Bytes16, Bytes31, Bytes32, Bytes33 } from "@zolana/interface";
import {
  NullifierKey,
  type P256PublicKey,
  ShieldedKeypair,
  SigningKey,
  ViewingKey,
} from "@zolana/keypair";
import {
  MergeZone,
  PreparedMerge,
  PreparedMergeZone,
  SppProofInputUtxo,
  SOL_MINT,
  SppProofInputs,
  Utxo,
  deriveBlinding,
  type ProofOutputUtxo,
} from "@zolana/transaction";
import { sha256 } from "@noble/hashes/sha2.js";
import { describe, expect, it } from "vitest";

import { createExternalData } from "../../../transaction/src/instructions/transact.js";
import { createProofOutput } from "../../../transaction/src/utxo.js";
import { ClientError } from "../../src/error.js";
import {
  bigintToBytes,
  bytesToBigInt,
  encodeBase58,
  hashChain,
  poseidon,
} from "../../src/internal.js";
import { assembleMergeWithProofs, assembleMergeZoneWithProofs } from "../../src/prover/merge.js";
import { assembleZone, assembleZoneAuthority, assembleZoneP256 } from "../../src/prover/zone.js";
import type { SpendProof } from "../../src/rpc.js";
import { bytes } from "../helpers/prover-vectors.js";
import zoneOracle from "../oracles/zone-v1.json" with { type: "json" };
import mergeOracle from "../oracles/merge-v1.json" with { type: "json" };

/// Gate line: zone transfer, zone authority, and merge-zone have named positive
/// and rejection coverage. Positives live in the zone/merge oracles; this file
/// names each rejection rule the client enforces so a deleted check fails here
/// rather than silently becoming a later prove-time error.

const ZONE = encodeBase58(bytes(zoneOracle.inputs.zoneProgramIdBytes)) as Address;
const TREE = encodeBase58(bytes(zoneOracle.inputs.treeBytes)) as Address;
const USER_SOL_ACCOUNT = encodeBase58(bytes(zoneOracle.inputs.userSolAccountBytes)) as Address;
const AMOUNT = BigInt(zoneOracle.inputs.inputAmount);
const MERGE_TREE = mergeOracle.inputs.tree as Address;
const MERGE_ZONE = encodeBase58(bytes(mergeOracle.inputs.zoneProgramIdBytes)) as Address;

function fieldByte(value: number): Bytes32 {
  const result = new Uint8Array(32);
  result[31] = value;
  return result as Bytes32;
}

function expectCode(operation: () => unknown, code: string): void {
  try {
    operation();
  } catch (error) {
    expect(error).toBeInstanceOf(ClientError);
    expect((error as ClientError).code).toBe(code);
    return;
  }
  throw new Error(`expected ${code}`);
}

function keypair(p256: boolean): Readonly<{ keypair: ShieldedKeypair; signing: SigningKey }> {
  const signing = p256
    ? SigningKey.fromBytes(bytes(zoneOracle.inputs.p256SecretBytes) as Bytes32)
    : SigningKey.fromEd25519Bytes(bytes(zoneOracle.inputs.ed25519SecretBytes) as Bytes32);
  return {
    keypair: ShieldedKeypair.fromKeys(
      signing,
      NullifierKey.fromSigningKey(signing),
      ViewingKey.fromSeed(bytes(zoneOracle.inputs.viewingSeedBytes) as Bytes32, p256 ? 1 : 0),
    ),
    signing,
  };
}

function seed(): Bytes31 {
  return bytes(zoneOracle.inputs.blindingSeedBytes) as Bytes31;
}

function payerHash(): Bytes32 {
  return bytes(zoneOracle.expected.payerPubkeyHashBytes) as Bytes32;
}

function privateMessage(
  inputs: readonly SppProofInputUtxo[],
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

function spendProofs(proofInputs: SppProofInputs): readonly SpendProof[] {
  return proofInputs.inputUtxoHashes().map((context, index) => ({
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
}

function buildZone(
  p256: boolean,
  shape: Readonly<{ inputs: number; outputs: number }> = { inputs: 1, outputs: 1 },
): Readonly<{
  proofInputs: SppProofInputs;
  spendProofs: readonly SpendProof[];
  owner: ShieldedKeypair;
  signing: SigningKey;
}> {
  const { keypair: owner, signing } = keypair(p256);
  const inputs: SppProofInputUtxo[] = Array.from({ length: shape.inputs }, (_, index) =>
    index === 0
      ? new SppProofInputUtxo({
          utxo: new Utxo({
            owner: owner.signingPublicKey(),
            asset: SOL_MINT,
            amount: AMOUNT,
            blinding: deriveBlinding(seed(), index),
            zoneProgramId: ZONE,
          }),
          nullifierKey: NullifierKey.fromSigningKey(signing),
        })
      : SppProofInputUtxo.dummy(deriveBlinding(seed(), index)),
  );
  const outputs = Array.from({ length: shape.outputs }, (_, index) =>
    createProofOutput({
      ownerTag: fieldByte(32 + index),
      asset: SOL_MINT,
      amount: index === 0 ? AMOUNT : 0n,
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
  return { proofInputs, spendProofs: spendProofs(proofInputs), owner, signing };
}

describe("zone transfer named rejections", () => {
  /// The eddsa zone rail has no P256 gadget, so a P256-owned input cannot be
  /// authorized and must fail before a request is serialized.
  it("refuses a P256-owned input on the eddsa zone rail (CLIENT_EDDSA_INPUT_NOT_SOLANA_OWNED)", () => {
    // Rebuild without the P256 signature so the rail-mismatch check does not
    // fire first; the inputs remain P256-owned.
    const p256 = buildZone(true);
    const unsigned = new SppProofInputs({
      payerPublicKeyHash: p256.proofInputs.payerPublicKeyHash,
      inputUtxos: p256.proofInputs.inputUtxos,
      outputs: p256.proofInputs.outputs,
      externalData: p256.proofInputs.externalData,
    });
    expectCode(
      () => assembleZone(unsigned, p256.spendProofs, ZONE),
      "CLIENT_EDDSA_INPUT_NOT_SOLANA_OWNED",
    );
  });

  /// A P256 signature belongs to the P256 zone rail only. Attaching one to the
  /// eddsa assembler is a rail mismatch, not a shape or zone-binding failure.
  it("refuses a P256 signature on the eddsa zone rail (CLIENT_PROOF_RAIL_MISMATCH)", () => {
    const p256 = buildZone(true);
    expectCode(
      () => assembleZone(p256.proofInputs, p256.spendProofs, ZONE),
      "CLIENT_PROOF_RAIL_MISMATCH",
    );
  });

  /// The P256 zone rail requires the shared signature; without it the witness
  /// cannot bind the signing key and the request must not be built.
  it("refuses a P256 zone transfer without a signature (CLIENT_MISSING_P256_SIGNATURE)", () => {
    const p256 = buildZone(true);
    const unsigned = new SppProofInputs({
      payerPublicKeyHash: p256.proofInputs.payerPublicKeyHash,
      inputUtxos: p256.proofInputs.inputUtxos,
      outputs: p256.proofInputs.outputs,
      externalData: p256.proofInputs.externalData,
    });
    expectCode(
      () => assembleZoneP256(unsigned, p256.spendProofs, ZONE),
      "CLIENT_MISSING_P256_SIGNATURE",
    );
  });

  /// An all-dummy input list balances arithmetically but spends nothing, so the
  /// assembler refuses it rather than sending an empty nullifier set to the prover.
  it("refuses an all-dummy zone transfer (CLIENT_NO_INPUTS)", () => {
    const base = buildZone(false, { inputs: 2, outputs: 2 });
    const empty = new SppProofInputs({
      payerPublicKeyHash: base.proofInputs.payerPublicKeyHash,
      inputUtxos: [
        SppProofInputUtxo.dummy(deriveBlinding(seed(), 0)),
        SppProofInputUtxo.dummy(deriveBlinding(seed(), 1)),
      ],
      outputs: base.proofInputs.outputs,
      externalData: base.proofInputs.externalData,
    });
    expectCode(() => assembleZone(empty, [], ZONE), "CLIENT_NO_INPUTS");
  });
});

describe("zone authority named rejections", () => {
  /// Spec and verifying keys list four square shapes; the six non-square members
  /// of SPP_SUPPORTED_SHAPES are unprovable on this rail.
  it("refuses a non-square shape (CLIENT_UNSUPPORTED_ZONE_AUTHORITY_SHAPE)", () => {
    const { proofInputs, spendProofs } = buildZone(false, { inputs: 2, outputs: 3 });
    expect(() => assembleZoneAuthority(proofInputs, spendProofs, ZONE)).toThrow(
      expect.objectContaining({
        code: "CLIENT_UNSUPPORTED_ZONE_AUTHORITY_SHAPE",
        details: { nIn: 2, nOut: 3 },
      }),
    );
  });

  /// A P256 signature names a different ownership rail; the authority path has
  /// no owner signature at all.
  it("refuses a P256 signature on the authority rail (CLIENT_PROOF_RAIL_MISMATCH)", () => {
    const p256 = buildZone(true, { inputs: 2, outputs: 2 });
    expectCode(
      () => assembleZoneAuthority(p256.proofInputs, p256.spendProofs, ZONE),
      "CLIENT_PROOF_RAIL_MISMATCH",
    );
  });
});

describe("merge-zone named rejections", () => {
  function mergeOwner(): Readonly<{
    keypair: ShieldedKeypair;
    nullifierKey: NullifierKey;
  }> {
    const signing = SigningKey.fromBytes(bytes(mergeOracle.inputs.signingSecretBytes) as Bytes32);
    const nullifierKey = NullifierKey.fromSigningKey(signing);
    return {
      keypair: ShieldedKeypair.fromKeys(
        signing,
        nullifierKey,
        ViewingKey.fromSeed(bytes(mergeOracle.inputs.viewingSeedBytes) as Bytes32, 0),
      ),
      nullifierKey,
    };
  }

  /// Every real merge-zone input must carry the builder's zone. An unbound note
  /// would otherwise assemble a proof that cannot settle under that zone program.
  it("refuses an unbound input at MergeZone construction (TRANSACTION_MERGE_INPUT_ZONE_MISMATCH)", () => {
    const { keypair: owner, nullifierKey } = mergeOwner();
    const unbound = new SppProofInputUtxo({
      utxo: new Utxo({
        owner: owner.signingPublicKey(),
        asset: SOL_MINT,
        amount: 10n,
        blinding: deriveBlinding(bytes(mergeOracle.inputs.blindingSeedBytes) as Bytes31, 0),
      }),
      nullifierKey,
    });
    expect(() => new MergeZone(owner, [unbound], MERGE_ZONE)).toThrow(
      expect.objectContaining({
        code: "TRANSACTION_MERGE_INPUT_ZONE_MISMATCH",
        details: { index: 0 },
      }),
    );
  });

  /// Merge and merge-zone are distinct circuits. A zone prepared value on the
  /// plain assembler (or the reverse) must fail by name before proving.
  it("refuses a zone prepared value on the plain merge assembler (CLIENT_INVALID_MERGE)", () => {
    const { keypair: owner, nullifierKey } = mergeOwner();
    const blinding = bytes(mergeOracle.inputs.blindingSeedBytes) as Bytes31;
    const real = new SppProofInputUtxo({
      utxo: new Utxo({
        owner: owner.signingPublicKey(),
        asset: SOL_MINT,
        amount: 10n,
        blinding: deriveBlinding(blinding, 0),
        zoneProgramId: MERGE_ZONE,
      }),
      nullifierKey,
    });
    const preparedZone = new PreparedMergeZone({
      inputs: [
        real,
        ...Array.from({ length: 7 }, (_, index) =>
          SppProofInputUtxo.dummy(deriveBlinding(blinding, index + 1)),
        ),
      ],
      output: createProofOutput({
        ownerAddress: owner.shieldedAddress(),
        asset: SOL_MINT,
        amount: 10n,
        blinding: deriveBlinding(blinding, 2),
        zoneProgramId: MERGE_ZONE,
      }),
      expiryUnixTs: BigInt(mergeOracle.expected.mergeZone.expiryUnixTs),
      signingPublicKey: owner.signingPublicKey(),
      userViewingPublicKey: owner.viewingPublicKey(),
      txViewingSecret: bytes(mergeOracle.inputs.txViewingSecretBytes) as Bytes32,
      zoneProgramId: MERGE_ZONE,
    });
    const proofs = [
      {
        state: {
          leaf: real.hash(),
          merkleContext: { treeType: 1, tree: MERGE_TREE },
          path: Array.from({ length: 32 }, () => fieldByte(10)),
          leafIndex: 0n,
          root: fieldByte(11),
          rootSeq: 12n,
          rootIndex: 13,
        },
        nullifier: {
          leaf: real.nullifier(),
          merkleContext: { treeType: 2, tree: MERGE_TREE },
          path: Array.from({ length: 40 }, () => fieldByte(14)),
          lowElement: fieldByte(15),
          lowElementIndex: 0n,
          highElement: fieldByte(16),
          highElementIndex: 1n,
          root: fieldByte(17),
          rootSeq: 18n,
          rootIndex: 19,
        },
      },
    ];
    const material = {
      signingPublicKey: owner.signingPublicKey(),
      viewingPublicKey: owner.viewingPublicKey(),
      nullifierKey,
    };
    expectCode(
      () => assembleMergeWithProofs(preparedZone, material, proofs, MERGE_TREE),
      "CLIENT_INVALID_MERGE",
    );
    const preparedPlain = new PreparedMerge({
      inputs: preparedZone.inputs.map((input) =>
        input.isDummy()
          ? input
          : new SppProofInputUtxo({
              utxo: new Utxo({
                owner: input.utxo.owner,
                asset: input.utxo.asset,
                amount: input.utxo.amount,
                blinding: input.utxo.blinding,
              }),
              nullifierKey: input.nullifierKey,
            }),
      ),
      output: createProofOutput({
        ownerAddress: owner.shieldedAddress(),
        asset: SOL_MINT,
        amount: 10n,
        blinding: deriveBlinding(blinding, 2),
      }),
      expiryUnixTs: preparedZone.expiryUnixTs,
      signingPublicKey: owner.signingPublicKey(),
      userViewingPublicKey: owner.viewingPublicKey(),
      txViewingSecret: preparedZone.txViewingSecret,
    });
    expectCode(
      () =>
        assembleMergeZoneWithProofs(
          preparedPlain as unknown as PreparedMergeZone,
          material,
          proofs,
          MERGE_TREE,
        ),
      "CLIENT_INVALID_MERGE",
    );
  });
});
