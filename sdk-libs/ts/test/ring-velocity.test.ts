import { getAddressDecoder } from "@solana/kit";
import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "../src/hasher/index.js";
import type { Bytes31, Bytes32, Bytes128, TransactProof } from "../src/interface/types.js";
import { ShieldedAddress } from "../src/keypair/shielded.js";
import { ShieldedPublicKey } from "../src/keypair/public-key.js";
import { NullifierKey } from "../src/keypair/nullifier-key.js";
import { ViewingKey } from "../src/keypair/viewing-key.js";
import { Utxo, ProofInputUtxo, createProofOutput } from "../src/transaction/utxo.js";
import type { ProofInputUtxo as InputUtxo, ProofOutputUtxo } from "../src/transaction/utxo.js";
import type { CustomRingVelocityRow } from "../src/client/prover/types.js";
import { registerRingSpendInstruction } from "../src/ring/instructions.js";
import { chargeRows, recordShape, senderOutflow, type RingMovement } from "../src/ring/velocity.js";
import { memberOfAsset, memberOfIdentity, type Member } from "../src/ring/policy.js";

const filled = (byte: number): Bytes32 => new Uint8Array(32).fill(byte) as Bytes32;
const addressOf = (bytes: Bytes32) => getAddressDecoder().decode(bytes);
const RING = addressOf(filled(0x5a));
const ASSET = addressOf(filled(0xd4));
const NAMESPACE_OWNER = filled(0x77);

function senderIdentity(): { member: Member; address: ShieldedAddress } {
  const signing = ShieldedPublicKey.fromEd25519(filled(0xb2));
  const nullifier = NullifierKey.fromSecret(new Uint8Array(31).fill(1) as Bytes31);
  const viewing = ViewingKey.generate();
  try {
    const address = ShieldedAddress.fromPublicKeys(
      signing,
      nullifier.publicKey(),
      viewing.publicKey(),
    );
    return { member: memberOfIdentity(signing.ownerProofInputHash()), address };
  } finally {
    nullifier.destroy();
    viewing.destroy();
  }
}

function moneyInput(amount: bigint): InputUtxo {
  const owner = ShieldedPublicKey.fromEd25519(filled(0xb2));
  const nullifier = NullifierKey.fromSecret(new Uint8Array(31).fill(2) as Bytes31);
  try {
    return ProofInputUtxo.fromNullifierKey(
      new Utxo({ owner, asset: ASSET, amount, blinding: filled(0x11), ringProgramId: RING }),
      nullifier,
    );
  } finally {
    nullifier.destroy();
  }
}

function changeOutput(address: ShieldedAddress, amount: bigint): ProofOutputUtxo {
  return createProofOutput({
    ownerAddress: address,
    asset: ASSET,
    amount,
    blinding: filled(0x52),
    ringProgramId: RING,
  });
}

function movement(
  sender: Member,
  inputs: readonly InputUtxo[],
  outputs: readonly ProofOutputUtxo[] = [],
): RingMovement {
  return { sender, ringProgramId: RING, inputs, outputs };
}

describe("velocity outflow and charge", () => {
  beforeAll(async () => {
    await initializePoseidon();
  });

  it("picks the smallest shape one slot beyond the money on each side", () => {
    const at = (inputs: number, outputs: number) => recordShape({ inputs, outputs });
    expect(at(1, 1)).toEqual({ inputs: 2, outputs: 2 });
    expect(at(1, 2)).toEqual({ inputs: 2, outputs: 3 });
    expect(at(2, 3)).toEqual({ inputs: 4, outputs: 4 });
    expect(at(4, 3)).toEqual({ inputs: 5, outputs: 4 });
    expect(() => at(4, 4)).toThrow();
  });

  it("charges inputs less the sender's change inside the ring", () => {
    const { member, address } = senderIdentity();
    const asset = memberOfAsset(ASSET);
    expect(senderOutflow(movement(member, [moneyInput(1000n)]), asset)).toBe(1000n);
    expect(
      senderOutflow(movement(member, [moneyInput(1000n)], [changeOutput(address, 400n)]), asset),
    ).toBe(600n);
  });

  it("refuses an outflow above u64", () => {
    const { member } = senderIdentity();
    const half = (1n << 63n) + 1n;
    expect(() =>
      senderOutflow(movement(member, [moneyInput(half), moneyInput(half)]), memberOfAsset(ASSET)),
    ).toThrow(expect.objectContaining({ code: "RING_VELOCITY_OVERFLOW" }));
  });

  it("refuses a transfer over the cap and reads the threshold on the outflow alone", () => {
    const { member } = senderIdentity();
    const asset = memberOfAsset(ASSET);
    const rows: readonly CustomRingVelocityRow[] = [{ asset, cap: 650n, cosignAbove: 300n }];
    const charge = (amount: bigint) =>
      chargeRows({
        movement: movement(member, [moneyInput(amount)]),
        rows,
        namespaceOwnerHash: NAMESPACE_OWNER,
      });
    const under = charge(250n);
    expect(under.approvalRequired).toBe(false);
    expect(under.windowSlots).toBe(0n);
    expect(charge(350n).approvalRequired).toBe(true);
    expect(() => charge(700n)).toThrow(
      expect.objectContaining({ code: "RING_VELOCITY_CAP_EXCEEDED" }),
    );
  });

  it("asks no co-signer at the threshold", () => {
    const { member } = senderIdentity();
    const asset = memberOfAsset(ASSET);
    const rows: readonly CustomRingVelocityRow[] = [{ asset, cap: 0n, cosignAbove: 300n }];
    expect(
      chargeRows({
        movement: movement(member, [moneyInput(300n)]),
        rows,
        namespaceOwnerHash: NAMESPACE_OWNER,
      }).approvalRequired,
    ).toBe(false);
  });
});

describe("spend registration", () => {
  const PAYER = addressOf(filled(0x21));
  const TREE = addressOf(filled(0x40));

  function proof(): TransactProof {
    return {
      a: filled(1),
      b: new Uint8Array(128).fill(2) as Bytes128,
      c: filled(3),
    };
  }

  it("mirrors Rust `RegisterSpendIxData` with no shared root account", async () => {
    const instruction = await registerRingSpendInstruction({
      ringProgramId: RING,
      payer: PAYER,
      inputTree: TREE,
      outputTree: TREE,
      blinding: filled(7),
      proof: {
        proof: proof(),
        utxoTreeRootIndex: 0,
        nullifierTreeRootIndex: 0,
        nullifier: filled(9),
        privateTxBlinding: filled(0),
      },
    });
    const data = instruction.data ?? new Uint8Array();
    expect(data).toHaveLength(1 + 32 + 32 + 2 + 2 + 32 + 128 + 32);
    expect(data.subarray(1, 33)).toEqual(filled(7));
    expect(data.subarray(data.length - 32)).toEqual(filled(3));
  });
});
