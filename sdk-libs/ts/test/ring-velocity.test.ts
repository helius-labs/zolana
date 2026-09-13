import { AccountRole, getAddressDecoder } from "@solana/kit";
import { beforeAll, describe, expect, it } from "vitest";

import { initializePoseidon } from "../src/hasher/index.js";
import { ringHeadMapRootAddress } from "../src/interface/pda/index.js";
import type { Bytes32, Bytes128, TransactProof } from "../src/interface/types.js";
import { ShieldedAddress } from "../src/keypair/shielded.js";
import { ShieldedPublicKey } from "../src/keypair/public-key.js";
import { NullifierKey } from "../src/keypair/nullifier-key.js";
import { ViewingKey } from "../src/keypair/viewing-key.js";
import { Utxo, ProofInputUtxo, createProofOutput } from "../src/transaction/utxo.js";
import type { ProofInputUtxo as InputUtxo, ProofOutputUtxo } from "../src/transaction/utxo.js";
import { registerRingSpendInstruction } from "../src/ring/instructions.js";
import { chargeRows, recordShape, senderOutflow } from "../src/ring/velocity.js";
import { memberOfAsset, memberOfIdentity } from "../src/ring/policy.js";
import type { VelocityRow } from "../src/ring/policy.js";

const filled = (byte: number): Bytes32 => new Uint8Array(32).fill(byte) as Bytes32;
const addressOf = (bytes: Bytes32) => getAddressDecoder().decode(bytes);
const RING = addressOf(filled(0x5a));
const ASSET = addressOf(filled(0xd4));
const NAMESPACE_OWNER = filled(0x77);

function senderIdentity(): {
  member: ReturnType<typeof memberOfIdentity>;
  address: ShieldedAddress;
} {
  const signing = ShieldedPublicKey.fromEd25519(filled(0xb2));
  const nullifier = NullifierKey.fromSecret(new Uint8Array(31).fill(1) as never);
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
  const nullifier = NullifierKey.fromSecret(new Uint8Array(31).fill(2) as never);
  try {
    return new ProofInputUtxo({
      utxo: new Utxo({ owner, asset: ASSET, amount, blinding: filled(0x51), ringProgramId: RING }),
      nullifierKey: nullifier,
    });
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
    expect(senderOutflow(member, RING, [moneyInput(1000n)], [], asset)).toBe(1000n);
    expect(
      senderOutflow(member, RING, [moneyInput(1000n)], [changeOutput(address, 400n)], asset),
    ).toBe(600n);
  });

  it("refuses a transfer over the cap and reads the threshold on the outflow alone", () => {
    const { member } = senderIdentity();
    const asset = memberOfAsset(ASSET);
    const rows: readonly VelocityRow[] = [{ asset, cap: 650n, cosignAbove: 300n }];
    const under = chargeRows(member, RING, [moneyInput(250n)], [], rows, NAMESPACE_OWNER);
    expect(under.approvalRequired).toBe(false);
    expect(under.windowSlots).toBe(0n);
    const above = chargeRows(member, RING, [moneyInput(350n)], [], rows, NAMESPACE_OWNER);
    expect(above.approvalRequired).toBe(true);
    expect(() => chargeRows(member, RING, [moneyInput(700n)], [], rows, NAMESPACE_OWNER)).toThrow(
      expect.objectContaining({ code: "RING_VELOCITY_CAP_EXCEEDED" }),
    );
  });

  it("asks no co-signer at the threshold", () => {
    const { member } = senderIdentity();
    const asset = memberOfAsset(ASSET);
    const rows: readonly VelocityRow[] = [{ asset, cap: 0n, cosignAbove: 300n }];
    expect(
      chargeRows(member, RING, [moneyInput(300n)], [], rows, NAMESPACE_OWNER).approvalRequired,
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

  it("pins the shared compressed root as the trailing account", async () => {
    const instruction = await registerRingSpendInstruction({
      ringProgramId: RING,
      payer: PAYER,
      entriesTree: TREE,
      blinding: filled(7),
      headOldRoot: filled(1),
      headNewRoot: filled(2),
      headNextIndex: 1n,
      headProof: new Uint8Array(128),
      proof: {
        proof: proof(),
        utxoTreeRootIndex: 0,
        nullifierTreeRootIndex: 0,
        nullifier: filled(9),
        privateTxBlinding: filled(0),
      },
    });
    const head = await ringHeadMapRootAddress(RING);
    const accounts = instruction.accounts ?? [];
    const last = accounts[accounts.length - 1];
    expect(last?.address).toBe(head);
    expect(last?.role).toBe(AccountRole.WRITABLE);
  });
});
