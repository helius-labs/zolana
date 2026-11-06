import { address, type Address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import vectors from "../../../test-vectors/transfer_output_order.json" with { type: "json" };
import type { Bytes32 } from "../src/interface/index.js";
import { ShieldedKeypair, SigningKey, randomBlinding } from "../src/keypair/index.js";
import type { ShieldedAddress } from "../src/keypair/shielded.js";
import {
  ConfidentialTransfer,
  ProofInputUtxo,
  SOL_MINT,
  Utxo,
  WithdrawalTarget,
} from "../src/transaction/index.js";

interface Amount {
  readonly asset: string;
  readonly amount: number;
}

interface VectorCase {
  readonly name: string;
  readonly inputs: readonly Amount[];
  readonly sends?: readonly (Amount & { readonly recipient: number })[];
  readonly withdrawal?: Amount;
  readonly outputs: readonly (Amount & { readonly owner: string; readonly recipient?: number })[];
}

const cases: readonly VectorCase[] = vectors.cases;

// Any public account: the vectors pin the private output slots only.
const PUBLIC_ACCOUNT = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const SPL_MINT = address(vectors.spl_mint);

function keypair(seed: number): ShieldedKeypair {
  // The 32-byte array has the length `Bytes32` requires.
  return ShieldedKeypair.fromKeypair(
    SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(seed) as Bytes32),
  );
}

function asset(name: string): Address {
  if (name === "sol") return SOL_MINT;
  if (name === "spl") return SPL_MINT;
  throw new Error(`invalid vector asset ${name}`);
}

function viewTag(owner: ShieldedAddress | undefined): string | undefined {
  return owner && Buffer.from(owner.signingPublicKey.confidentialViewTag()).toString("hex");
}

describe("transfer output order", () => {
  // Rust builds the same real output slots from the same vectors, so the slot
  // order does not tell which SDK built a transaction.
  it.each(cases)("leads with change: $name", (vector) => {
    const sender = keypair(vectors.sender_seed);
    const recipients = vectors.recipient_seeds.map((seed) => keypair(seed).shieldedAddress());
    const transfer = new ConfidentialTransfer(
      sender.shieldedAddress(),
      vector.inputs.map((input) =>
        ProofInputUtxo.fromKeypair(
          new Utxo({
            owner: sender.signingPublicKey(),
            asset: asset(input.asset),
            amount: BigInt(input.amount),
            blinding: randomBlinding(),
          }),
          sender,
        ),
      ),
      sender.shieldedAddress().solanaAddress(),
    );
    for (const send of vector.sends ?? []) {
      const recipient = recipients[send.recipient];
      if (recipient === undefined) throw new Error("invalid vector recipient");
      transfer.send(recipient, asset(send.asset), BigInt(send.amount));
    }
    if (vector.withdrawal !== undefined) {
      const withdrawn = asset(vector.withdrawal.asset);
      transfer.withdraw(
        withdrawn,
        BigInt(vector.withdrawal.amount),
        withdrawn === SOL_MINT
          ? WithdrawalTarget.sol({ recipient: PUBLIC_ACCOUNT })
          : WithdrawalTarget.spl({
              recipientTokenAccount: PUBLIC_ACCOUNT,
              splTokenInterface: PUBLIC_ACCOUNT,
              splInterfaceBump: 255,
            }),
      );
    }
    const expected = vector.outputs.map((output) => {
      const owner =
        output.owner === "sender"
          ? sender.shieldedAddress()
          : output.recipient === undefined
            ? undefined
            : recipients[output.recipient];
      if (owner === undefined) throw new Error("invalid vector owner");
      return { owner: viewTag(owner), asset: asset(output.asset), amount: BigInt(output.amount) };
    });
    const actual = transfer.prepare().outputs.map((output) => ({
      owner: viewTag(output.ownerAddress),
      asset: output.asset,
      amount: output.amount,
    }));
    expect(actual).toEqual(expected);
  });
});
