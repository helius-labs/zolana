import { getBase58Decoder, type Address, type Signature } from "@solana/kit";
import { encodeRingDepositInstructionData } from "../../src/interface/codecs/index.js";
import { CUSTOM_RING_PROOF_LENGTH } from "../../src/interface/custom-ring-proof.js";
import { Writer, addressBytes } from "../../src/interface/internal.js";
import { InstructionTag, SHIELDED_POOL_PROGRAM_ID } from "../../src/interface/program.js";
import type { Bytes16, Bytes32 } from "../../src/interface/types.js";
import {
  encodeRingDepositCapsule,
  type RingDepositCapsule,
} from "../../src/ring/deposit-capsule.js";
import { EncryptedScheme, encodeOutputData } from "../../src/transaction/serialization/codecs.js";

/** Borsh `RingDepositOutput`, the capsule as its ciphertext. */
export function ringDepositPayload(
  input: Readonly<{
    ring: Address;
    ownerCommitment: Bytes32;
    asset: Address;
    amount: bigint;
    capsule: RingDepositCapsule;
  }>,
): Uint8Array {
  const ciphertext = encodeRingDepositCapsule(input.capsule);
  const body = new Writer()
    .bytes(input.ownerCommitment)
    .bytes(addressBytes(input.asset))
    .u64(input.amount, "amount")
    .u8(0, "dataHash")
    .bytes(addressBytes(input.ring))
    .bytes(new Uint8Array(32))
    .bytes(input.capsule.ephemeralPublicKey)
    .bytes(new Uint8Array(16))
    .u32(ciphertext.length, "ciphertext.length")
    .bytes(ciphertext)
    .finish();
  return encodeOutputData(EncryptedScheme.ringDeposit, body, "encrypted");
}

/** A successful confirmed wrapper and its exact SPP self-CPI ancestry. */
export function confirmedDepositTransaction(
  ring: Address,
  signature: Signature,
  capsules: readonly RingDepositCapsule[],
  owners: readonly Bytes32[],
) {
  const wire = Uint8Array.of(
    InstructionTag.ringDeposit,
    ...encodeRingDepositInstructionData({
      assets: [{ kind: "sol" }],
      deposits: capsules.map((capsule, index) => {
        const ownerUtxoHash = owners[index];
        if (ownerUtxoHash === undefined) throw new Error("missing owner commitment");
        return {
          assetIndex: 0,
          viewTag: new Uint8Array(32) as Bytes32,
          ownerUtxoHash,
          amount: 1n,
          ringDataHash: new Uint8Array(32) as Bytes32,
          encrypted: {
            txViewingPublicKey: capsule.ephemeralPublicKey,
            salt: new Uint8Array(16) as Bytes16,
            ciphertext: encodeRingDepositCapsule(capsule),
          },
        };
      }),
    }),
  );
  const encode = getBase58Decoder();
  const wrapper = Uint8Array.of(31, ...new Uint8Array(CUSTOM_RING_PROOF_LENGTH + 1), ...wire);
  return {
    transaction: {
      signatures: [signature],
      message: {
        accountKeys: [ring, SHIELDED_POOL_PROGRAM_ID],
        instructions: [{ programIdIndex: 0, accounts: [], data: encode.decode(wrapper) }],
      },
    },
    meta: {
      err: null,
      innerInstructions: [
        {
          index: 0,
          instructions: [
            { programIdIndex: 1, accounts: [], data: encode.decode(wire), stackHeight: 2 },
            {
              programIdIndex: 1,
              accounts: [],
              data: encode.decode(Uint8Array.of(InstructionTag.emitEvent, 0)),
              stackHeight: 3,
            },
          ],
        },
      ],
    },
  };
}
