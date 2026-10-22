import { address, type Signature } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { hashBytes, initializePoseidon } from "../src/hasher/index.js";
import { CUSTOM_RING_PROOF_LENGTH } from "../src/interface/custom-ring-proof.js";
import { addressBytes } from "../src/interface/internal.js";
import { treeAddress } from "../src/interface/pda/index.js";
import type { Bytes16, Bytes32 } from "../src/interface/types.js";
import { bigIntToBytes } from "../src/keypair/bytes.js";
import { mergeOutputKey } from "../src/keypair/merge/index.js";
import { ShieldedKeypair } from "../src/keypair/shielded.js";
import { X25519Keypair } from "../src/keypair/x25519.js";
import { createdRingUtxos, scanCreatedRingUtxos } from "../src/ring/created.js";
import { sealRingDepositOpenings } from "../src/ring/deposit-audit.js";
import { sealRingMergeDisclosure } from "../src/ring/merge-disclosure.js";
import { ConfirmedDeposit, type TransactionOrigin } from "../src/ring/origin.js";
import { SOL_MINT } from "../src/transaction/asset.js";
import type { IndexedShieldedTransaction } from "../src/transaction/instructions/transact.js";
import {
  encodeMergeOutputData,
  encryptMergeOutput,
} from "../src/transaction/serialization/merge.js";
import { Utxo, ownerUtxoHash } from "../src/transaction/utxo.js";
import { ringAuditReader, transactionsPage } from "./helpers/clients.js";
import { confirmedDepositTransaction, ringDepositPayload } from "./helpers/confirmed-deposits.js";

await initializePoseidon();

const RING = address("9vyTbYGyh3cwxkAQpjjFQGXmdJP6p9B6YcQ5pNuXPNbh");
const TREE_ID = 0;
const SIGNATURE = "1".repeat(87) as Signature;
const ZERO = new Uint8Array(32) as Bytes32;
const SOL_ASSET = hashBytes(addressBytes(SOL_MINT)) as Bytes32;

function field(value: bigint): Bytes32 {
  return bigIntToBytes(value) as Bytes32;
}

function transaction(
  input: Pick<IndexedShieldedTransaction, "outputSlots" | "nullifiers" | "proofless">,
): IndexedShieldedTransaction {
  return {
    slot: 1n,
    txSignature: SIGNATURE,
    eventIndex: 0,
    messages: [],
    ringProgramId: RING,
    ...input,
  };
}

function outputContext(hash: Bytes32, leafIndex: bigint) {
  return { hash, tree: treeAddress(TREE_ID), treeId: TREE_ID, leafIndex };
}

/** One deposit paying an anonymous ring's owner then a confidential ring's. */
function deposits(auditor: X25519Keypair) {
  const anonymous = ShieldedKeypair.generate();
  const confidential = ShieldedKeypair.generate();
  const blinding = field(5n);
  const ownerKey = anonymous.signingPublicKey().ed25519();
  const sealed = sealRingDepositOpenings(
    [
      {
        ownerHash: anonymous.ownerHash(),
        blinding,
        ownerKey,
        recipientCiphertext: Uint8Array.of(1),
      },
      { ownerHash: confidential.ownerHash(), blinding, recipientCiphertext: Uint8Array.of(2) },
    ],
    auditor.publicKey(),
  );
  const owners = [anonymous, confidential].map((keypair) =>
    ownerUtxoHash(keypair.ownerHash(), blinding),
  );
  const commitments = [anonymous, confidential].map((keypair) =>
    new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 1n,
      blinding,
      ringProgramId: RING,
    }).hash(keypair.nullifierPublicKey(), TREE_ID),
  );
  return {
    sealed,
    commitments,
    bindings: ConfirmedDeposit.fromTransaction(
      confirmedDepositTransaction(RING, SIGNATURE, sealed.capsules, owners),
      SIGNATURE,
      0,
      RING,
    ),
    outputSlots: sealed.capsules.map((capsule, index) => ({
      viewTag: ZERO,
      outputContext: outputContext(commitments[index]!, BigInt(index)),
      payload: ringDepositPayload({
        ring: RING,
        ownerCommitment: owners[index]!,
        asset: SOL_MINT,
        amount: 1n,
        capsule,
      }),
    })),
    utxo: {
      ownerKey,
      owner: { kind: "deposited", ownerHash: anonymous.ownerHash() },
      asset: SOL_ASSET,
      mint: SOL_MINT,
      amount: 1n,
      blinding,
      dataHash: ZERO,
      ringDataHash: ZERO,
      treeId: TREE_ID,
    },
  };
}

describe("createdRingUtxos", () => {
  it("opens the anonymous deposit's UTXO by its owner hash and passes over a confidential one", () => {
    const auditor = X25519Keypair.generate();
    const deposit = deposits(auditor);
    try {
      const created = (outputSlots: typeof deposit.outputSlots) =>
        createdRingUtxos({
          confirmed: {
            kind: "deposit",
            transaction: transaction({ outputSlots, nullifiers: [], proofless: true }),
            deposits: deposit.bindings,
          },
          ringProgramId: RING,
          auditor,
        });
      expect(created(deposit.outputSlots)).toEqual([
        { commitment: deposit.commitments[0], slotIndex: 0, utxo: deposit.utxo },
      ]);
      const moved = deposit.outputSlots.map((slot, index) =>
        index === 0 ? { ...slot, outputContext: outputContext(deposit.commitments[1]!, 0n) } : slot,
      );
      expect(() => created(moved)).toThrow(expect.objectContaining({ code: "RING_AUDIT_MESSAGE" }));
    } finally {
      deposit.sealed.ephemeralSecret.fill(0);
      auditor.destroy();
    }
  });

  it("scans the ring's history for created UTXOs and stops at the page cap", async () => {
    const auditor = X25519Keypair.generate();
    const deposit = deposits(auditor);
    try {
      const indexed = transaction({
        outputSlots: deposit.outputSlots,
        nullifiers: [],
        proofless: true,
      });
      const transfer = { ...indexed, txSignature: "2".repeat(87) as Signature };
      const origin: TransactionOrigin = {
        confirmedTransaction: async (event) =>
          event.txSignature === SIGNATURE
            ? { kind: "deposit", transaction: event, deposits: deposit.bindings }
            : {
                kind: "transfer",
                transaction: event,
                inputTreeIds: [],
                layout: {
                  kind: "packed",
                  outputs: 2,
                  exits: false,
                  keyEscrow: false,
                  dataFree: true,
                },
              },
      };
      const scan = (page: Parameters<typeof transactionsPage>[0], maxPages?: number) =>
        scanCreatedRingUtxos({
          client: ringAuditReader({
            getShieldedTransactionsByTags: async () => transactionsPage(page),
          }),
          ringProgramId: RING,
          auditor,
          origin,
          ...(maxPages === undefined ? {} : { maxPages }),
        });
      const scanned = await scan({
        transactions: [indexed, transfer],
        scannedThrough: Uint8Array.of(1),
      });
      expect(scanned).toEqual({
        utxos: [{ commitment: deposit.commitments[0], slotIndex: 0, utxo: deposit.utxo }],
      });
      const foreign = await scan({
        transactions: [{ ...indexed, ringProgramId: address("11111111111111111111111111111111") }],
        scannedThrough: Uint8Array.of(1),
      });
      expect(foreign).toEqual({ utxos: [] });
      const capped = await scan({ transactions: [transfer], nextCursor: Uint8Array.of(7) }, 1);
      expect(capped).toEqual({ utxos: [], nextCursor: Uint8Array.of(7) });
      await expect(
        scan({ transactions: [], scannedThrough: Uint8Array.of(1) }, 0),
      ).rejects.toMatchObject({
        code: "RING_RPC",
        details: { reason: "invalid scan limit", name: "maxPages" },
      });
    } finally {
      deposit.sealed.ephemeralSecret.fill(0);
      auditor.destroy();
    }
  });

  it("opens the anonymous merge's settled UTXO with its nullifier key and nothing of a confidential one", () => {
    const auditor = X25519Keypair.generate();
    const owner = ShieldedKeypair.generate();
    const nullifiers = [field(7n), field(8n)];
    const salt = new Uint8Array(16).fill(3) as Bytes16;
    const ringDataHash = field(0xd0n);
    const outputBlinding = field(11n);
    const commitment = ownerUtxoHash({
      owner: owner.ownerHash(),
      asset: SOL_MINT,
      amount: 12n,
      blinding: outputBlinding,
      treeId: TREE_ID,
      ringDataHash,
      ringProgramId: RING,
    });
    const sealed = sealRingMergeDisclosure(
      {
        ownerKey: owner.shieldedAddress().solanaAddress(),
        nullifierPublicKey: owner.nullifierPublicKey(),
        mint: SOL_MINT,
        amount: 12n,
        outputBlinding,
        inputCommitments: Array.from({ length: 8 }, (_, index) =>
          index < nullifiers.length ? field(20n + BigInt(index)) : ZERO,
        ),
      },
      salt,
      auditor.publicKey(),
    );
    try {
      const merge = transaction({
        outputSlots: [
          {
            viewTag: nullifiers[0]!,
            outputContext: outputContext(commitment, 3n),
            payload: encodeMergeOutputData({
              salt,
              ciphertext: encryptMergeOutput(
                { amount: 12n, mint: SOL_MINT },
                mergeOutputKey(owner.nullifierKey(), nullifiers[0]!),
                salt,
              ),
              ringDataHash,
            }),
          },
        ],
        nullifiers,
        proofless: false,
      });
      const disclosure = { ...sealed.disclosure, proof: new Uint8Array(CUSTOM_RING_PROOF_LENGTH) };
      expect(
        createdRingUtxos({
          confirmed: { kind: "merge", transaction: merge, disclosure },
          ringProgramId: RING,
          auditor,
        }),
      ).toEqual([
        {
          commitment,
          slotIndex: 0,
          utxo: {
            ownerKey: owner.signingPublicKey().ed25519(),
            owner: { kind: "keyed", nullifierPk: owner.nullifierPublicKey() },
            asset: SOL_ASSET,
            mint: SOL_MINT,
            amount: 12n,
            blinding: outputBlinding,
            dataHash: ZERO,
            ringDataHash,
            treeId: TREE_ID,
          },
        },
      ]);
      expect(
        createdRingUtxos({
          confirmed: { kind: "merge", transaction: merge },
          ringProgramId: RING,
          auditor,
        }),
      ).toEqual([]);
    } finally {
      sealed.ephemeralSecret.fill(0);
      sealed.disclosureKey.fill(0);
      auditor.destroy();
    }
  });
});
