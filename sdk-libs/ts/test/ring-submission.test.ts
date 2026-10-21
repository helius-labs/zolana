import {
  address,
  generateKeyPairSigner,
  signTransactionWithSigners,
  type Address,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";
import { ClientError } from "../src/client/error.js";
import type { RingSubmissionStatus, RingSubmissionTransport } from "../src/client/ports.js";
import { compileUnsignedTransaction } from "../src/flows/compile.js";
import type { Bytes32 } from "../src/interface/types.js";
import { EPOCH_SLOTS, tagIndex } from "../src/keypair/ring-stream.js";
import { X25519Keypair } from "../src/keypair/x25519.js";
import { RingProgramError } from "../src/ring/error.js";
import type { PendingFirstContact } from "../src/ring/pipeline.js";
import { SOL_MINT } from "../src/transaction/asset.js";
import {
  createKitRingSubmissionTransport,
  RingTransactionSubmission,
  type RingSubmissionAttempt,
} from "../src/ring/submission.js";
import { ringMemberRegistryPda, treeAddress } from "../src/interface/pda/index.js";
import { BLOCKHASH, kitReads } from "./helpers/clients.js";
import { memberRegistryData, ownedAccount } from "./helpers/ring-accounts.js";
import { ANCHOR_ROOT, ANCHOR_ROOT_INDEX, anchorTreeAccount } from "./helpers/ring-pipeline.js";

const HASH = new Uint8Array(32) as Bytes32;
const MEMO = address("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");
const STALE_ROOT: RingSubmissionStatus = {
  kind: "failed",
  instructionIndex: 0,
  customCode: RingProgramError.rootBelowFloor,
};

/** A registry whose history slot 3 holds `root`. */
async function registryAccount(ringProgramId: Address, root: Bytes32, policyHash?: Bytes32) {
  const [, bump] = await ringMemberRegistryPda(ringProgramId);
  const history = Array.from({ length: 32 }, (_, slot) =>
    slot === 3 ? { root, applied: 0n, slot: 0n } : undefined,
  );
  return ownedAccount(
    ringProgramId,
    memberRegistryData({
      bump,
      history,
      historyCursor: 3,
      nextIndex: 40,
      ...(policyHash === undefined ? {} : { policyHash }),
    }),
  );
}

const PROOF_REJECTED: RingSubmissionStatus = {
  kind: "failed",
  instructionIndex: 0,
  customCode: RingProgramError.proofVerificationFailed,
};

/** The inbox payment an attempt of `version` sends. */
function firstContact(version: number): PendingFirstContact {
  return {
    recipient: X25519Keypair.fromBytes(new Uint8Array(32).fill(version + 1)).publicKey(),
    treeId: 0,
    utxoHash: new Uint8Array(32).fill(version) as Bytes32,
    slotSecret: HASH,
    firstNullifier: HASH,
    slotIndex: 1,
    epoch: 0n,
    index: tagIndex(0),
    asset: SOL_MINT,
    amount: 5n,
  };
}

async function fixture(
  roots?: RingSubmissionAttempt["roots"],
  contacts?: (version: number) => readonly PendingFirstContact[],
) {
  const payer = await generateKeyPairSigner();
  let version = 0;
  const build = vi.fn(async (): Promise<RingSubmissionAttempt> => ({
    ...(roots === undefined ? {} : { roots }),
    ...(contacts === undefined ? {} : { firstContacts: contacts(version) }),
    transaction: compileUnsignedTransaction({
      feePayer: payer.address,
      lifetime: BLOCKHASH,
      instructions: [{ programAddress: MEMO, data: Uint8Array.of(version++) }],
      computeUnitLimit: 1_000,
    }),
    lastValidBlockHeight: 100n,
    intentHash: HASH,
    ringInstructionIndex: 0,
  }));
  const release = vi.fn();
  const extend = vi.fn();
  const submission = new RingTransactionSubmission({
    first: await build(),
    build,
    reservation: { release, extend },
  });
  const send = vi.fn(async (): Promise<RingSubmissionStatus | undefined> => undefined);
  const sign = vi.fn(async (transaction: RingSubmissionAttempt["transaction"]) =>
    signTransactionWithSigners([payer], transaction),
  );
  return { submission, build, release, extend, send, sign };
}

describe("ring submission ownership", () => {
  it("refuses a signer that returns a different message before broadcasting", async () => {
    const f = await fixture();
    const another = await f.build();
    await expect(
      f.submission.send({
        sign: async () => f.sign(another.transaction),
        send: f.send,
        status: async () => ({ kind: "confirmed", slot: 1n }),
      }),
    ).rejects.toMatchObject({ code: "RING_INTENT_MISMATCH" });
    expect(f.send).not.toHaveBeenCalled();
    expect(f.release).toHaveBeenCalledTimes(1);
  });

  it("does not resend or release after unknown, and resumes by checking that signature", async () => {
    const f = await fixture();
    const transport: RingSubmissionTransport = {
      sign: f.sign,
      send: f.send,
      status: async () => ({ kind: "unknown" }),
    };
    const first = await f.submission.send(transport);
    const second = await f.submission.send(transport);
    expect(first).toEqual(second);
    expect(f.send).toHaveBeenCalledTimes(1);
    expect(f.sign).toHaveBeenCalledTimes(1);
    expect(f.build).toHaveBeenCalledTimes(1);
    expect(f.release).not.toHaveBeenCalled();
    expect(() => f.submission.cancel()).toThrow("RING_SUBMISSION_PENDING");
    const confirmed = await f.submission.send({
      ...transport,
      status: async () => ({ kind: "confirmed", slot: 10n }),
    });
    expect(confirmed.kind).toBe("confirmed");
    expect(f.send).toHaveBeenCalledTimes(1);
    expect(f.release).not.toHaveBeenCalled();
  });

  it("checks the reservation before signing and polls without changing its lifetime", async () => {
    const f = await fixture();
    const transport: RingSubmissionTransport = {
      sign: f.sign,
      send: f.send,
      status: async () => ({ kind: "unknown" }),
    };
    await f.submission.send(transport);
    expect(f.extend).toHaveBeenCalledTimes(1);
    await f.submission.send(transport);
    expect(f.extend).toHaveBeenCalledTimes(1);
  });

  it("rebuilds and re-signs only after a confirmed stale-root failure, at most three times", async () => {
    const f = await fixture();
    const result = await f.submission.send({
      sign: f.sign,
      send: f.send,
      status: async () => STALE_ROOT,
    });
    expect(result).toMatchObject({ kind: "failed", attempts: 3 });
    expect(f.build).toHaveBeenCalledTimes(3);
    expect(f.sign).toHaveBeenCalledTimes(3);
    expect(f.send).toHaveBeenCalledTimes(3);
    expect(f.release).toHaveBeenCalledTimes(1);
  });

  it("confirms with the first contacts of the attempt that landed", async () => {
    const f = await fixture(undefined, (version) => [firstContact(version)]);
    let sent = 0;
    const result = await f.submission.send({
      sign: f.sign,
      send: f.send,
      status: async () => (++sent === 1 ? STALE_ROOT : { kind: "confirmed", slot: 7n }),
    });
    expect(result).toMatchObject({ kind: "confirmed", attempts: 2, slot: 7n });
    if (result.kind !== "confirmed") throw new Error("not confirmed");
    expect(result.firstContacts.map((contact) => contact.utxoHash)).toEqual([
      firstContact(1).utxoHash,
    ]);
  });

  it.each([
    RingProgramError.rootBelowFloor,
    RingProgramError.curatorRootStale,
    RingProgramError.rootIndexEmpty,
    RingProgramError.authorityBatchTooLarge,
  ])("rebuilds after the stale proof code %i", async (customCode) => {
    const f = await fixture();
    const result = await f.submission.send({
      sign: f.sign,
      send: f.send,
      status: async () => ({ kind: "failed", instructionIndex: 0, customCode }),
    });
    expect(result).toMatchObject({ kind: "failed", attempts: 3, customCode });
    expect(f.build).toHaveBeenCalledTimes(3);
  });

  it("treats a refusal returned by send as a confirmed failure", async () => {
    const f = await fixture();
    const status = vi.fn(async (): Promise<RingSubmissionStatus> => ({ kind: "unknown" }));
    const result = await f.submission.send({ sign: f.sign, send: async () => STALE_ROOT, status });
    expect(result).toMatchObject({
      kind: "failed",
      attempts: 3,
      instructionIndex: 0,
      customCode: RingProgramError.rootBelowFloor,
    });
    expect(status).not.toHaveBeenCalled();
    expect(f.build).toHaveBeenCalledTimes(3);
    expect(f.release).toHaveBeenCalledTimes(1);
  });

  it("does not retry the same numeric error from a different instruction", async () => {
    const f = await fixture();
    const result = await f.submission.send({
      sign: f.sign,
      send: f.send,
      status: async () => ({ ...STALE_ROOT, instructionIndex: 1 }),
    });
    expect(result).toMatchObject({
      kind: "failed",
      attempts: 1,
      instructionIndex: 1,
      customCode: RingProgramError.rootBelowFloor,
    });
    expect(f.build).toHaveBeenCalledTimes(1);
  });

  it("never rebuilds a rejected policy proof", async () => {
    const rejected = await fixture();
    const proof = await rejected.submission.send({
      sign: rejected.sign,
      send: rejected.send,
      status: async () => ({
        kind: "failed",
        instructionIndex: 0,
        customCode: RingProgramError.proofVerificationFailed,
      }),
    });
    expect(proof).toMatchObject({ kind: "failed", attempts: 1 });
    expect(rejected.build).toHaveBeenCalledTimes(1);
  });

  it("rebuilds a rejected proof only when its registry slot holds another root", async () => {
    const ringProgramId = address("Ring111111111111111111111111111111111111111");
    const bound = new Uint8Array(32).fill(7) as Bytes32;
    for (const [held, attempts] of [
      [new Uint8Array(32).fill(8) as Bytes32, 3],
      [bound, 1],
    ] as const) {
      const f = await fixture([{ ringProgramId, rootIndex: 3, root: bound }]);
      const account = await registryAccount(ringProgramId, held);
      const registry = { getAccount: vi.fn(async () => account) };
      const submission = new RingTransactionSubmission({
        first: await f.build(),
        build: f.build,
        reservation: { release: f.release, extend: f.extend },
        registry,
      });
      const result = await submission.send({
        sign: f.sign,
        send: f.send,
        status: async () => ({
          kind: "failed",
          instructionIndex: 0,
          customCode: RingProgramError.proofVerificationFailed,
        }),
      });
      expect(result).toMatchObject({ kind: "failed", attempts });
      expect(registry.getAccount).toHaveBeenCalledTimes(attempts);
    }
  });

  it("rebuilds a rejected anonymous proof only once the epoch it binds passed", async () => {
    for (const [slot, attempts] of [
      [EPOCH_SLOTS, 3],
      [EPOCH_SLOTS - 1n, 1],
    ] as const) {
      const f = await fixture();
      const build = vi.fn(async () => ({ ...(await f.build()), epoch: 0n }));
      const clock = { getSlot: vi.fn(async () => slot) };
      const submission = new RingTransactionSubmission({
        first: await build(),
        build,
        reservation: { release: f.release, extend: f.extend },
        clock,
      });
      const result = await submission.send({
        sign: f.sign,
        send: f.send,
        status: async () => ({
          kind: "failed",
          instructionIndex: 0,
          customCode: RingProgramError.proofVerificationFailed,
        }),
      });
      expect(result).toMatchObject({ kind: "failed", attempts });
      expect(clock.getSlot).toHaveBeenCalledTimes(attempts);
    }
  });

  it("rebuilds a rejected policy proof only once the registry holds another policy hash", async () => {
    const ringProgramId = address("Ring111111111111111111111111111111111111111");
    const bound = new Uint8Array(32).fill(5) as Bytes32;
    for (const [held, attempts] of [
      [new Uint8Array(32).fill(6) as Bytes32, 3],
      [bound, 1],
    ] as const) {
      const f = await fixture();
      const build = vi.fn(async () => ({
        ...(await f.build()),
        policy: { ringProgramId, policyHash: bound },
      }));
      const account = await registryAccount(ringProgramId, HASH, held);
      const registry = { getAccount: vi.fn(async () => account) };
      const submission = new RingTransactionSubmission({
        first: await build(),
        build,
        reservation: { release: f.release, extend: f.extend },
        registry,
      });
      const result = await submission.send({
        sign: f.sign,
        send: f.send,
        status: async () => PROOF_REJECTED,
      });
      expect(result).toMatchObject({ kind: "failed", attempts });
    }
  });

  it("rebuilds a rejected anonymous proof only once its first-contact root left the tree's slot", async () => {
    const anchor = { tree: treeAddress(0), rootIndex: ANCHOR_ROOT_INDEX, root: ANCHOR_ROOT };
    for (const [held, attempts] of [
      [new Uint8Array(32).fill(0x73) as Bytes32, 3],
      [ANCHOR_ROOT, 1],
    ] as const) {
      const f = await fixture();
      const build = vi.fn(async () => ({ ...(await f.build()), anchor }));
      const account = anchorTreeAccount(held);
      const registry = { getAccount: vi.fn(async () => account) };
      const submission = new RingTransactionSubmission({
        first: await build(),
        build,
        reservation: { release: f.release, extend: f.extend },
        registry,
      });
      const result = await submission.send({
        sign: f.sign,
        send: f.send,
        status: async () => PROOF_REJECTED,
      });
      expect(result).toMatchObject({ kind: "failed", attempts });
      expect(registry.getAccount).toHaveBeenCalledTimes(attempts);
    }
  });

  it("rebuilds on curator rollover and keeps a failed curator read pending", async () => {
    const ringProgramId = address("Ring111111111111111111111111111111111111111");
    const curatorProgram = MEMO;
    const [ownAddress] = await ringMemberRegistryPda(ringProgramId);
    const [curator] = await ringMemberRegistryPda(curatorProgram);
    const bound = new Uint8Array(32).fill(7) as Bytes32;
    const replaced = new Uint8Array(32).fill(8) as Bytes32;
    for (const [held, expectedAttempts] of [
      [bound, 1],
      [replaced, 3],
    ] as const) {
      const roots = [
        { ringProgramId, rootIndex: 3, root: bound },
        { ringProgramId: curatorProgram, rootIndex: 3, root: bound },
      ];
      const f = await fixture(roots);
      const [own, foreign] = await Promise.all([
        registryAccount(ringProgramId, bound),
        registryAccount(curatorProgram, held),
      ]);
      let missing = true;
      const registry = {
        getAccount: vi.fn(async (account: typeof ownAddress) => {
          if (account === curator && missing)
            throw new ClientError("CLIENT_RPC", { details: { reason: "unavailable" } });
          expect(account === ownAddress || account === curator).toBe(true);
          return account === ownAddress ? own : foreign;
        }),
      };
      const submission = new RingTransactionSubmission({
        first: await f.build(),
        build: f.build,
        reservation: { release: f.release, extend: f.extend },
        registry,
      });
      const transport = {
        sign: f.sign,
        send: f.send,
        status: async (): Promise<RingSubmissionStatus> => ({
          kind: "failed",
          instructionIndex: 0,
          customCode: RingProgramError.proofVerificationFailed,
        }),
      };
      await expect(submission.send(transport)).rejects.toMatchObject({ code: "CLIENT_RPC" });
      expect(f.send).toHaveBeenCalledTimes(1);
      expect(f.release).not.toHaveBeenCalled();
      missing = false;
      expect(await submission.send(transport)).toMatchObject({
        kind: "failed",
        attempts: expectedAttempts,
      });
      expect(f.send).toHaveBeenCalledTimes(expectedAttempts);
      expect(f.release).toHaveBeenCalledTimes(1);
    }
  });

  it("refuses changed retry intent before signing or sending it", async () => {
    const f = await fixture();
    const changed = await f.build();
    f.build.mockResolvedValue({ ...changed, intentHash: new Uint8Array(32).fill(1) as Bytes32 });
    await expect(
      f.submission.send({
        sign: f.sign,
        send: f.send,
        status: async () => STALE_ROOT,
      }),
    ).rejects.toMatchObject({ code: "RING_INTENT_MISMATCH" });
    expect(f.send).toHaveBeenCalledTimes(1);
    expect(f.sign).toHaveBeenCalledTimes(1);
    expect(f.release).toHaveBeenCalledTimes(1);
  });

  it("rethrows the caller's abort and keeps the signature pending", async () => {
    const f = await fixture();
    await expect(
      f.submission.send({
        sign: f.sign,
        send: async () => {
          throw new ClientError("CLIENT_ABORTED");
        },
        status: async () => ({ kind: "confirmed", slot: 1n }),
      }),
    ).rejects.toMatchObject({ code: "CLIENT_ABORTED" });
    expect(f.release).not.toHaveBeenCalled();
    expect(() => f.submission.cancel()).toThrow("RING_SUBMISSION_PENDING");
  });

  it("keeps the signature and reservation when send and status both fail", async () => {
    const f = await fixture();
    const result = await f.submission.send({
      sign: f.sign,
      send: async () => {
        throw new Error("offline");
      },
      status: async () => {
        throw new Error("offline");
      },
    });
    expect(result.kind).toBe("unknown");
    expect(f.release).not.toHaveBeenCalled();
  });

  it("retains an expired attempt when signature history fails and later resolves its signature", async () => {
    const f = await fixture();
    let available = false;
    const history = vi.fn(async () => {
      if (!available) throw new Error("history unavailable");
      return {
        context: { slot: 1_001n },
        value: [
          {
            slot: 99n,
            confirmations: 1n,
            err: null,
            confirmationStatus: "confirmed",
          },
        ],
      };
    });
    const height = vi.fn(async () => 1_000n);
    const client = kitReads({
      solanaRpc: {
        getSignatureStatuses: () => ({ send: history }),
        getBlockHeight: () => ({ send: height }),
      },
    });
    const transport: RingSubmissionTransport = {
      ...createKitRingSubmissionTransport(client, []),
      sign: f.sign,
      send: f.send,
    };
    const pending = await f.submission.send(transport);
    expect(pending).toMatchObject({ kind: "unknown", attempts: 1 });
    expect(await f.submission.send(transport)).toEqual(pending);
    expect(height).not.toHaveBeenCalled();
    expect(f.build).toHaveBeenCalledTimes(1);
    expect(f.sign).toHaveBeenCalledTimes(1);
    expect(f.send).toHaveBeenCalledTimes(1);
    expect(f.release).not.toHaveBeenCalled();
    expect(() => f.submission.cancel()).toThrow("RING_SUBMISSION_PENDING");
    available = true;
    const confirmed = await f.submission.send(transport);
    expect(confirmed).toEqual({ ...pending, kind: "confirmed", slot: 99n, firstContacts: [] });
    expect(f.send).toHaveBeenCalledTimes(1);
    expect(f.release).not.toHaveBeenCalled();
    expect(height).not.toHaveBeenCalled();
  });

  it.each([
    { shape: "empty", value: [] },
    { shape: "extra absent", value: [null, null] },
    {
      shape: "extra confirmed",
      value: [
        {
          slot: 99n,
          confirmations: 1n,
          err: null,
          confirmationStatus: "confirmed",
        },
        null,
      ],
    },
  ])("retains an expired attempt after a $shape status response", async ({ value }) => {
    const f = await fixture();
    let restored = false;
    const history = vi.fn(async () => ({
      context: { slot: 1_001n },
      value: restored ? [null] : value,
    }));
    const height = vi.fn(async () => 1_000n);
    const client = kitReads({
      solanaRpc: {
        getSignatureStatuses: () => ({ send: history }),
        getBlockHeight: () => ({ send: height }),
      },
    });
    const transport: RingSubmissionTransport = {
      ...createKitRingSubmissionTransport(client, []),
      sign: f.sign,
      send: f.send,
    };
    const pending = await f.submission.send(transport);
    expect(pending).toMatchObject({ kind: "unknown", attempts: 1 });
    expect(await f.submission.send(transport)).toEqual(pending);
    expect(height).not.toHaveBeenCalled();
    expect(f.build).toHaveBeenCalledTimes(1);
    expect(f.sign).toHaveBeenCalledTimes(1);
    expect(f.send).toHaveBeenCalledTimes(1);
    expect(f.release).not.toHaveBeenCalled();
    expect(() => f.submission.cancel()).toThrow("RING_SUBMISSION_PENDING");
    restored = true;
    expect(await f.submission.send(transport)).toMatchObject({
      attempts: 3,
      kind: "failed",
    });
    expect(height).toHaveBeenCalledTimes(3);
    expect(history).toHaveBeenCalledTimes(8);
    expect(f.send).toHaveBeenCalledTimes(3);
    expect(f.release).toHaveBeenCalledTimes(1);
  });

  it.each([
    { outcome: "confirmed", err: null },
    { outcome: "failed", err: { InstructionError: [1, { Custom: 8143 }] } },
  ])(
    "observes a $outcome transaction that lands during the expiry check",
    async ({ outcome, err }) => {
      const f = await fixture();
      let expired = false;
      const history = vi.fn(async () => ({
        context: { slot: expired ? 101n : 100n },
        value: [
          expired
            ? {
                slot: 100n,
                confirmations: 1n,
                err,
                confirmationStatus: "confirmed",
              }
            : null,
        ],
      }));
      const height = vi.fn(async () => {
        expired = true;
        return 101n;
      });
      const client = kitReads({
        solanaRpc: {
          getSignatureStatuses: () => ({ send: history }),
          getBlockHeight: () => ({ send: height }),
        },
      });
      const result = await f.submission.send({
        ...createKitRingSubmissionTransport(client, []),
        sign: f.sign,
        send: f.send,
      });
      expect(result).toMatchObject(
        outcome === "confirmed"
          ? { kind: "confirmed", slot: 100n, attempts: 1 }
          : {
              kind: "failed",
              instructionIndex: 1,
              customCode: 8143,
              attempts: 1,
            },
      );
      expect(history).toHaveBeenCalledTimes(2);
      expect(height).toHaveBeenCalledTimes(1);
      expect(f.sign).toHaveBeenCalledTimes(1);
      expect(f.send).toHaveBeenCalledTimes(1);
      expect(f.build).toHaveBeenCalledTimes(1);
      expect(f.release).toHaveBeenCalledTimes(outcome === "confirmed" ? 0 : 1);
    },
  );

  it.each(["unavailable", "empty", "extra"] as const)(
    "retains the original attempt when the post-expiry history is %s",
    async (condition) => {
      const f = await fixture();
      let expired = false;
      let resolved = false;
      const history = vi.fn(async () => {
        if (expired && !resolved && condition === "unavailable")
          throw new Error("history unavailable");
        return {
          context: { slot: 101n },
          value: resolved
            ? [
                {
                  slot: 100n,
                  confirmations: 1n,
                  err: null,
                  confirmationStatus: "confirmed",
                },
              ]
            : expired
              ? condition === "extra"
                ? [null, null]
                : []
              : [null],
        };
      });
      const height = vi.fn(async () => {
        expired = true;
        return 101n;
      });
      const client = kitReads({
        solanaRpc: {
          getSignatureStatuses: () => ({ send: history }),
          getBlockHeight: () => ({ send: height }),
        },
      });
      const transport: RingSubmissionTransport = {
        ...createKitRingSubmissionTransport(client, []),
        sign: f.sign,
        send: f.send,
      };
      const pending = await f.submission.send(transport);
      expect(pending).toMatchObject({ kind: "unknown", attempts: 1 });
      expect(history).toHaveBeenCalledTimes(2);
      expect(height).toHaveBeenCalledTimes(1);
      expect(f.release).not.toHaveBeenCalled();
      expect(() => f.submission.cancel()).toThrow("RING_SUBMISSION_PENDING");
      resolved = true;
      expect(await f.submission.send(transport)).toEqual({
        ...pending,
        kind: "confirmed",
        slot: 100n,
        firstContacts: [],
      });
      expect(f.sign).toHaveBeenCalledTimes(1);
      expect(f.send).toHaveBeenCalledTimes(1);
      expect(f.build).toHaveBeenCalledTimes(1);
      expect(f.release).not.toHaveBeenCalled();
      expect(height).toHaveBeenCalledTimes(1);
    },
  );
});
