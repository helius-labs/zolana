import { address, generateKeyPairSigner, signTransactionWithSigners } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";
import type { RingSubmissionTransport } from "../src/client/ports.js";
import { compileUnsignedTransaction } from "../src/flows/compile.js";
import type { Bytes32 } from "../src/interface/types.js";
import { RingTransactionSubmission, type RingSubmissionAttempt } from "../src/ring/submission.js";
import { BLOCKHASH } from "./helpers/clients.js";

const HASH = new Uint8Array(32) as Bytes32;
const MEMO = address("MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr");

async function fixture() {
  const payer = await generateKeyPairSigner();
  let version = 0;
  const build = vi.fn(async (): Promise<RingSubmissionAttempt> => ({
    transaction: compileUnsignedTransaction({
      feePayer: payer.address,
      lifetime: BLOCKHASH,
      instructions: [{ programAddress: MEMO, data: Uint8Array.of(version++) }],
      computeUnitLimit: 1_000,
    }),
    intentHash: HASH,
    ringInstructionIndex: 0,
    window: { index: 1n, slots: 10n },
  }));
  const release = vi.fn();
  const windowChanged = vi.fn(async () => true);
  const submission = new RingTransactionSubmission({
    first: await build(),
    build,
    release,
    windowChanged,
  });
  const send = vi.fn(async () => {});
  const sign = vi.fn(async (transaction: RingSubmissionAttempt["transaction"]) =>
    signTransactionWithSigners([payer], transaction),
  );
  return { submission, build, release, windowChanged, send, sign };
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
    expect(f.release).toHaveBeenCalledTimes(1);
  });

  it("rebuilds and re-signs only after a confirmed stale-head failure, at most three times", async () => {
    const f = await fixture();
    const result = await f.submission.send({
      sign: f.sign,
      send: f.send,
      status: async () => ({ kind: "failed", instructionIndex: 0, customCode: 8166 }),
    });
    expect(result).toMatchObject({ kind: "failed", attempts: 3 });
    expect(f.build).toHaveBeenCalledTimes(3);
    expect(f.sign).toHaveBeenCalledTimes(3);
    expect(f.send).toHaveBeenCalledTimes(3);
    expect(f.release).toHaveBeenCalledTimes(1);
  });

  it("does not retry the same numeric error from a different instruction", async () => {
    const f = await fixture();
    const result = await f.submission.send({
      sign: f.sign,
      send: f.send,
      status: async () => ({ kind: "failed", instructionIndex: 1, customCode: 8166 }),
    });
    expect(result).toMatchObject({ kind: "failed", attempts: 1 });
    expect(f.build).toHaveBeenCalledTimes(1);
  });

  it("requires an actual window change before retrying a rejected policy proof", async () => {
    const f = await fixture();
    f.windowChanged.mockResolvedValue(false);
    const result = await f.submission.send({
      sign: f.sign,
      send: f.send,
      status: async () => ({ kind: "failed", instructionIndex: 0, customCode: 8101 }),
    });
    expect(result).toMatchObject({ kind: "failed", attempts: 1 });
    expect(f.windowChanged).toHaveBeenCalledTimes(1);
  });

  it("refuses changed retry intent before signing or sending it", async () => {
    const f = await fixture();
    const changed = await f.build();
    f.build.mockResolvedValue({ ...changed, intentHash: new Uint8Array(32).fill(1) as Bytes32 });
    await expect(
      f.submission.send({
        sign: f.sign,
        send: f.send,
        status: async () => ({ kind: "failed", instructionIndex: 0, customCode: 8166 }),
      }),
    ).rejects.toMatchObject({ code: "RING_INTENT_MISMATCH" });
    expect(f.send).toHaveBeenCalledTimes(1);
    expect(f.sign).toHaveBeenCalledTimes(1);
    expect(f.release).toHaveBeenCalledTimes(1);
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
});
