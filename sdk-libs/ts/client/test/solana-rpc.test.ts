import {
  SHIELDED_POOL_PROGRAM_ID,
  type Address,
  type Signature,
  type Transaction,
} from "@zolana/interface";
import { describe, expect, it, vi } from "vitest";

import proverFixture from "../../fixtures/client/prover-shapes-v1.json" with { type: "json" };
import rpcFixture from "../../fixtures/client/rpc-indexer-v1.json" with { type: "json" };
import { ClientError, SolanaRpc } from "../src/index.js";
import { encodeBase58 } from "../src/internal.js";
import { bytes, hex } from "./helpers/prover-vectors.js";

const ZERO_ADDRESS = "1".repeat(32) as Address;
const ZERO_SIGNATURE = "1".repeat(64) as Signature;

function rpcResult(id: number, result: unknown): Response {
  return Response.json({ jsonrpc: "2.0", id, result });
}

/// A 1x2 `TRANSACT` instruction taken from the Rust-generated prover fixture,
/// compiled against a message whose account key 0 is the shielded pool.
function transactInstruction(): Readonly<{
  programIdIndex: number;
  accounts: readonly number[];
  data: string;
}> {
  const shape = proverFixture.expected.rails[0]?.shapes.find(
    (value) => value.shape.inputs === "1" && value.shape.outputs === "2",
  );
  if (!shape) throw new Error("missing RPC fixture shape");
  return {
    programIdIndex: 0,
    accounts: [],
    data: encodeBase58(Uint8Array.from([0, ...bytes(shape.transactIxData.afterProofBytes)])),
  };
}

async function expectCode(promise: Promise<unknown>, code: string): Promise<ClientError> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(ClientError);
    expect((error as ClientError).code).toBe(code);
    return error as ClientError;
  }
  throw new Error("expected client call to fail");
}

describe("SolanaRpc", () => {
  it("sends exact JSON-RPC requests and converts integer results without precision loss", async () => {
    const fetch = vi.fn((_url: URL | RequestInfo, init?: RequestInit) => {
      expect(init?.method).toBe("POST");
      expect(init?.headers).toEqual({ "content-type": "application/json" });
      expect(JSON.parse(typeof init?.body === "string" ? init.body : "")).toEqual({
        jsonrpc: "2.0",
        id: 1,
        method: "getBalance",
        params: [ZERO_ADDRESS, { commitment: "confirmed" }],
      });
      return Promise.resolve(rpcResult(1, { value: Number.MAX_SAFE_INTEGER }));
    });
    const rpc = new SolanaRpc({ url: "https://solana.example.test", fetch });

    await expect(rpc.getBalance(ZERO_ADDRESS)).resolves.toBe(BigInt(Number.MAX_SAFE_INTEGER));
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("rejects malformed envelopes, unsafe integers, and account encoding", async () => {
    const responses = [
      Response.json({ jsonrpc: "2.0", id: 9, result: { value: 1 } }),
      rpcResult(2, { value: Number.MAX_SAFE_INTEGER + 1 }),
      rpcResult(3, {
        value: { owner: ZERO_ADDRESS, lamports: 1, data: ["AA==", "base58"] },
      }),
    ];
    const rpc = new SolanaRpc({
      url: "https://solana.example.test",
      fetch: vi.fn(() => Promise.resolve(responses.shift() ?? rpcResult(0, null))),
    });

    await expectCode(rpc.getBalance(ZERO_ADDRESS), "CLIENT_RPC_ENVELOPE");
    await expectCode(rpc.getBalance(ZERO_ADDRESS), "CLIENT_INVALID_RPC_RESPONSE");
    await expectCode(rpc.getAccount(ZERO_ADDRESS), "CLIENT_INVALID_RPC_RESPONSE");
  });

  it("decodes program-owned registry account listings", async () => {
    const fetch = vi.fn(() =>
      Promise.resolve(
        rpcResult(1, [
          {
            pubkey: ZERO_ADDRESS,
            account: {
              owner: SHIELDED_POOL_PROGRAM_ID,
              lamports: 7,
              data: ["BQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIAAAAAAAAA", "base64"],
            },
          },
        ]),
      ),
    );
    const rpc = new SolanaRpc({ url: "https://solana.example.test", fetch });
    const accounts = await rpc.getProgramAccounts(SHIELDED_POOL_PROGRAM_ID);

    expect(accounts).toHaveLength(1);
    expect(accounts[0]?.address).toBe(ZERO_ADDRESS);
    expect(accounts[0]?.account.owner).toBe(SHIELDED_POOL_PROGRAM_ID);
    expect(accounts[0]?.account.data).toHaveLength(48);
  });

  it("preserves known and unknown custom program errors", async () => {
    const responses = [7023, 7999].map((code, index) =>
      Response.json({
        jsonrpc: "2.0",
        id: index + 1,
        error: {
          code: -32002,
          message: "simulation failed",
          data: { err: { InstructionError: [3, { Custom: code }] } },
        },
      }),
    );
    const rpc = new SolanaRpc({
      url: "https://solana.example.test",
      fetch: vi.fn(() => Promise.resolve(responses.shift() ?? rpcResult(0, null))),
    });

    const known = await expectCode(rpc.getBalance(ZERO_ADDRESS), "CLIENT_RPC_PROGRAM_ERROR");
    expect(known.details).toEqual({
      method: "getBalance",
      instructionIndex: 3,
      programError: { kind: "known", code: 7023, name: "BothPublicAmountsSet" },
    });
    const unknown = await expectCode(rpc.getBalance(ZERO_ADDRESS), "CLIENT_RPC_PROGRAM_ERROR");
    expect(unknown.details).toEqual({
      method: "getBalance",
      instructionIndex: 3,
      programError: { kind: "unknown", code: 7999 },
    });
  });

  it("serializes unsigned native transactions and returns only a confirmed signature", async () => {
    const methods: string[] = [];
    const fetch = vi.fn((_url: URL | RequestInfo, init?: RequestInit) => {
      const body = JSON.parse(typeof init?.body === "string" ? init.body : "") as {
        id: number;
        method: string;
        params: readonly [string, unknown];
      };
      methods.push(body.method);
      if (body.method === "sendTransaction") {
        const serialized = Uint8Array.from(globalThis.atob(body.params[0]), (character) =>
          character.charCodeAt(0),
        );
        expect(serialized).toEqual(Uint8Array.from([1, ...new Uint8Array(64), 9, 8, 7]));
        return Promise.resolve(rpcResult(body.id, ZERO_SIGNATURE));
      }
      return Promise.resolve(
        rpcResult(body.id, { value: [{ err: null, confirmationStatus: "confirmed" }] }),
      );
    });
    const rpc = new SolanaRpc({ url: "https://solana.example.test", fetch });
    const transaction: Transaction = {
      messageBytes: Uint8Array.of(9, 8, 7),
      signatures: [undefined],
    };

    await expect(rpc.sendTransaction(transaction)).resolves.toBe(ZERO_SIGNATURE);
    expect(methods).toEqual(["sendTransaction", "getSignatureStatuses"]);
  });

  it("fails a send whose signature never confirms", async () => {
    const rpc = new SolanaRpc({
      url: "https://solana.example.test",
      confirmationTimeoutMs: 0,
      fetch: vi.fn((_url: URL | RequestInfo, init?: RequestInit) => {
        const body = JSON.parse(typeof init?.body === "string" ? init.body : "") as {
          id: number;
          method: string;
        };
        return Promise.resolve(
          rpcResult(
            body.id,
            body.method === "sendTransaction" ? ZERO_SIGNATURE : { value: [null] },
          ),
        );
      }),
    });

    const failure = await expectCode(
      rpc.sendTransaction({ messageBytes: Uint8Array.of(1), signatures: [undefined] }),
      "CLIENT_CONFIRMATION_TIMEOUT",
    );
    expect(failure.details).toEqual({ signature: ZERO_SIGNATURE, attempts: 1 });
  });

  // `send_and_confirm_transaction` resubmits while it waits, so a transaction
  // the leader drops still lands. Submitting once and only polling gave up on a
  // transaction Rust confirms.
  it("resubmits a dropped transaction while waiting, as send_and_confirm does", async () => {
    vi.useFakeTimers();
    const methods: string[] = [];
    const payloads: string[] = [];
    let statusCalls = 0;
    const rpc = new SolanaRpc({
      url: "https://solana.example.test",
      confirmationTimeoutMs: 60_000,
      fetch: vi.fn((_url: URL | RequestInfo, init?: RequestInit) => {
        const body = JSON.parse(typeof init?.body === "string" ? init.body : "") as {
          id: number;
          method: string;
          params: readonly [string, unknown];
        };
        methods.push(body.method);
        if (body.method === "sendTransaction") {
          payloads.push(body.params[0]);
          return Promise.resolve(rpcResult(body.id, ZERO_SIGNATURE));
        }
        statusCalls++;
        // The first copy is dropped; only the resubmitted one confirms.
        return Promise.resolve(
          rpcResult(body.id, {
            value: [statusCalls < 3 ? null : { err: null, confirmationStatus: "confirmed" }],
          }),
        );
      }),
    });

    const pending = rpc.sendTransaction({
      messageBytes: Uint8Array.of(9, 8, 7),
      signatures: [undefined],
    });
    await vi.runAllTimersAsync();
    await expect(pending).resolves.toBe(ZERO_SIGNATURE);

    expect(methods.filter((method) => method === "sendTransaction")).toHaveLength(3);
    // Identical bytes every time, so the signature never changes.
    expect(new Set(payloads).size).toBe(1);
    vi.useRealTimers();
  });

  it("airdrops and asserts executability against confirmed state", async () => {
    const responses: Record<string, unknown> = {
      requestAirdrop: ZERO_SIGNATURE,
      getSignatureStatuses: { value: [{ err: null, confirmationStatus: "finalized" }] },
      getAccountInfo: { value: { owner: ZERO_ADDRESS, lamports: 1, executable: false } },
    };
    const rpc = new SolanaRpc({
      url: "https://solana.example.test",
      fetch: vi.fn((_url: URL | RequestInfo, init?: RequestInit) => {
        const body = JSON.parse(typeof init?.body === "string" ? init.body : "") as {
          id: number;
          method: string;
        };
        return Promise.resolve(rpcResult(body.id, responses[body.method] ?? null));
      }),
    });

    await expect(rpc.airdrop(ZERO_ADDRESS, 5n)).resolves.toBe(ZERO_SIGNATURE);
    const failure = await expectCode(rpc.assertExecutable(ZERO_ADDRESS), "CLIENT_RPC");
    expect(failure.details).toEqual({
      method: "assertExecutable",
      reason: "program is not executable",
    });
  });

  it("distinguishes cancellation from timeout", async () => {
    const fetch = vi.fn(
      (_url: URL | RequestInfo, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            reject(new DOMException("aborted", "AbortError"));
          });
        }),
    );
    const rpc = new SolanaRpc({ url: "https://solana.example.test", fetch });
    const controller = new AbortController();
    const aborted = rpc.getBalance(ZERO_ADDRESS, { signal: controller.signal });
    controller.abort();

    await expectCode(aborted, "CLIENT_ABORTED");
    await expectCode(rpc.getBalance(ZERO_ADDRESS, { timeoutMs: 1 }), "CLIENT_TIMEOUT");
  });

  it("extracts the frozen sorted tags from direct and inner transact instructions", async () => {
    const instruction = transactInstruction();
    const variants = [
      {
        transaction: {
          message: { accountKeys: [SHIELDED_POOL_PROGRAM_ID], instructions: [instruction] },
        },
        meta: { innerInstructions: [] },
      },
      {
        transaction: {
          message: {
            accountKeys: [SHIELDED_POOL_PROGRAM_ID, ZERO_ADDRESS],
            instructions: [{ programIdIndex: 1, accounts: [], data: encodeBase58(bytes("00")) }],
          },
        },
        meta: { innerInstructions: [{ index: 0, instructions: [instruction] }] },
      },
    ];
    const rpc = new SolanaRpc({
      url: "https://solana.example.test",
      fetch: vi.fn((_url: URL | RequestInfo, init?: RequestInit) => {
        const request = JSON.parse(typeof init?.body === "string" ? init.body : "") as {
          id: number;
        };
        return Promise.resolve(rpcResult(request.id, variants.shift()));
      }),
    });

    expect((await rpc.transactOutputViewTags(ZERO_SIGNATURE)).map(hex)).toEqual(
      rpcFixture.expected.confirmation.directTags,
    );
    expect((await rpc.transactOutputViewTags(ZERO_SIGNATURE)).map(hex)).toEqual(
      rpcFixture.expected.confirmation.innerTags,
    );
  });

  it("resolves program ids that only appear in the loaded address table", async () => {
    const rpc = new SolanaRpc({
      url: "https://solana.example.test",
      fetch: vi.fn(() =>
        Promise.resolve(
          rpcResult(1, {
            transaction: {
              message: {
                accountKeys: [ZERO_ADDRESS],
                instructions: [{ ...transactInstruction(), programIdIndex: 1 }],
              },
            },
            meta: {
              innerInstructions: [],
              loadedAddresses: { writable: [SHIELDED_POOL_PROGRAM_ID], readonly: [] },
            },
          }),
        ),
      ),
    });

    expect((await rpc.transactOutputViewTags(ZERO_SIGNATURE)).map(hex)).toEqual(
      rpcFixture.expected.confirmation.directTags,
    );
  });

  it("scans each group's inner instructions before the next group's outer instruction", async () => {
    const corrupt = { programIdIndex: 0, accounts: [], data: encodeBase58(Uint8Array.of(0, 1, 2)) };
    const rpc = new SolanaRpc({
      url: "https://solana.example.test",
      fetch: vi.fn(() =>
        Promise.resolve(
          rpcResult(1, {
            transaction: {
              message: {
                accountKeys: [SHIELDED_POOL_PROGRAM_ID, ZERO_ADDRESS],
                instructions: [
                  { programIdIndex: 1, accounts: [], data: encodeBase58(Uint8Array.of(9)) },
                  corrupt,
                ],
              },
            },
            meta: {
              innerInstructions: [{ index: 0, instructions: [transactInstruction()] }],
            },
          }),
        ),
      ),
    });

    expect((await rpc.transactOutputViewTags(ZERO_SIGNATURE)).map(hex)).toEqual(
      rpcFixture.expected.confirmation.directTags,
    );
  });

  it("rejects a confirmed transaction whose metadata is absent", async () => {
    const rpc = new SolanaRpc({
      url: "https://solana.example.test",
      fetch: vi.fn(() =>
        Promise.resolve(
          rpcResult(1, {
            transaction: { message: { accountKeys: [ZERO_ADDRESS], instructions: [] } },
          }),
        ),
      ),
    });

    const failure = await expectCode(
      rpc.transactOutputViewTags(ZERO_SIGNATURE),
      "CLIENT_INVALID_RPC_RESPONSE",
    );
    expect(failure.details).toEqual({ path: "result.meta" });
  });

  it("rejects a confirmed transaction without a transact instruction", async () => {
    const rpc = new SolanaRpc({
      url: "https://solana.example.test",
      fetch: vi.fn(() =>
        Promise.resolve(
          rpcResult(1, {
            transaction: { message: { accountKeys: [ZERO_ADDRESS], instructions: [] } },
            meta: { innerInstructions: [] },
          }),
        ),
      ),
    });

    await expectCode(rpc.transactOutputViewTags(ZERO_SIGNATURE), "CLIENT_RPC_TRANSACT_NOT_FOUND");
    expect(rpcFixture.expected.confirmation.missingTransactError.code).toBe("Rpc");
  });
});
