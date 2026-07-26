import type { Address, Instruction, Signature, Transaction } from "@zolana/interface";
import { describe, expect, it, vi } from "vitest";

import fixture from "../../../vectors/solana-rpc-reads-v1.json" with { type: "json" };
import { ClientError, SolanaRpc, createAndSendTransaction } from "../../src/index.js";
import type { Rpc, RpcAccount } from "../../src/index.js";

/**
 * Replays `xtask/src/bin/solana-rpc-reads.rs`. The generator points a real Rust
 * `SolanaRpc` at a recording listener, so `request` is the JSON body Rust put on
 * the wire and `decoded` is what it read back out of `response`.
 */

interface Read {
  readonly id: string;
  readonly request: { readonly method: string; readonly params: unknown };
  readonly response: unknown;
  readonly decoded: unknown;
}

const READS = fixture.reads as readonly Read[];

function readCase(id: string): Read {
  const entry = READS.find((value) => value.id === id);
  if (entry === undefined) throw new Error(`missing oracle read ${id}`);
  return entry;
}

/** Answers with the recorded response and captures the request Rust recorded. */
function recordingRpc(read: Read): Readonly<{ rpc: SolanaRpc; sent: unknown[] }> {
  const sent: unknown[] = [];
  const rpc = new SolanaRpc({
    url: "https://solana.example.test",
    fetch: vi.fn((_url: URL | RequestInfo, init?: RequestInit) => {
      const body: unknown = JSON.parse(typeof init?.body === "string" ? init.body : "null");
      sent.push(body);
      const response = read.response as { readonly result: unknown };
      return Promise.resolve(
        Response.json({ jsonrpc: "2.0", id: requestId(body), result: response.result }),
      );
    }),
  });
  return { rpc, sent };
}

function requestId(body: unknown): unknown {
  return typeof body === "object" && body !== null ? (body as Record<string, unknown>)["id"] : 0;
}

/** The request minus its id, which each client numbers on its own. */
function wire(body: unknown): Readonly<{ method: unknown; params: unknown }> {
  const request = body as Record<string, unknown>;
  expect(request["jsonrpc"]).toBe("2.0");
  return { method: request["method"], params: request["params"] ?? null };
}

function signatureOf(read: Read): Signature {
  const [signatures] = read.request.params as readonly (readonly Signature[])[];
  const signature = signatures?.[0];
  if (signature === undefined) throw new Error(`oracle read ${read.id} carries no signature`);
  return signature;
}

function expectMatchesOracle(read: Read, sent: readonly unknown[]): void {
  expect(sent).toHaveLength(1);
  expect(wire(sent[0])).toEqual({ method: read.request.method, params: read.request.params });
}

describe("plain Solana reads against the Rust wire", () => {
  it("getSlot sends and decodes what Rust does", async () => {
    const read = readCase("getSlot");
    const { rpc, sent } = recordingRpc(read);

    await expect(rpc.getSlot()).resolves.toBe(BigInt(read.decoded as string));
    expectMatchesOracle(read, sent);
  });

  it("getBlockHeight sends and decodes what Rust does", async () => {
    const read = readCase("getBlockHeight");
    const { rpc, sent } = recordingRpc(read);

    await expect(rpc.getBlockHeight()).resolves.toBe(BigInt(read.decoded as string));
    expectMatchesOracle(read, sent);
  });

  it("getMinimumBalanceForRentExemption sends the length alone, as Rust does", async () => {
    const read = readCase("getMinimumBalanceForRentExemption");
    const { rpc, sent } = recordingRpc(read);
    const [dataLength] = read.request.params as readonly number[];

    await expect(rpc.getMinimumBalanceForRentExemption(dataLength ?? 0)).resolves.toBe(
      BigInt(read.decoded as string),
    );
    expectMatchesOracle(read, sent);
  });

  it('getHealth sends no parameter list and resolves on "ok"', async () => {
    const read = readCase("getHealth");
    const { rpc, sent } = recordingRpc(read);

    await expect(rpc.getHealth()).resolves.toBeUndefined();
    expect(read.decoded).toBe(true);
    expectMatchesOracle(read, sent);
  });

  it("getSignatureStatuses sends the signatures alone and maps a missing status to undefined", async () => {
    const read = readCase("getSignatureStatuses");
    const { rpc, sent } = recordingRpc(read);
    const [signatures] = read.request.params as readonly (readonly Signature[])[];
    const expected = read.decoded as readonly (Readonly<{
      slot: string;
      confirmations: number | null;
      confirmationStatus: string | null;
      ok: boolean;
    }> | null)[];

    const statuses = await rpc.getSignatureStatuses(signatures ?? []);

    expectMatchesOracle(read, sent);
    expect(statuses).toHaveLength(expected.length);
    expected.forEach((entry, index) => {
      const status = statuses[index];
      if (entry === null) {
        expect(status).toBeUndefined();
        return;
      }
      expect(status?.slot).toBe(BigInt(entry.slot));
      expect(status?.confirmations).toBe(entry.confirmations ?? undefined);
      expect(status?.confirmationStatus).toBe(entry.confirmationStatus ?? undefined);
      expect(status?.err).toBeUndefined();
    });
  });

  /**
   * A pinned divergence rather than a parity claim, and not C03's to settle.
   * Rust's `confirm_transaction` asks only for the recent status cache, so a
   * signature that has aged out of it reads as unconfirmed; the port asks the
   * node to search transaction history, so the same signature reads as
   * confirmed. Both answers agree for anything recent enough to be worth
   * confirming, which is why no existing test noticed.
   */
  it("asks for transaction history where Rust does not", async () => {
    const read = readCase("confirmTransaction");
    const { rpc, sent } = recordingRpc(read);

    await expect(rpc.confirmTransaction(signatureOf(read))).resolves.toBe(read.decoded);
    expect(wire(sent[0]).method).toBe(read.request.method);
    expect(read.request.params).toEqual([[signatureOf(read)]]);
    expect(wire(sent[0]).params).toEqual([[signatureOf(read)], { searchTransactionHistory: true }]);
  });

  it("rejects an unhealthy node rather than resolving", async () => {
    const read = readCase("getHealth");
    const rpc = new SolanaRpc({
      url: "https://solana.example.test",
      fetch: vi.fn(() =>
        Promise.resolve(Response.json({ jsonrpc: "2.0", id: 1, result: "behind" })),
      ),
    });
    void read;

    await expect(rpc.getHealth()).rejects.toBeInstanceOf(ClientError);
  });

  it("refuses a signature-status list of the wrong length", async () => {
    const rpc = new SolanaRpc({
      url: "https://solana.example.test",
      fetch: vi.fn(() =>
        Promise.resolve(
          Response.json({ jsonrpc: "2.0", id: 1, result: { context: { slot: 1 }, value: [] } }),
        ),
      ),
    });
    const [signatures] = readCase("getSignatureStatuses").request.params as readonly (
      readonly Signature[] | undefined
    )[];

    await expect(rpc.getSignatureStatuses(signatures ?? [])).rejects.toMatchObject({
      code: "CLIENT_INVALID_RPC_RESPONSE",
    });
  });
});

const BUILD = fixture.createAndSendTransaction;

function oracleInstructions(): readonly Instruction[] {
  return BUILD.instructions.map((instruction) =>
    Object.freeze({
      programAddress: instruction.programAddress as Address,
      accounts: Object.freeze(
        instruction.accounts.map((account) =>
          Object.freeze({
            address: account.address as Address,
            isSigner: account.isSigner,
            isWritable: account.isWritable,
          }),
        ),
      ),
      data: hexBytes(instruction.data),
    }),
  );
}

function hexBytes(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** The two methods `create_and_send_transaction`'s Rust body calls, and no more. */
function buildRpc(): Readonly<{ rpc: Rpc; sent: Transaction[] }> {
  const sent: Transaction[] = [];
  const unsupported = (): never => {
    throw new Error("createAndSendTransaction reached an unexpected method");
  };
  const rpc: Rpc = {
    getLatestBlockhash: () =>
      Promise.resolve(Object.freeze({ blockhash: BUILD.blockhash, lastValidBlockHeight: 1n })),
    sendTransaction: (transaction) => {
      sent.push(transaction);
      return Promise.resolve(BUILD.signature as Signature);
    },
    getAccount: (): Promise<RpcAccount | undefined> => unsupported(),
    getMultipleAccounts: unsupported,
    getBalance: unsupported,
    confirmTransaction: unsupported,
    transactOutputViewTags: unsupported,
    getMerkleProofs: unsupported,
    getNonInclusionProofs: unsupported,
    getInputMerkleProofs: unsupported,
  };
  return { rpc, sent };
}

describe("createAndSendTransaction against the Rust default body", () => {
  it("compiles the message Rust compiles and sends what the signer returned", async () => {
    const { rpc, sent } = buildRpc();
    const handed: Transaction[] = [];

    const signature = await createAndSendTransaction({
      rpc,
      feePayer: BUILD.feePayer as Address,
      instructions: oracleInstructions(),
      sign: (transaction) => {
        handed.push(transaction);
        return Promise.resolve(
          Object.freeze({
            messageBytes: transaction.messageBytes,
            signatures: Object.freeze(
              transaction.signatures.map(() => BUILD.signature as Signature),
            ),
          }),
        );
      },
    });

    expect(signature).toBe(BUILD.signature);
    expect(hex(handed[0]?.messageBytes ?? new Uint8Array())).toBe(BUILD.messageBytes);
    expect(handed[0]?.signatures).toHaveLength(BUILD.signatureCount);
    expect(sent).toHaveLength(1);
    expect(sent[0]?.signatures).toEqual([BUILD.signature]);
  });

  it("refuses to send a transaction the signer left a slot empty in", async () => {
    const { rpc, sent } = buildRpc();

    await expect(
      createAndSendTransaction({
        rpc,
        feePayer: BUILD.feePayer as Address,
        instructions: oracleInstructions(),
        sign: (transaction) => Promise.resolve(transaction),
      }),
    ).rejects.toMatchObject({
      code: "CLIENT_INCOMPLETE_SIGNATURES",
      details: { required: BUILD.signatureCount, provided: BUILD.signatureCount, missingIndex: 0 },
    });
    expect(sent).toHaveLength(0);
  });
});
