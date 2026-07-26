import type { Signature, Transaction } from "@zolana/interface";
import { describe, expect, it, vi } from "vitest";

import fixture from "../../../vectors/solana-rpc-send-v1.json" with { type: "json" };
import { ClientError, SolanaRpc } from "../../src/index.js";
import type { SendTransactionConfig } from "../../src/index.js";

/**
 * Replays `xtask/src/bin/solana-rpc-send.rs`, which drove a real Rust
 * `SolanaRpc` through both send entry points against a recording listener.
 *
 * The recorded `sendTransaction` parameters are the point: `solana_rpc_client`
 * decides which config fields ride along, whether an unset one is omitted or
 * sent as null, and what an absent preflight commitment resolves to. None of
 * that is visible in this repository's source.
 */

interface Request {
  readonly method: string;
  readonly params: readonly unknown[];
}

interface Case {
  readonly id: string;
  readonly signature: string;
  readonly requests: readonly Request[];
}

const CASES = fixture.cases as readonly Case[];
const SIGNATURE = fixture.transaction.signature as Signature;

function oracleCase(id: string): Case {
  const entry = CASES.find((value) => value.id === id);
  if (entry === undefined) throw new Error(`missing oracle case ${id}`);
  return entry;
}

function sendParameters(oracle: Case): readonly unknown[] {
  const request = oracle.requests.find((entry) => entry.method === "sendTransaction");
  if (request === undefined) throw new Error(`oracle case ${oracle.id} sent no transaction`);
  return request.params;
}

function transaction(): Transaction {
  return Object.freeze({
    messageBytes: Uint8Array.from(
      fixture.transaction.messageBytes.match(/../g) ?? [],
      (byte) => Number.parseInt(byte, 16),
    ),
    signatures: Object.freeze([SIGNATURE]),
  });
}

/** Accepts the transaction and reports it confirmed, recording every request. */
function recordingRpc(): Readonly<{ rpc: SolanaRpc; sent: Request[] }> {
  const sent: Request[] = [];
  const rpc = new SolanaRpc({
    url: "https://solana.example.test",
    fetch: vi.fn((_url: URL | RequestInfo, init?: RequestInit) => {
      const body = JSON.parse(typeof init?.body === "string" ? init.body : "null") as Request & {
        readonly id: unknown;
      };
      sent.push({ method: body.method, params: body.params });
      return Promise.resolve(Response.json({ jsonrpc: "2.0", id: body.id, result: answer(body) }));
    }),
  });
  return { rpc, sent };
}

function answer(request: Request): unknown {
  if (request.method === "sendTransaction") return SIGNATURE;
  return {
    context: { slot: 100 },
    value: [{ slot: 99, confirmations: null, err: null, confirmationStatus: "finalized" }],
  };
}

async function sent(
  call: (rpc: SolanaRpc, tx: Transaction) => Promise<Signature>,
): Promise<readonly unknown[]> {
  const { rpc, sent: requests } = recordingRpc();
  await expect(call(rpc, transaction())).resolves.toBe(SIGNATURE);
  const request = requests.find((entry) => entry.method === "sendTransaction");
  expect(request).toBeDefined();
  return request?.params ?? [];
}

describe("sendTransaction against the Rust wire", () => {
  it("sends the config Rust's no-config entry point builds", async () => {
    const parameters = await sent((rpc, tx) => rpc.sendTransaction(tx));

    expect(parameters).toEqual(sendParameters(oracleCase("sendTransaction")));
  });

  /**
   * The default config resolves its preflight commitment to `finalized` while
   * the no-config path above resolves it to `confirmed`, because Rust fills the
   * two from different places. The port reproduces the difference rather than
   * making the two agree, so this case and the one above disagree on purpose.
   */
  it("sends the config Rust builds from a default RpcSendTransactionConfig", async () => {
    const parameters = await sent((rpc, tx) => rpc.sendTransactionWithConfig(tx, {}));

    expect(parameters).toEqual(sendParameters(oracleCase("sendTransactionWithDefaultConfig")));
    expect((parameters[1] as { preflightCommitment: string }).preflightCommitment).toBe("finalized");
  });

  it("passes every configured field through as Rust does", async () => {
    const config: SendTransactionConfig = {
      skipPreflight: true,
      preflightCommitment: "processed",
      maxRetries: 3,
      minContextSlot: 77n,
    };

    const parameters = await sent((rpc, tx) => rpc.sendTransactionWithConfig(tx, config));

    expect(parameters).toEqual(sendParameters(oracleCase("sendTransactionWithConfig")));
  });

  it("refuses a slot or retry count no JSON number can carry", async () => {
    const { rpc } = recordingRpc();

    await expect(
      rpc.sendTransactionWithConfig(transaction(), { minContextSlot: 2n ** 60n }),
    ).rejects.toMatchObject({ code: "CLIENT_INVALID_INTEGER", details: { field: "minContextSlot" } });
    await expect(
      rpc.sendTransactionWithConfig(transaction(), { maxRetries: -1 }),
    ).rejects.toBeInstanceOf(ClientError);
  });
});
