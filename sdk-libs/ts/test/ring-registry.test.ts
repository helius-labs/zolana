import {
  address,
  getAddressEncoder,
  getBase64Decoder,
  SolanaError,
  SOLANA_ERROR__JSON_RPC__METHOD_NOT_FOUND,
  type Base64EncodedBytes,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { decodeRingConfig } from "../src/interface/accounts.js";
import { StateDiscriminator } from "../src/interface/state.js";
import { listRegisteredRings } from "../src/ring/registry.js";
import { kitReads } from "./helpers/clients.js";

const base64Decoder = getBase64Decoder();
const addressEncoder = getAddressEncoder();

const AUTHORITY = address("54XGz8UVJaGpwba1nxsNC4AfVZ6Uiue6J9cymVSv2Qpu");
const RING_PROGRAM = address("8QqsEqz1ff1YYt6hH7VNq6VVzq5TGWQ66bkdtrALbhn6");
const CONFIG_PDA = address("CFXxaVUTKtHr4yrL7zxWbeP9E2dcB15a7cwuVG1hGHP");

/** The account exactly as the program lays it out: 1 + 32 + 32 + 1 + 1 + 1 + 1. */
function ringConfigAccount(
  options: {
    enabled?: boolean;
    paused?: boolean;
    activated?: boolean;
    bump?: number;
  } = {},
): Uint8Array {
  return Uint8Array.from([
    StateDiscriminator.ringConfig,
    ...addressEncoder.encode(AUTHORITY),
    ...addressEncoder.encode(RING_PROGRAM),
    options.enabled ? 1 : 0,
    options.paused ? 1 : 0,
    (options.activated ?? true) ? 1 : 0,
    options.bump ?? 255,
  ]);
}

describe("ring config account", () => {
  it("reads the account the program actually writes", () => {
    // 69 bytes: the three flags run enabled, paused, activated, then the bump.
    // An earlier decoder was one byte short and read the bump out of the
    // adjacent flag, so it threw on every real account.
    const bytes = ringConfigAccount({ enabled: true, paused: false, bump: 255 });
    expect(bytes).toHaveLength(69);

    const config = decodeRingConfig(bytes);
    expect(config).toEqual({
      authority: AUTHORITY,
      programId: RING_PROGRAM,
      ringAuthorityTransactIsEnabled: true,
      paused: false,
      activated: true,
      bump: 255,
    });
  });

  it("does not confuse the trailing flags with the bump", () => {
    // The flags and the bump are adjacent, so reading one for another decodes
    // without error and reports the wrong thing.
    const paused = decodeRingConfig(ringConfigAccount({ paused: true, bump: 254 }));
    expect(paused.paused).toBe(true);
    expect(paused.activated).toBe(true);
    expect(paused.bump).toBe(254);

    const inert = decodeRingConfig(ringConfigAccount({ activated: false, bump: 253 }));
    expect(inert.activated).toBe(false);
    expect(inert.paused).toBe(false);
    expect(inert.bump).toBe(253);
  });
});

describe("listRegisteredRings", () => {
  function reader(accounts: readonly { pubkey: string; data: Uint8Array }[]) {
    const send = vi.fn(async () =>
      accounts.map((entry) => ({
        pubkey: entry.pubkey,
        account: {
          data: [base64Decoder.decode(entry.data) as Base64EncodedBytes, "base64"],
          executable: false,
          lamports: 0n,
          owner: address("sppXZU59VoYodv9Accs4hHNTjYiuYmDFyFVjUjPxFsG"),
          rentEpoch: 0n,
          space: BigInt(entry.data.length),
        },
      })),
    );
    const getProgramAccounts = vi.fn((_programId: unknown, _config: unknown) => ({ send }));
    return {
      rpc: kitReads({ solanaRpc: { getProgramAccounts }, commitment: "confirmed" }),
      getProgramAccounts,
    };
  }

  it("asks the pool for ring configs only", async () => {
    const { rpc, getProgramAccounts } = reader([]);

    // An empty list means the pool has no rings, and only that: every way of
    // failing to read the registry throws instead.
    expect(await listRegisteredRings(rpc)).toEqual([]);

    const [programId, config] = getProgramAccounts.mock.calls[0] ?? [];
    expect(programId).toBe("sppXZU59VoYodv9Accs4hHNTjYiuYmDFyFVjUjPxFsG");
    // Filtered at the RPC: the pool also holds trees and asset registries, and
    // an unfiltered scan would download all of them to find a handful of rings.
    expect(config).toMatchObject({
      filters: [{ dataSize: 69n }, { memcmp: { offset: 0n } }],
    });
  });

  it("returns a ring's program, which is what a utxo names", async () => {
    const { rpc } = reader([
      { pubkey: CONFIG_PDA, data: ringConfigAccount({ enabled: true, paused: true }) },
    ]);

    const rings = await listRegisteredRings(rpc);

    expect(rings).toEqual([
      {
        configAddress: CONFIG_PDA,
        programId: RING_PROGRAM,
        authority: AUTHORITY,
        ringAuthorityTransactIsEnabled: true,
        // A paused ring is still listed: a wallet holding balance there needs
        // to see where it is, and a depositor filters deliberately. The same
        // goes for an unactivated one.
        paused: true,
        activated: true,
      },
    ]);
  });

  it("refuses a record it cannot read rather than returning a shorter list", async () => {
    // The filters already asked for ring configs and nothing else, so a record
    // that is not one means the RPC did not honour the query -- the accounts
    // that did decode are no more trustworthy than the one that did not, and a
    // wallet must not read the answer as "the pool has one ring".
    const { rpc } = reader([
      { pubkey: CONFIG_PDA, data: Uint8Array.of(StateDiscriminator.ringConfig, 1, 2) },
      { pubkey: CONFIG_PDA, data: ringConfigAccount() },
    ]);

    await expect(listRegisteredRings(rpc)).rejects.toMatchObject({
      code: "CLIENT_INVALID_RPC_RESPONSE",
      details: {
        method: "getProgramAccounts",
        path: "$.result[0].account.data",
        expected: 69,
        actual: 3,
      },
    });
  });

  it("reports an RPC that refuses the scan instead of reporting no rings", async () => {
    // Some providers do not serve getProgramAccounts. An empty list here would
    // tell a wallet the pool has no rings registered at all.
    const send = vi.fn(async () => {
      throw new SolanaError(SOLANA_ERROR__JSON_RPC__METHOD_NOT_FOUND, {
        __serverMessage: "method not found",
      });
    });
    const rpc = kitReads({
      solanaRpc: { getProgramAccounts: vi.fn(() => ({ send })) },
      commitment: "confirmed",
    });

    await expect(listRegisteredRings(rpc)).rejects.toMatchObject({
      code: "CLIENT_UNSUPPORTED_RPC_METHOD",
      details: { method: "getProgramAccounts" },
    });
  });
});
