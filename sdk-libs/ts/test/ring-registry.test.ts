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
import type { KitRpcAccess } from "../src/client/index.js";
import { listRegisteredRings } from "../src/ring/registry.js";

const base64Decoder = getBase64Decoder();
const addressEncoder = getAddressEncoder();

const AUTHORITY = address("54XGz8UVJaGpwba1nxsNC4AfVZ6Uiue6J9cymVSv2Qpu");
const RING_PROGRAM = address("8QqsEqz1ff1YYt6hH7VNq6VVzq5TGWQ66bkdtrALbhn6");
const CONFIG_PDA = address("CFXxaVUTKtHr4yrL7zxWbeP9E2dcB15a7cwuVG1hGHP");

/** The account exactly as the program lays it out: 1 + 32 + 32 + 1 + 1 + 1. */
function ringConfigAccount(
  options: { enabled?: boolean; paused?: boolean; bump?: number } = {},
): Uint8Array {
  return Uint8Array.from([
    StateDiscriminator.ringConfig,
    ...addressEncoder.encode(AUTHORITY),
    ...addressEncoder.encode(RING_PROGRAM),
    options.enabled ? 1 : 0,
    options.paused ? 1 : 0,
    options.bump ?? 255,
  ]);
}

describe("ring config account", () => {
  it("reads the account the program actually writes", () => {
    // 68 bytes, with `paused` between the enable flag and the bump. An earlier
    // decoder expected 67 and read the bump out of the paused byte, so it threw
    // on every real account -- 26 of them exist on devnet, all 68 bytes.
    const bytes = ringConfigAccount({ enabled: true, paused: false, bump: 255 });
    expect(bytes).toHaveLength(68);

    const config = decodeRingConfig(bytes);
    expect(config).toEqual({
      authority: AUTHORITY,
      programId: RING_PROGRAM,
      ringAuthorityTransactIsEnabled: true,
      paused: false,
      bump: 255,
    });
  });

  it("does not confuse the paused flag with the bump", () => {
    // The two are adjacent, so reading one for the other decodes without error
    // and reports the wrong thing.
    const paused = decodeRingConfig(ringConfigAccount({ paused: true, bump: 254 }));
    expect(paused.paused).toBe(true);
    expect(paused.bump).toBe(254);
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
    const getProgramAccounts = vi.fn(() => ({ send }));
    return {
      rpc: { solanaRpc: { getProgramAccounts }, commitment: "confirmed" } as object as KitRpcAccess,
      getProgramAccounts,
    };
  }

  it("asks the pool for ring configs only", async () => {
    const { rpc, getProgramAccounts } = reader([]);

    // An empty list means the pool has no rings, and only that: every way of
    // failing to read the registry throws instead.
    expect(await listRegisteredRings(rpc)).toEqual([]);

    const call = getProgramAccounts.mock.calls[0];
    const [programId, config] = call as unknown as [string, unknown];
    expect(programId).toBe("sppXZU59VoYodv9Accs4hHNTjYiuYmDFyFVjUjPxFsG");
    // Filtered at the RPC: the pool also holds trees and asset registries, and
    // an unfiltered scan would download all of them to find a handful of rings.
    expect(config).toMatchObject({
      filters: [{ dataSize: 68n }, { memcmp: { offset: 0n } }],
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
        // to see where it is, and a depositor filters deliberately.
        paused: true,
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
        expected: 68,
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
    const rpc = {
      solanaRpc: { getProgramAccounts: vi.fn(() => ({ send })) },
      commitment: "confirmed",
    } as object as KitRpcAccess;

    await expect(listRegisteredRings(rpc)).rejects.toMatchObject({
      code: "CLIENT_UNSUPPORTED_RPC_METHOD",
      details: { method: "getProgramAccounts" },
    });
  });
});
