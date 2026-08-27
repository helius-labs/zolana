import { address, getBase64Decoder, type Base64EncodedBytes } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { decodeRingConfig } from "../src/interface/accounts.js";
import { StateDiscriminator } from "../src/interface/state.js";
import { listRegisteredRings } from "../src/ring/registry.js";

const base64Decoder = getBase64Decoder();

const AUTHORITY = address("54XGz8UVJaGpwba1nxsNC4AfVZ6Uiue6J9cymVSv2Qpu");
const RING_PROGRAM = address("8QqsEqz1ff1YYt6hH7VNq6VVzq5TGWQ66bkdtrALbhn6");
const CONFIG_PDA = address("CFXxaVUTKtHr4yrL7zxWbeP9E2dcB15a7cwuVG1hGHP");

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function decodeBase58(value: string): Uint8Array {
  let numeric = 0n;
  for (const character of value) {
    const digit = ALPHABET.indexOf(character);
    if (digit < 0) throw new Error(`not base58: ${character}`);
    numeric = numeric * 58n + BigInt(digit);
  }
  const body: number[] = [];
  while (numeric > 0n) {
    body.unshift(Number(numeric & 0xffn));
    numeric >>= 8n;
  }
  const leadingZeroes = value.length - value.replace(/^1+/, "").length;
  return Uint8Array.from([...Array.from<number>({ length: leadingZeroes }).fill(0), ...body]);
}

/** The account exactly as the program lays it out: 1 + 32 + 32 + 1 + 1 + 1. */
function ringConfigAccount(
  options: { enabled?: boolean; paused?: boolean; bump?: number } = {},
): Uint8Array {
  return Uint8Array.from([
    StateDiscriminator.ringConfig,
    ...decodeBase58(AUTHORITY),
    ...decodeBase58(RING_PROGRAM),
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
      rpc: { solanaRpc: { getProgramAccounts }, commitment: "confirmed" },
      getProgramAccounts,
    };
  }

  it("asks the pool for ring configs only", async () => {
    const { rpc, getProgramAccounts } = reader([]);

    await listRegisteredRings(rpc as never);

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

    const rings = await listRegisteredRings(rpc as never);

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

  it("skips a record it cannot read rather than losing the rest", async () => {
    const { rpc } = reader([
      { pubkey: CONFIG_PDA, data: Uint8Array.of(StateDiscriminator.ringConfig, 1, 2) },
      { pubkey: CONFIG_PDA, data: ringConfigAccount() },
    ]);

    const rings = await listRegisteredRings(rpc as never);

    expect(rings).toHaveLength(1);
    expect(rings[0]?.programId).toBe(RING_PROGRAM);
  });
});
