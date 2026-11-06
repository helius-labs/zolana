import { getMintDecoder, getMintSize } from "@solana-program/token";

import type { ChainReader } from "../client/ports.js";
import type { RpcAccount } from "../client/rpc.js";
import { SPL_TOKEN_2022_PROGRAM_ID, SPL_TOKEN_PROGRAM_ID } from "../interface/program.js";
import type { Address, RequestContext } from "../interface/types.js";
import { SOL_MINT } from "../transaction/asset.js";

import { WalletError } from "./error.js";

export interface AssetMetadata {
  readonly mint: Address;
  readonly decimals: number;
}

/**
 * The mint account: one that SPL Token or Token-2022 owns and that decodes as
 * an initialized mint.
 */
async function readMint(
  client: Pick<ChainReader, "getAccount">,
  mint: Address,
  context?: RequestContext,
): Promise<Readonly<{ tokenProgram: Address; decimals: number }>> {
  let account: RpcAccount | undefined;
  try {
    account = await client.getAccount(mint, context);
  } catch (cause) {
    throw new WalletError("WALLET_ASSET_METADATA", {
      details: { mint, reason: "fetch" },
      cause,
    });
  }
  if (account === undefined) {
    throw new WalletError("WALLET_ASSET_METADATA", { details: { mint, reason: "missing" } });
  }
  if (account.owner !== SPL_TOKEN_PROGRAM_ID && account.owner !== SPL_TOKEN_2022_PROGRAM_ID) {
    throw new WalletError("WALLET_ASSET_METADATA", { details: { mint, reason: "owner" } });
  }
  try {
    if (account.data.length < getMintSize()) throw new Error();
    const decoded = getMintDecoder().decode(account.data.subarray(0, getMintSize()));
    if (!decoded.isInitialized) throw new Error();
    return { tokenProgram: account.owner, decimals: decoded.decimals };
  } catch {
    throw new WalletError("WALLET_ASSET_METADATA", { details: { mint, reason: "data" } });
  }
}

export async function fetchAssetMetadata(
  client: Pick<ChainReader, "getAccount">,
  mint: Address,
  context?: RequestContext,
): Promise<AssetMetadata> {
  if (mint === SOL_MINT) return Object.freeze({ mint, decimals: 9 });
  const { decimals } = await readMint(client, mint, context);
  return Object.freeze({ mint, decimals });
}

/**
 * @internal The token program an SPL deposit or withdrawal of `asset` settles
 * through: `splTokenProgram` when the caller names it, otherwise the program
 * that owns the mint account. `undefined` for SOL.
 */
export async function resolveSplTokenProgram(
  client: Pick<ChainReader, "getAccount">,
  asset: Address,
  splTokenProgram: Address | null | undefined,
  context?: RequestContext,
): Promise<Address | undefined> {
  if (asset === SOL_MINT) return undefined;
  if (splTokenProgram !== undefined && splTokenProgram !== null) return splTokenProgram;
  return (await readMint(client, asset, context)).tokenProgram;
}

export class AssetMetadataCache {
  readonly #client: Pick<ChainReader, "getAccount">;
  readonly #entries = new Map<Address, AssetMetadata>();

  constructor(client: Pick<ChainReader, "getAccount">) {
    this.#client = client;
    this.#entries.set(SOL_MINT, Object.freeze({ mint: SOL_MINT, decimals: 9 }));
  }

  async get(mint: Address, context?: RequestContext): Promise<AssetMetadata> {
    const cached = this.#entries.get(mint);
    if (cached !== undefined) return cached;
    const metadata = await fetchAssetMetadata(this.#client, mint, context);
    this.#entries.set(mint, metadata);
    return metadata;
  }

  clear(mint?: Address): void {
    if (mint === undefined) {
      this.#entries.clear();
      this.#entries.set(SOL_MINT, Object.freeze({ mint: SOL_MINT, decimals: 9 }));
      return;
    }
    if (mint !== SOL_MINT) this.#entries.delete(mint);
  }
}
