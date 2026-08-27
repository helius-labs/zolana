import { getBase64Decoder, getBase64Encoder, type Base64EncodedBytes } from "@solana/kit";

import type { ZolanaClient } from "../client/client.js";
import { ClientError } from "../client/error.js";
import { runKitRpc } from "../client/kit.js";
import { decodeRingConfig } from "../interface/accounts.js";
import { SHIELDED_POOL_PROGRAM_ID } from "../interface/program.js";
import { StateDiscriminator } from "../interface/state.js";
import type { Address, RequestContext } from "../interface/types.js";

const base64Decoder = getBase64Decoder();
const base64Encoder = getBase64Encoder();

/** Size of a `RingConfig` account: 1 + 32 + 32 + 1 + 1 + 1. */
const RING_CONFIG_SIZE = 68n;

/** One ring the shielded pool has a config for. */
export interface RegisteredRing {
  /** The config account, a PDA of the pool derived from the ring program. */
  readonly configAddress: Address;
  /** The ring's own program. This is what a utxo's `ringProgramId` names. */
  readonly programId: Address;
  readonly authority: Address;
  readonly ringAuthorityTransactIsEnabled: boolean;
  /** Every operational ring instruction is refused while this is set. */
  readonly paused: boolean;
}

type RingRegistryReader = Pick<ZolanaClient, "solanaRpc" | "commitment">;

/**
 * Every ring registered with the shielded pool.
 *
 * A ring's own config lives under its own program, so rings cannot be
 * enumerated from there -- each one is a separate program and you would have to
 * know its address already. The pool keeps a config of its own per ring, and
 * the pool is a single known program, so that side is the directory.
 *
 * This is the list to offer a depositor. A paused ring still appears: hiding it
 * would leave a wallet holding balance there unable to see where it is, and a
 * caller choosing a deposit target should filter on `paused` deliberately.
 *
 * The list is complete or the call throws, so an empty array means the pool has
 * no rings registered and never that the registry could not be read. An RPC
 * that refuses `getProgramAccounts`, which some providers do, raises
 * `CLIENT_UNSUPPORTED_RPC_METHOD`; a returned account that does not decode
 * raises `CLIENT_INVALID_RPC_RESPONSE`, because the size and discriminator
 * filters already asked for ring configs and nothing else, so a record that is
 * not one means the response did not honour the query and the accounts that did
 * decode are no more trustworthy than the one that did not. A caller that would
 * rather degrade than fail catches the `ClientError` and decides for itself
 * what an unreadable registry should show.
 *
 * The size filter pins this to the current `RingConfig` layout: a program that
 * changes the account's size needs `RING_CONFIG_SIZE` changed with it, or rings
 * written in the new layout stop being listed.
 */
export async function listRegisteredRings(
  rpc: RingRegistryReader,
  context?: RequestContext,
): Promise<readonly RegisteredRing[]> {
  const accounts = await runKitRpc("getProgramAccounts", context, (abortSignal) =>
    rpc.solanaRpc
      .getProgramAccounts(SHIELDED_POOL_PROGRAM_ID, {
        commitment: rpc.commitment,
        encoding: "base64",
        // Filtered at the RPC: the pool holds trees and asset registries too,
        // and a client-side scan would download all of them to find a few.
        filters: [
          { dataSize: RING_CONFIG_SIZE },
          {
            memcmp: {
              offset: 0n,
              encoding: "base64",
              bytes: base64Decoder.decode(
                Uint8Array.of(StateDiscriminator.ringConfig),
              ) as Base64EncodedBytes,
            },
          },
        ],
      })
      .send({ abortSignal }),
  );

  const rings: RegisteredRing[] = [];
  for (const [index, { pubkey, account }] of accounts.entries()) {
    const data = new Uint8Array(base64Encoder.encode(account.data[0]));
    let config;
    try {
      config = decodeRingConfig(data);
    } catch (cause) {
      // Only reachable when the RPC returned an account the filters excluded,
      // so the listing is reported as unreadable rather than silently short.
      throw new ClientError("CLIENT_INVALID_RPC_RESPONSE", {
        details: {
          method: "getProgramAccounts",
          path: `$.result[${index}].account.data`,
          expected: Number(RING_CONFIG_SIZE),
          actual: data.length,
        },
        cause,
      });
    }
    rings.push(
      Object.freeze({
        configAddress: pubkey,
        programId: config.programId,
        authority: config.authority,
        ringAuthorityTransactIsEnabled: config.ringAuthorityTransactIsEnabled,
        paused: config.paused,
      }),
    );
  }
  return Object.freeze(rings);
}
