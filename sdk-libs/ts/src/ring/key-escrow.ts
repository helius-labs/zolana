import { isClientError } from "../client/error.js";
import type { CustomRingOpening, CustomRingRegistryKey } from "../client/prover/types.js";
import { hashBytes } from "../hasher/index.js";
import { UTXO_DOMAIN } from "../interface/program.js";
import type { Address, Bytes32, RequestContext } from "../interface/types.js";
import { ownerHash } from "../keypair/hash.js";
import { bytesToBigInt } from "../transaction/internal.js";
import { bytesKey, equalBytes } from "../wallet/internal.js";

import { fetchRingKeyRegistryRoot } from "./config.js";
import { RingError } from "./error.js";
import { readSealedKey, registersKey, type RingSealedKeyClient } from "./key-registry.js";
import { memberOfIdentity } from "./policy.js";
import { KEY_REGISTRY_PROJECTION_ERRORS, waitForRingProjection } from "./projection.js";

export interface RingKeyOwner {
  readonly ownerPkHash: Bytes32;
  readonly nullifierPk: Bytes32;
}

export interface RingEscrowedKeys {
  readonly root: Bytes32;
  readonly rootIndex: number;
  /** Per owner, absent for an owner that needs none. */
  readonly keys: readonly (CustomRingRegistryKey | undefined)[];
}

/** Mirrors Rust `output_keys`, the namespace owner hash binds the only zero key escrow admits. */
export function ringEscrowedOwners(
  outputs: readonly CustomRingOpening[],
  namespaceOwnerHash: Bytes32,
): readonly (RingKeyOwner | undefined)[] {
  return outputs.map((opening) =>
    bytesToBigInt(opening.domain) === BigInt(UTXO_DOMAIN) &&
    !equalBytes(ownerHash(opening.ownerPkHash, opening.nullifierPk), namespaceOwnerHash)
      ? { ownerPkHash: opening.ownerPkHash, nullifierPk: opening.nullifierPk }
      : undefined,
  );
}

/** Mirrors Rust `UnregisteredOutputKey`, refused before any prover round. */
export async function openRingEscrowedKeys(
  input: Readonly<{
    client: RingSealedKeyClient;
    ringProgramId: Address;
    /** `undefined` for a slot the circuit does not check or a namespace-owned record. */
    owners: readonly (RingKeyOwner | undefined)[];
  }>,
  context?: RequestContext,
): Promise<RingEscrowedKeys> {
  return waitForRingProjection(
    async (attemptContext) => {
      const registry = await fetchRingKeyRegistryRoot(
        input.client,
        input.ringProgramId,
        attemptContext,
      );
      const opened = new Map<string, Promise<CustomRingRegistryKey>>();
      const keys = await Promise.all(
        input.owners.map((owner) => {
          if (owner === undefined) return undefined;
          const key = `${bytesKey(owner.ownerPkHash)}:${bytesKey(owner.nullifierPk)}`;
          let open = opened.get(key);
          if (open === undefined) {
            open = openKey({ ...input, owner, registry }, attemptContext);
            opened.set(key, open);
          }
          return open;
        }),
      );
      return Object.freeze({
        root: registry.root,
        rootIndex: registry.historyCursor,
        keys: Object.freeze(keys),
      });
    },
    KEY_REGISTRY_PROJECTION_ERRORS,
    context,
  );
}

async function openKey(
  input: Readonly<{
    client: RingSealedKeyClient;
    ringProgramId: Address;
    owner: RingKeyOwner;
    registry: Parameters<typeof readSealedKey>[0]["registry"];
  }>,
  context: RequestContext,
): Promise<CustomRingRegistryKey> {
  const member = memberOfIdentity(input.owner.ownerPkHash);
  const unregistered = (cause?: unknown): RingError =>
    new RingError("RING_UNREGISTERED_OUTPUT_KEY", {
      details: { owner: bytesKey(input.owner.ownerPkHash) },
      ...(cause === undefined ? {} : { cause }),
    });
  let entry;
  try {
    entry = await readSealedKey({ ...input, member }, context);
  } catch (cause) {
    if (isClientError(cause) && cause.code === "CLIENT_KEY_REGISTRY_MEMBER_UNREGISTERED") {
      throw unregistered(cause);
    }
    throw cause;
  }
  if (!registersKey(entry, input.owner.nullifierPk)) throw unregistered();
  return Object.freeze({
    next: entry.next,
    ctHash: hashBytes(entry.sealed.ciphertext) as Bytes32,
    index: entry.index,
    path: entry.proof,
  });
}
