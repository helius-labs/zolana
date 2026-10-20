import { describe, expect, it } from "vitest";

import { address, getAddressEncoder } from "@solana/kit";

import type { ChainReader } from "../src/client/index.js";
import type { ProgramAccount } from "../src/client/rpc.js";
import { USER_REGISTRY_PROGRAM_ID } from "../src/interface/program.js";
import type { Address } from "../src/interface/types.js";
import {
  decodeUserRecordAccount,
  fetchViewingKeyOwners,
  viewingKeyIndex,
} from "../src/wallet/registry.js";
import { accountReads } from "./helpers/clients.js";

const FIRST = address("7xKqmYUZ7pQHXcQnaZaZzR1oPjQb8kk8gA7XN3XxKzKq");
const SECOND = address("3DzKPyV33som4oRrXKA46xe47cQryGN7AdkYXA3wg2WP");
const addressEncoder = getAddressEncoder();

/** `1 || owner || bump || nullifier || viewing || merging`. */
function recordData(owner: Address, viewingPublicKey: Uint8Array): Uint8Array {
  const data = new Uint8Array(100);
  data[0] = 1;
  data.set(addressEncoder.encode(owner), 1);
  data[33] = 254;
  data.set(new Uint8Array(32).fill(3), 34);
  data.set(viewingPublicKey, 66);
  return data;
}

function record(owner: Address, viewingPublicKey: Uint8Array): ProgramAccount {
  return {
    address: owner,
    account: {
      owner: USER_REGISTRY_PROGRAM_ID,
      data: recordData(owner, viewingPublicKey),
      lamports: 1n,
    },
  };
}

function listing(accounts: readonly ProgramAccount[]): Pick<ChainReader, "getProgramAccounts"> {
  return accountReads({
    getProgramAccounts: async (programId: Address) => {
      expect(programId).toBe(USER_REGISTRY_PROGRAM_ID);
      return accounts;
    },
  });
}

describe("registry viewing key index", () => {
  it("indexes every readable record to its owner", async () => {
    const first = new Uint8Array(33).fill(7);
    const second = new Uint8Array(33).fill(8);
    const unreadable: ProgramAccount = {
      address: FIRST,
      account: { owner: USER_REGISTRY_PROGRAM_ID, data: new Uint8Array(100), lamports: 1n },
    };

    const owners = await fetchViewingKeyOwners({
      rpc: listing([record(FIRST, first), record(SECOND, second), unreadable]),
    });

    // The record the discriminator rejects names no owner, the rest do.
    expect(owners.size).toBe(2);
    expect(owners.get(viewingKeyIndex(first))).toBe(FIRST);
    expect(owners.get(viewingKeyIndex(second))).toBe(SECOND);
  });
  it("rejects a record of any other size", () => {
    const account = record(FIRST, new Uint8Array(33).fill(7)).account;
    expect(decodeUserRecordAccount(account).owner).toBe(FIRST);
    for (const length of [99, 101, 134]) {
      const data = new Uint8Array(length);
      data.set(account.data.subarray(0, Math.min(length, account.data.length)));
      expect(() => decodeUserRecordAccount({ ...account, data })).toThrow(
        "WALLET_INVALID_USER_RECORD",
      );
    }
  });
});
