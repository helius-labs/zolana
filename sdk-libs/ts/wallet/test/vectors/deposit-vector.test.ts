import { readFileSync } from "node:fs";

import type { Rpc } from "@zolana/client";
import { type Address, type Bytes31, type Bytes32 } from "@zolana/interface";
import { SOL_MINT } from "@zolana/transaction";
import { describe, expect, it } from "vitest";

import { Deposit, buildDepositTransaction } from "../../src/index.js";
import { base58, hexBytes, walletFixture } from "../helpers/fixtures.js";

interface Fixture {
  readonly inputs: Readonly<{
    amount: string;
    blindingBytes: string;
    memoBytes: string;
    ownerBytes: string;
    viewTagBytes: string;
  }>;
  readonly expected: Readonly<{
    instruction: Readonly<{
      dataBytes: string;
      programId: Address;
      accounts: readonly Readonly<{
        address: Address;
        signer: boolean;
        writable: boolean;
      }>[];
    }>;
  }>;
}

const bytes = (hex: string): Uint8Array =>
  Uint8Array.from(hex.match(/../g)?.map((pair) => Number.parseInt(pair, 16)) ?? []);
const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
const readBytes = readFileSync as unknown as (path: URL) => Uint8Array;
const readText = readFileSync as unknown as (path: URL, encoding: "utf8") => string;

describe("wallet deposit vector", () => {
  it("verifies the manifest hash and preserves the frozen instruction behavior", async () => {
    const fixtureUrl = new URL("../../../fixtures/workflows/deposit-v1.json", import.meta.url);
    const manifestUrl = new URL("../../../fixtures/manifest.json", import.meta.url);
    const fixtureBytes = readBytes(fixtureUrl);
    const manifest = JSON.parse(readText(manifestUrl, "utf8")) as {
      files: readonly Readonly<{ path: string; sha256: string }>[];
    };
    const entry = manifest.files.find(
      (candidate) => candidate.path === "workflows/deposit-v1.json",
    );
    expect(entry).toBeDefined();
    const digest = await globalThis.crypto.subtle.digest("SHA-256", Uint8Array.from(fixtureBytes));
    expect(hex(new Uint8Array(digest))).toBe(entry?.sha256);

    const fixture = JSON.parse(new TextDecoder().decode(fixtureBytes)) as Fixture;
    const deposit = new Deposit({
      data: {
        amount: BigInt(fixture.inputs.amount),
        blinding: bytes(fixture.inputs.blindingBytes) as Bytes31,
        memo: bytes(fixture.inputs.memoBytes),
        owner: bytes(fixture.inputs.ownerBytes) as Bytes32,
        viewTag: bytes(fixture.inputs.viewTagBytes) as Bytes32,
      },
      utxoHash: new Uint8Array(32) as Bytes32,
      asset: SOL_MINT,
    });
    const [tree, depositor] = fixture.expected.instruction.accounts;
    if (tree === undefined || depositor === undefined) throw new Error("invalid fixture accounts");
    const instruction = deposit.instruction(tree.address, depositor.address);
    expect(instruction.programAddress).toBe(fixture.expected.instruction.programId);
    expect(hex(instruction.data)).toBe(fixture.expected.instruction.dataBytes);
    expect(instruction.accounts).toEqual(
      fixture.expected.instruction.accounts.map((account) => ({
        address: account.address,
        isSigner: account.signer,
        isWritable: account.writable,
      })),
    );
  });

  it("matches the wallet deposit instruction and unsigned message oracle", async () => {
    const fixture = await walletFixture<{
      inputs: { amount: string; payer: Address; tree: Address };
      expected: {
        sol: {
          blindingBytes: string;
          ownerBytes: string;
          utxoHashBytes: string;
          viewTagBytes: string;
          instruction: Fixture["expected"]["instruction"];
          unsignedTransaction: { messageBytes: string };
        };
      };
    }>("deposit");
    const expected = fixture.expected.sol;
    const deposit = new Deposit({
      data: {
        amount: BigInt(fixture.inputs.amount),
        blinding: hexBytes(expected.blindingBytes) as Bytes31,
        memo: new TextEncoder().encode("wallet fixture"),
        owner: hexBytes(expected.ownerBytes) as Bytes32,
        viewTag: hexBytes(expected.viewTagBytes) as Bytes32,
      },
      utxoHash: hexBytes(expected.utxoHashBytes) as Bytes32,
      asset: SOL_MINT,
    });
    const instruction = deposit.instruction(fixture.inputs.tree, fixture.inputs.payer);
    expect(hex(instruction.data)).toBe(expected.instruction.dataBytes);
    expect(instruction.accounts).toEqual(
      expected.instruction.accounts.map((account) => ({
        address: account.address,
        isSigner: account.signer,
        isWritable: account.writable,
      })),
    );
    const unsupported = (): Promise<never> => Promise.reject(new Error("unexpected RPC call"));
    const rpc: Rpc = {
      getAccount: unsupported,
      getMultipleAccounts: unsupported,
      getBalance: unsupported,
      getLatestBlockhash: () =>
        Promise.resolve({
          blockhash: base58(new Uint8Array(32).fill(32)),
          lastValidBlockHeight: 1n,
        }),
      sendTransaction: unsupported,
      confirmTransaction: unsupported,
      transactOutputViewTags: unsupported,
      getMerkleProofs: unsupported,
      getNonInclusionProofs: unsupported,
      getInputMerkleProofs: unsupported,
    };
    const transaction = await buildDepositTransaction({
      rpc,
      payer: fixture.inputs.payer,
      tree: fixture.inputs.tree,
      depositor: fixture.inputs.payer,
      deposit,
    });
    expect(hex(transaction.messageBytes)).toBe(expected.unsignedTransaction.messageBytes);
  });
});
