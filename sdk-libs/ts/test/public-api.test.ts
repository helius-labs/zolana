import { AccountRole, address, type TransactionSigner } from "@solana/kit";
import { describe, expect, it } from "vitest";

import {
  DEFAULT_TREE_ADDRESS,
  SHIELDED_POOL_PROGRAM_ID,
  ShieldedKeypair,
  SOL_MINT,
  USER_REGISTRY_PROGRAM_ID,
  Wallet,
  createZolanaClient,
} from "../src/index.js";
import {
  getProtocolConfigAddress,
  getSplAssetRegistryAddress,
  getZoneConfigAddress,
} from "../src/addresses.js";
import { getCreateTreeInstructionAsync, getDepositInstruction } from "../src/instructions.js";
import { InstructionTag, type Bytes31, type Bytes32 } from "../src/interface/index.js";

const OWNER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const ZONE = address("8qbHbw2BbbTHBW1sbeqakYXV9q2RZ1R6MUi6nEZa6wJk");

describe("public package surface", () => {
  it("creates the one configured client and initializes protocol crypto", async () => {
    const client = await createZolanaClient({
      rpcUrl: "http://127.0.0.1:8899",
      indexerUrl: "http://127.0.0.1:8784",
      proverUrl: "http://127.0.0.1:3001",
    });
    expect(client.tree).toBe(DEFAULT_TREE_ADDRESS);
    expect(client.commitment).toBe("confirmed");
  });

  it("exposes only the objects needed for the common wallet flow", () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    expect(wallet.identity).toEqual(keypair.shieldedAddress());
    expect(SOL_MINT).toBe("11111111111111111111111111111111");
    expect(SHIELDED_POOL_PROGRAM_ID).toBe("sppzgEd25DF4PC1FgNerLWVZndUAV82LV9Dy5yCvRVA");
    expect(USER_REGISTRY_PROGRAM_ID).toBe("EXM6UUA56UJySzRDCx4dKwN6Xdcrkq3kmizqgZwgwNEc");
  });
});

describe("address and instruction builders", () => {
  it("derives protocol and zone addresses without RPC calls", async () => {
    const [protocol, registry, zoneConfig] = await Promise.all([
      getProtocolConfigAddress(),
      getSplAssetRegistryAddress(OWNER),
      getZoneConfigAddress(ZONE),
    ]);
    expect(new Set([protocol, registry, zoneConfig[0]]).size).toBe(3);
    expect(zoneConfig[1]).toBeTypeOf("number");
  });

  it("uses Kit account roles and canonical program addresses", async () => {
    const authority = { address: OWNER } as TransactionSigner;
    const instruction = await getCreateTreeInstructionAsync({
      authority,
      tree: DEFAULT_TREE_ADDRESS,
    });
    expect(instruction.programAddress).toBe(SHIELDED_POOL_PROGRAM_ID);
    expect(instruction.data).toEqual(Uint8Array.of(InstructionTag.createTree));
    expect(instruction.accounts?.map((account) => account.role)).toEqual([
      AccountRole.READONLY_SIGNER,
      AccountRole.READONLY,
      AccountRole.WRITABLE,
    ]);
    expect(instruction.accounts?.[0]).toMatchObject({ signer: authority });
  });

  it("builds a fixed-layout deposit instruction", () => {
    const instruction = getDepositInstruction({
      tree: DEFAULT_TREE_ADDRESS,
      depositor: OWNER,
      data: {
        viewTag: new Uint8Array(32).fill(1) as Bytes32,
        owner: new Uint8Array(32).fill(2) as Bytes32,
        blinding: new Uint8Array(31).fill(3) as Bytes31,
        amount: 42n,
      },
    });
    expect(instruction.data?.[0]).toBe(InstructionTag.deposit);
    expect(instruction.accounts).toHaveLength(6);
    expect(instruction.programAddress).toBe(SHIELDED_POOL_PROGRAM_ID);
  });
});
