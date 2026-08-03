import {
  AccountRole,
  address,
  getAddressEncoder,
  type Signature,
  type TransactionSigner,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import {
  DEFAULT_TREE_ADDRESS,
  SHIELDED_POOL_PROGRAM_ID,
  ShieldedKeypair,
  SOL_MINT,
  SPL_TOKEN_2022_PROGRAM_ID,
  SPL_TOKEN_PROGRAM_ID,
  USER_REGISTRY_PROGRAM_ID,
  Wallet,
  createZolanaClient,
  ensureRegistered,
  setMergingEnabled,
} from "../src/index.js";
import type { ZolanaClient } from "../src/client/client.js";
import {
  getAssociatedTokenAddress,
  getProtocolConfigAddress,
  getSplAssetRegistryAddress,
} from "../src/addresses.js";
import {
  getCreateAssociatedTokenAccountInstructionAsync,
  getCreateSplInterfaceInstructionAsync,
  getCreateTreeInstructionAsync,
  getDepositInstructionAsync,
  getTransactInstruction,
} from "../src/instructions.js";
import {
  InstructionTag,
  type Bytes16,
  type Bytes32,
  type Bytes33,
  type Bytes64,
} from "../src/interface/index.js";
import { internalUserRecordPda } from "../src/wallet/registry.js";

const OWNER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const SIGNATURE = "1".repeat(64) as Signature;

describe("public package surface", () => {
  it("creates the one configured client and initializes protocol crypto", async () => {
    const client = await createZolanaClient({
      solanaRpcUrl: "http://127.0.0.1:8899",
      indexerUrl: "http://127.0.0.1:8784",
      proverUrl: "http://127.0.0.1:3001",
    });
    expect(client.tree).toBe(DEFAULT_TREE_ADDRESS);
    expect(client.commitment).toBe("confirmed");
    expect(client.solanaRpc).toBeDefined();
    expect(client.proveTransact).toBeTypeOf("function");
    expect("rpc" in client).toBe(false);
    expect("proveMergeZone" in client).toBe(false);
    expect("finishMergeZoneSubmissionUnsigned" in client).toBe(false);
  });

  it("exposes only the objects needed for the common wallet flow", () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    expect(wallet.identity).toEqual(keypair.shieldedAddress());
    expect(SOL_MINT).toBe("11111111111111111111111111111111");
    expect(SHIELDED_POOL_PROGRAM_ID).toBe("sppzgEd25DF4PC1FgNerLWVZndUAV82LV9Dy5yCvRVA");
    expect(USER_REGISTRY_PROGRAM_ID).toBe("EXM6UUA56UJySzRDCx4dKwN6Xdcrkq3kmizqgZwgwNEc");
  });

  it("does not expose partial zone builders", async () => {
    const [addresses, instructions, protocol, transaction] = await Promise.all([
      import("../src/addresses.js"),
      import("../src/instructions.js"),
      import("../src/interface/index.js"),
      import("../src/transaction/index.js"),
    ]);
    expect(addresses).not.toHaveProperty("getZoneConfigAddress");
    expect(instructions).not.toHaveProperty("getCreateZoneConfigInstructionAsync");
    expect(instructions).not.toHaveProperty("getUpdateZoneConfigInstruction");
    expect(instructions).not.toHaveProperty("getUpdateZoneConfigOwnerInstruction");
    expect(instructions).not.toHaveProperty("getZoneDepositInstructionAsync");
    expect(instructions).not.toHaveProperty("getZoneTransactInstructionAsync");
    expect(instructions).not.toHaveProperty("getZoneAuthorityTransactInstructionAsync");
    expect(instructions).not.toHaveProperty("getMergeZoneInstructionAsync");
    expect(transaction).not.toHaveProperty("MergeZone");
    expect(transaction).not.toHaveProperty("PreparedMergeZone");
    expect(protocol.decodeZoneConfig).toBeTypeOf("function");
  });

  it("builds the merging opt-in with the owner signer", async () => {
    const owner = { address: OWNER } as TransactionSigner;
    const signAndSendInstructions = vi.fn(
      async (_request: Parameters<ZolanaClient["signAndSendInstructions"]>[0]) => SIGNATURE,
    );

    await expect(
      setMergingEnabled({
        client: { signAndSendInstructions },
        owner,
        enabled: true,
      }),
    ).resolves.toBe(SIGNATURE);
    const request = signAndSendInstructions.mock.calls[0]?.[0];
    expect(request?.instructions[0]).toMatchObject({
      programAddress: USER_REGISTRY_PROGRAM_ID,
      data: Uint8Array.of(1, 1),
      accounts: [
        { role: AccountRole.WRITABLE },
        { address: OWNER, role: AccountRole.READONLY_SIGNER, signer: owner },
      ],
    });
  });

  it("keeps the owner read-only when updating registry keys", async () => {
    const current = ShieldedKeypair.generate().shieldedAddress();
    const replacement = ShieldedKeypair.generate();
    const pda = await internalUserRecordPda(OWNER);
    const data = Uint8Array.of(
      1,
      ...getAddressEncoder().encode(OWNER),
      pda.bump,
      0,
      ...current.nullifierPublicKey,
      ...current.viewingPublicKey.toBytes(),
      0,
    );
    const owner = { address: OWNER } as TransactionSigner;
    const signAndSendInstructions = vi.fn(
      async (_request: Parameters<ZolanaClient["signAndSendInstructions"]>[0]) => SIGNATURE,
    );

    await ensureRegistered({
      client: {
        getAccount: vi.fn(async () => ({ owner: USER_REGISTRY_PROGRAM_ID, data, lamports: 1n })),
        signAndSendInstructions,
      },
      funding: owner,
      keypair: replacement,
    });

    const instruction = signAndSendInstructions.mock.calls[0]?.[0].instructions[0];
    expect(instruction?.data?.[0]).toBe(2);
    expect(instruction).toMatchObject({
      accounts: [
        { role: AccountRole.WRITABLE },
        { address: OWNER, role: AccountRole.READONLY_SIGNER },
      ],
    });
  });
});

describe("address and instruction builders", () => {
  it("derives protocol addresses without RPC calls", async () => {
    const [protocol, registry] = await Promise.all([
      getProtocolConfigAddress(),
      getSplAssetRegistryAddress(OWNER),
    ]);
    expect(protocol).not.toBe(registry);
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

  it("builds a deposit instruction", async () => {
    const depositor = { address: OWNER } as TransactionSigner;
    const instruction = await getDepositInstructionAsync({
      tree: DEFAULT_TREE_ADDRESS,
      depositor,
      deposits: [
        {
          asset: { kind: "sol" },
          viewTag: new Uint8Array(32).fill(1) as Bytes32,
          owner: new Uint8Array(32).fill(2) as Bytes32,
          blinding: new Uint8Array(32).fill(3) as Bytes32,
          amount: 42n,
        },
      ],
    });
    expect(instruction.data?.[0]).toBe(InstructionTag.deposit);
    expect(instruction.accounts).toHaveLength(5);
    expect(instruction.programAddress).toBe(SHIELDED_POOL_PROGRAM_ID);
  });

  it("threads Token-2022 through SPL interface and ATA builders", async () => {
    const authority = { address: OWNER } as TransactionSigner;
    const [legacyAta, token2022Ata, createInterface, createAta] = await Promise.all([
      getAssociatedTokenAddress(OWNER, DEFAULT_TREE_ADDRESS),
      getAssociatedTokenAddress(OWNER, DEFAULT_TREE_ADDRESS, SPL_TOKEN_2022_PROGRAM_ID),
      getCreateSplInterfaceInstructionAsync({
        authority,
        mint: DEFAULT_TREE_ADDRESS,
        tokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
      }),
      getCreateAssociatedTokenAccountInstructionAsync({
        payer: authority,
        owner: OWNER,
        mint: DEFAULT_TREE_ADDRESS,
        tokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
      }),
    ]);

    expect(legacyAta).not.toBe(token2022Ata);
    expect(createInterface.accounts?.at(-1)?.address).toBe(SPL_TOKEN_2022_PROGRAM_ID);
    expect(
      createAta.accounts?.some((account) => account.address === SPL_TOKEN_2022_PROGRAM_ID),
    ).toBe(true);
    expect(
      (
        await getCreateSplInterfaceInstructionAsync({
          authority,
          mint: DEFAULT_TREE_ADDRESS,
          tokenProgram: null,
        })
      ).accounts?.at(-1)?.address,
    ).toBe(SPL_TOKEN_PROGRAM_ID);
  });

  it("keeps input and output trees explicit in the transact builder", () => {
    const payer = { address: OWNER } as TransactionSigner;
    const instruction = getTransactInstruction({
      payer,
      inputTree: DEFAULT_TREE_ADDRESS,
      outputTree: OWNER,
      data: {
        expiryUnixTs: 0n,
        privateTxHash: new Uint8Array(32) as Bytes32,
        circuit: {
          kind: "confidentialEddsa",
          inputs: 0,
          outputs: 0,
          publicAssetSlots: 3,
        },
        txViewingPk: new Uint8Array(33) as Bytes33,
        salt: new Uint8Array(16) as Bytes16,
        proof: {
          a: new Uint8Array(32) as Bytes32,
          b: new Uint8Array(64) as Bytes64,
          c: new Uint8Array(32) as Bytes32,
        },
        inputs: [],
        interfaceTransfers: [],
        outputs: [],
        messages: [],
      },
    });

    expect(instruction.accounts?.[1]).toMatchObject({
      address: DEFAULT_TREE_ADDRESS,
      role: AccountRole.WRITABLE,
    });
    expect(instruction.accounts?.[2]).toMatchObject({
      address: OWNER,
      role: AccountRole.WRITABLE,
    });
  });
});
