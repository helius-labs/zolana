import {
  AccountRole,
  address,
  assertIsFullySignedTransaction,
  getAddressEncoder,
  type Blockhash,
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
  buildDepositTransaction,
  buildRegistrationTransaction,
  buildSetMergingEnabledTransaction,
  createZolanaClient,
} from "../src/index.js";
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
const BLOCKHASH = "11111111111111111111111111111111" as Blockhash;

describe("public package surface", () => {
  it("creates the one configured client and initializes protocol crypto", async () => {
    const client = await createZolanaClient({
      solanaRpcUrl: "http://127.0.0.1:8899",
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

  it("exposes build-only actions and removes submission wrappers", async () => {
    const sdk = await import("../src/index.js");
    expect(sdk.buildDepositTransaction).toBeTypeOf("function");
    expect(sdk.buildTransferTransaction).toBeTypeOf("function");
    expect(sdk.buildWithdrawalTransaction).toBeTypeOf("function");
    expect(sdk.buildSplitTransaction).toBeTypeOf("function");
    expect(sdk.buildMergeTransaction).toBeTypeOf("function");
    expect(sdk).not.toHaveProperty("deposit");
    expect(sdk).not.toHaveProperty("transfer");
    expect(sdk).not.toHaveProperty("withdraw");
    expect(sdk).not.toHaveProperty("split");
    expect(sdk).not.toHaveProperty("merge");
    expect(sdk).not.toHaveProperty("signPrivateTransaction");
  });

  it("resolves a registered Solana deposit recipient through the public builder", async () => {
    const keypair = ShieldedKeypair.fromEd25519(new Uint8Array(32).fill(9) as Bytes32, 0);
    const recipient = keypair.shieldedAddress().solanaAddress();
    const pda = await internalUserRecordPda(recipient);
    const data = Uint8Array.of(
      1,
      ...getAddressEncoder().encode(recipient),
      pda.bump,
      0,
      ...keypair.nullifierPublicKey(),
      ...keypair.viewingPublicKey().toBytes(),
      0,
    );
    const getAccount = vi.fn(async () => ({
      owner: USER_REGISTRY_PROGRAM_ID,
      data,
      lamports: 1n,
    }));
    const getLatestBlockhash = vi.fn(async () => ({
      blockhash: BLOCKHASH,
      lastValidBlockHeight: 1n,
    }));

    const transaction = await buildDepositTransaction({
      client: {
        tree: DEFAULT_TREE_ADDRESS,
        getAccount,
        getLatestBlockhash,
      } as never,
      feePayer: OWNER,
      recipient,
      amount: 42n,
    });

    expect(getAccount).toHaveBeenCalledOnce();
    expect(getLatestBlockhash).toHaveBeenCalledOnce();
    expect(Object.keys(transaction.signatures)).toEqual([OWNER]);
  });

  it("rejects an unregistered Solana deposit recipient before blockhash lookup", async () => {
    const getAccount = vi.fn(async () => undefined);
    const getLatestBlockhash = vi.fn(async () => ({
      blockhash: BLOCKHASH,
      lastValidBlockHeight: 1n,
    }));

    await expect(
      buildDepositTransaction({
        client: {
          tree: DEFAULT_TREE_ADDRESS,
          getAccount,
          getLatestBlockhash,
        } as never,
        feePayer: OWNER,
        recipient: OWNER,
        amount: 42n,
      }),
    ).rejects.toMatchObject({
      code: "WALLET_RECIPIENT_NOT_REGISTERED",
      details: { recipient: OWNER },
    });
    expect(getAccount).toHaveBeenCalledOnce();
    expect(getLatestBlockhash).not.toHaveBeenCalled();
  });

  it("bypasses registry lookup for a direct shielded deposit recipient", async () => {
    const getAccount = vi.fn(async () => undefined);
    const getLatestBlockhash = vi.fn(async () => ({
      blockhash: BLOCKHASH,
      lastValidBlockHeight: 1n,
    }));

    await expect(
      buildDepositTransaction({
        client: {
          tree: DEFAULT_TREE_ADDRESS,
          getAccount,
          getLatestBlockhash,
        } as never,
        feePayer: OWNER,
        recipient: ShieldedKeypair.generate().shieldedAddress(),
        amount: 42n,
      }),
    ).resolves.toBeDefined();
    expect(getAccount).not.toHaveBeenCalled();
    expect(getLatestBlockhash).toHaveBeenCalledOnce();
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

  it("builds the merging opt-in as an unsigned transaction", async () => {
    const transaction = await buildSetMergingEnabledTransaction({
      client: {
        getLatestBlockhash: vi.fn(async () => ({
          blockhash: BLOCKHASH,
          lastValidBlockHeight: 1n,
        })),
      },
      owner: OWNER,
      enabled: true,
    });

    expect(() => assertIsFullySignedTransaction(transaction)).toThrow();
    expect(Object.keys(transaction.signatures)).toEqual([OWNER]);
  });

  it("builds a key update without signing or sending it", async () => {
    const seed = new Uint8Array(32).fill(1) as Bytes32;
    const current = ShieldedKeypair.fromEd25519(seed, 1).shieldedAddress();
    const replacement = ShieldedKeypair.fromEd25519(seed, 0);
    const owner = replacement.shieldedAddress().solanaAddress();
    const pda = await internalUserRecordPda(owner);
    const data = Uint8Array.of(
      1,
      ...getAddressEncoder().encode(owner),
      pda.bump,
      0,
      ...current.nullifierPublicKey,
      ...current.viewingPublicKey.toBytes(),
      0,
    );
    const transaction = await buildRegistrationTransaction({
      client: {
        getAccount: vi.fn(async () => ({ owner: USER_REGISTRY_PROGRAM_ID, data, lamports: 1n })),
        getLatestBlockhash: vi.fn(async () => ({
          blockhash: BLOCKHASH,
          lastValidBlockHeight: 1n,
        })),
      },
      owner,
      address: replacement.shieldedAddress(),
    });

    expect(transaction).toBeDefined();
    expect(() => assertIsFullySignedTransaction(transaction!)).toThrow();
    expect(Object.keys(transaction!.signatures)).toEqual([owner]);
  });

  it("rejects P256 registration before building or reading RPC state", async () => {
    const getAccount = vi.fn(async () => undefined);
    const getLatestBlockhash = vi.fn(async () => ({
      blockhash: BLOCKHASH,
      lastValidBlockHeight: 1n,
    }));

    await expect(
      buildRegistrationTransaction({
        client: { getAccount, getLatestBlockhash },
        owner: OWNER,
        address: ShieldedKeypair.generate("p256").shieldedAddress(),
      }),
    ).rejects.toMatchObject({ code: "WALLET_P256_REGISTRATION_UNSUPPORTED" });
    expect(getAccount).not.toHaveBeenCalled();
    expect(getLatestBlockhash).not.toHaveBeenCalled();
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
