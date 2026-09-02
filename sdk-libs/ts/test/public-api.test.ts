import {
  AccountRole,
  address,
  assertIsFullySignedTransaction,
  getAddressEncoder,
  getProgramDerivedAddress,
  type Blockhash,
  type TransactionSigner,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { EncryptedScheme, decodeOutputData } from "../src/transaction/index.js";
// The encoder stays internal; only the decoders are needed by a relayed client.
import { encodeOutputData } from "../src/transaction/serialization/index.js";
import {
  SHIELDED_POOL_PROGRAM_ID,
  ShieldedKeypair,
  SigningKey,
  SOL_MINT,
  SPL_TOKEN_2022_PROGRAM_ID,
  SPL_TOKEN_PROGRAM_ID,
  USER_REGISTRY_PROGRAM_ID,
  ViewingKey,
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
  getTreeAddress,
} from "../src/addresses.js";
import {
  getCreateAssociatedTokenAccountInstructionAsync,
  getCreateSplInterfaceInstructionAsync,
  getCreateTreeInstructionsAsync,
  getDepositInstructionAsync,
  getTransactInstructionAsync,
  DepositAsset,
} from "../src/instructions.js";
import {
  InstructionTag,
  NULLIFIER_TREE_HEIGHT,
  NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE,
  NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
  NULLIFIER_TREE_ROOT_HISTORY_CAPACITY,
  STATE_ROOT_OFFSET,
  TREE_ACCOUNT_SIZE,
  TREE_ALLOCATION_STEP,
  TREE_CREATION_STEP_COUNT,
  nullifierTreeParams,
  type Bytes16,
  type Bytes32,
  type Bytes33,
  type Bytes64,
} from "../src/interface/index.js";
import { treeWithBump } from "../src/interface/pda/index.js";
import { internalUserRecordPda } from "../src/wallet/registry.js";

const OWNER = address("4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi");
const TREE = getTreeAddress(0);
const SYSTEM = address("11111111111111111111111111111111");
const BLOCKHASH = "11111111111111111111111111111111" as Blockhash;

async function kitTreePda(treeId: number) {
  const seed = new Uint8Array(2);
  new DataView(seed.buffer).setUint16(0, treeId, true);
  return getProgramDerivedAddress({
    programAddress: SHIELDED_POOL_PROGRAM_ID,
    seeds: [new TextEncoder().encode("tree"), seed],
  });
}

describe("public package surface", () => {
  it("creates the default client and initializes protocol crypto", async () => {
    const client = await createZolanaClient();
    expect(client.tree).toBe(TREE);
    expect(client.commitment).toBe("confirmed");
    expect(client.solanaRpc).toBeDefined();
    expect(client.proveTransact).toBeTypeOf("function");
    expect("rpc" in client).toBe(false);
    expect(client.proveRingTransact).toBeTypeOf("function");
    expect(client.proveCustomRing).toBeTypeOf("function");
  });

  it("exposes only the objects needed for the common wallet flow", () => {
    const keypair = ShieldedKeypair.generate();
    const wallet = new Wallet({ identity: keypair.shieldedAddress() });
    expect(ShieldedKeypair).not.toHaveProperty("fromEd25519");
    expect(SigningKey).not.toHaveProperty("fromBytes");
    expect(SigningKey.fromP256Bytes).toBeTypeOf("function");
    expect(ViewingKey).not.toHaveProperty("fromSeed");
    expect(wallet.identity).toEqual(keypair.shieldedAddress());
    expect(SOL_MINT).toBe("11111111111111111111111111111111");
    expect(TREE).toBe("7XD1LF7FMhd8Na9yG86wfMjGhAHsjipc2LCHRtciEjtE");
    expect(SHIELDED_POOL_PROGRAM_ID).toBe("sppXZU59VoYodv9Accs4hHNTjYiuYmDFyFVjUjPxFsG");
    expect(USER_REGISTRY_PROGRAM_ID).toBe("regyS5rkAcw2YzDJCmTwCTHs2s246FXxbmuRZ42u2PD");
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
    const keypair = ShieldedKeypair.fromKeypair(
      SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(9) as Bytes32),
    );
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
        tree: TREE,
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
          tree: TREE,
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
          tree: TREE,
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

  it("keeps the ring instruction surface in the ring entry point only", async () => {
    const [ring, ...others] = await Promise.all([
      import("../src/ring.js"),
      import("../src/index.js"),
      import("../src/client/index.js"),
      import("../src/addresses.js"),
      import("../src/instructions.js"),
      import("../src/interface/index.js"),
      import("../src/transaction/index.js"),
    ]);
    for (const name of [
      "ringConfigAddress",
      "createRingConfigInstruction",
      "initSppRingConfigInstruction",
      "ringTransactInstruction",
      "proveCustomRingTransfer",
    ] as const) {
      expect(ring[name]).toBeTypeOf("function");
      for (const other of others) expect(other).not.toHaveProperty(name);
    }
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
    const current = ShieldedKeypair.fromKeypair(
      SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(2) as Bytes32),
    ).shieldedAddress();
    const replacement = ShieldedKeypair.fromKeypair(
      SigningKey.fromEd25519Bytes(new Uint8Array(32).fill(1) as Bytes32),
    );
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

  it("derives tree PDAs the way Rust pda::tree does", async () => {
    // Rust: `Pubkey::find_program_address(&[b"tree", &tree_id.to_le_bytes()], &program_id)`.
    expect(treeWithBump(0)).toEqual([TREE, 254]);
    expect(treeWithBump(0)).toEqual(await kitTreePda(0));
    expect(treeWithBump(1)).toEqual(await kitTreePda(1));
    expect(treeWithBump(7)).toEqual([address("AA1StGw39a5tcHovwUhoZkn89mr2SsSrVTuQdE5KfYoZ"), 255]);
    expect(getTreeAddress(7 << 8)).not.toBe(getTreeAddress(7));
    expect(() => getTreeAddress(0x1_0000)).toThrow();
  });

  it("splits tree creation into one step per allocation chunk", async () => {
    expect(nullifierTreeParams()).toEqual({
      inputQueueBatchSize: NULLIFIER_TREE_INPUT_QUEUE_BATCH_SIZE,
      inputQueueZkpBatchSize: NULLIFIER_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
      height: NULLIFIER_TREE_HEIGHT,
    });
    expect(NULLIFIER_TREE_ROOT_HISTORY_CAPACITY).toBe(120);
    expect(TREE_ACCOUNT_SIZE).toBe(34_856);
    expect(TREE_CREATION_STEP_COUNT).toBe(Math.ceil(TREE_ACCOUNT_SIZE / TREE_ALLOCATION_STEP));
    expect(TREE_CREATION_STEP_COUNT).toBe(4);
    expect(STATE_ROOT_OFFSET).toBe(80);

    const payer = { address: OWNER } as TransactionSigner;
    const authority = { address: SYSTEM } as TransactionSigner;
    const steps = await getCreateTreeInstructionsAsync({ payer, authority, treeId: 0 });
    expect(steps).toHaveLength(TREE_CREATION_STEP_COUNT);
    for (const step of steps) expect(step).toEqual(steps[0]);

    const [step] = steps;
    expect(step?.programAddress).toBe(SHIELDED_POOL_PROGRAM_ID);
    expect(step?.accounts?.map((account) => [account.address, account.role])).toEqual([
      [OWNER, AccountRole.WRITABLE_SIGNER],
      [SYSTEM, AccountRole.READONLY_SIGNER],
      [await getProtocolConfigAddress(), AccountRole.WRITABLE],
      [TREE, AccountRole.WRITABLE],
      [SYSTEM, AccountRole.READONLY],
    ]);
    expect(step?.accounts?.[0]).toMatchObject({ signer: payer });
    expect(step?.accounts?.[1]).toMatchObject({ signer: authority });
    // tag, tree_id u16, batch size u64, zkp batch size u64, height u32, then the
    // at-cost fee schedule for 250: fee_per_nullifier 190, append 5000, close 170.
    expect(step?.data).toEqual(
      Uint8Array.of(
        InstructionTag.createTree,
        0,
        0,
        48,
        117,
        0,
        0,
        0,
        0,
        0,
        0,
        250,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        40,
        0,
        0,
        0,
        190,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        136,
        19,
        0,
        0,
        0,
        0,
        0,
        0,
        170,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
      ),
    );
  });

  it("encodes custom tree parameters and binds the PDA to the tree id", async () => {
    const [step] = await getCreateTreeInstructionsAsync({
      payer: OWNER,
      authority: OWNER,
      treeId: 0x0102,
      nullifierTreeParams: {
        inputQueueBatchSize: 1n,
        inputQueueZkpBatchSize: 2n,
        height: 3,
      },
    });
    expect(step?.accounts?.[3]?.address).toBe(getTreeAddress(0x0102));
    // ceil((5000 + 2 * 170) / 2) = 2670 lamports per nullifier for a ZKP batch of 2.
    expect(step?.data).toEqual(
      Uint8Array.of(
        InstructionTag.createTree,
        2,
        1,
        1,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        2,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
        3,
        0,
        0,
        0,
        110,
        10,
        0,
        0,
        0,
        0,
        0,
        0,
        136,
        19,
        0,
        0,
        0,
        0,
        0,
        0,
        170,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
      ),
    );
  });

  it("builds a deposit instruction", async () => {
    expect(DepositAsset.sol).toBeTypeOf("function");
    const depositor = { address: OWNER } as TransactionSigner;
    const instruction = await getDepositInstructionAsync({
      tree: TREE,
      depositor,
      deposits: [
        {
          asset: DepositAsset.sol(),
          viewTag: new Uint8Array(32).fill(1) as Bytes32,
          recipientOwnerHash: new Uint8Array(32).fill(2) as Bytes32,
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
      getAssociatedTokenAddress(OWNER, TREE),
      getAssociatedTokenAddress(OWNER, TREE, SPL_TOKEN_2022_PROGRAM_ID),
      getCreateSplInterfaceInstructionAsync({
        authority,
        mint: TREE,
        tokenProgram: SPL_TOKEN_2022_PROGRAM_ID,
      }),
      getCreateAssociatedTokenAccountInstructionAsync({
        payer: authority,
        owner: OWNER,
        mint: TREE,
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
          mint: TREE,
          tokenProgram: null,
        })
      ).accounts?.at(-1)?.address,
    ).toBe(SPL_TOKEN_PROGRAM_ID);
  });

  it("keeps input and output trees explicit in the transact builder", async () => {
    const payer = { address: OWNER } as TransactionSigner;
    const instruction = await getTransactInstructionAsync({
      payer,
      inputTree: TREE,
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
      address: TREE,
      role: AccountRole.WRITABLE,
    });
    expect(instruction.accounts?.[2]).toMatchObject({
      address: OWNER,
      role: AccountRole.WRITABLE,
    });
  });
});

describe("relayed decryption surface", () => {
  it("exports the plaintext decoders through @heliuslabs/zolana/transaction", async () => {
    // `syncWallet` decrypts and decodes in one step and needs the viewing key in
    // this process. A client whose viewing key is held remotely -- an enclave,
    // an HSM -- gets plaintext back and still has to read it, so the decoders
    // have to be reachable on their own. They live in the serialization barrel;
    // this asserts the outer entry point forwards them.
    const transaction = await import("../src/transaction/index.js");

    for (const name of [
      "decodeOutputData",
      "decodeConfidential",
      "decodeAnonymousRecipient",
      "decodeAnonymousSender",
      "decodeSplitBundle",
      "decodeSplitEncrypted",
      "decodePlaintextTransfer",
      "decodeProofless",
      "decodeData",
    ]) {
      expect(transaction, name).toHaveProperty(name);
      expect(typeof (transaction as Record<string, unknown>)[name]).toBe("function");
    }
  });

  it("names the scheme of a slot payload and hands back the body to decrypt", () => {
    // The header is not encrypted; decrypting the framed payload whole would
    // feed the discriminator bytes to the cipher and return garbage. A relayed
    // client has to split the frame before it sends anything to be decrypted.
    const body = Uint8Array.from([1, 2, 3, 4]);
    const framed = encodeOutputData(EncryptedScheme.ringConfidential, body);
    const frame = decodeOutputData(framed);

    expect(frame.scheme).toBe(EncryptedScheme.ringConfidential);
    expect(frame.body).toEqual(body);
    expect(frame.body.length).toBeLessThan(framed.length);
  });
});
