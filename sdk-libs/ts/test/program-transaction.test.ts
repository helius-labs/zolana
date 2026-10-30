import { address } from "@solana/kit";
import { describe, expect, expectTypeOf, it, vi } from "vitest";

import { bytesToBigInt } from "../src/interface/bytes.js";
import type { Bytes32 } from "../src/interface/index.js";
import { splInterfaceWithBump, treeAddress } from "../src/interface/pda/index.js";
import { checkedBytes, type Bytes34 } from "../src/keypair/bytes.js";
import {
  ShieldedKeypair,
  ShieldedPublicKey,
  SigningKey,
  ViewingKey,
} from "../src/keypair/index.js";
import {
  AssetRegistry,
  Data,
  LocalShieldedKeys,
  Utxo,
  bindProgramTransaction,
  createProofOutput,
  decodeProgramTransaction,
  toProgramWalletUtxo,
  type ProgramData,
  type ProgramFinalizedTransaction,
  type ProgramOwnerTag,
  type ProgramProofInputUtxo,
  type ProgramProofOutputUtxo,
  type ProgramSettlementTransfer,
  type ProgramUtxo,
  type ProgramTransaction,
  type ProgramWalletUtxo,
  type WalletUtxo,
} from "../src/transaction/index.js";
import { dummyCiphertextLength } from "../src/transaction/instructions/transact.js";
import escrowFixture from "../../program/tests/wasm/tests/fixtures/escrow.json" with { type: "json" };
import withdrawFixture from "../../program/tests/wasm/tests/fixtures/withdraw.json" with { type: "json" };

type FixtureBytes = readonly number[];

interface FixtureMint {
  readonly asset: string;
  readonly assetId: number;
}

interface FixtureData {
  readonly records: readonly Readonly<{
    kind: string;
    bytes: FixtureBytes;
  }>[];
}

interface FixtureUtxo {
  readonly owner: FixtureBytes;
  readonly asset: FixtureMint;
  readonly amount: number;
  readonly blinding: FixtureBytes;
  readonly ringProgramId?: string;
  readonly data: FixtureData;
}

interface FixtureInputUtxo {
  readonly utxo: FixtureUtxo;
  readonly nullifierPubkey: FixtureBytes;
  readonly utxoHash: FixtureBytes;
  readonly nullifier: FixtureBytes;
  readonly dataHash?: FixtureBytes;
  readonly ringDataHash?: FixtureBytes;
  readonly treeId: number;
  readonly leafIndex: number;
}

interface FixtureOutputUtxo {
  readonly asset: FixtureMint;
  readonly amount: number;
  readonly blinding: FixtureBytes;
  readonly ringProgramId?: string;
  readonly ringDataHash?: FixtureBytes;
  readonly dataHash?: FixtureBytes;
  readonly ownerAddress?: FixtureBytes;
  readonly ownerTag?: FixtureBytes;
  readonly compact?: boolean;
  readonly data: FixtureData;
}

interface FixtureOwnerTag {
  readonly kind: string;
  readonly value?: FixtureBytes;
  readonly index?: number;
}

type FixtureTransfer =
  | Readonly<{ kind: "sol"; isDeposit: boolean; amount: number; userSolAccount: string }>
  | Readonly<{
      kind: "spl";
      mint: string;
      isDeposit: boolean;
      amount: number;
      userSplToken: string;
    }>;

interface FixtureFinalizedTransaction {
  readonly inputUtxos: readonly FixtureInputUtxo[];
  readonly outputUtxos: readonly FixtureOutputUtxo[];
  readonly outputHashes: readonly FixtureBytes[];
  readonly ownerTags: readonly Readonly<{ tag: FixtureOwnerTag; resolved: FixtureBytes }>[];
  readonly interfaceTransfers: readonly FixtureTransfer[];
  readonly firstNullifier: FixtureBytes;
  readonly blindingSeed: FixtureBytes;
  readonly privateTxBlinding: FixtureBytes;
  readonly paddingIndependentPrivateTxHash: FixtureBytes;
  readonly outputTreeId: number;
  readonly payer: string;
  readonly sender: FixtureBytes;
}

interface Fixture {
  readonly sender: FixtureBytes;
  readonly payer: string;
  readonly records: Readonly<{ inputs: readonly FixtureInputUtxo[] }>;
  readonly transaction: Readonly<{ finalizedTx: FixtureFinalizedTransaction }>;
  readonly encrypted: Readonly<{
    utxoHashes: readonly FixtureBytes[];
    ownerTags: readonly FixtureOwnerTag[];
    resolvedOwnerTags: readonly FixtureBytes[];
    interfaceTransfers: readonly FixtureTransfer[];
  }>;
}

const escrow: Fixture = escrowFixture;
const withdraw: Fixture = withdrawFixture;

const FIXTURES = [
  ["escrow", escrow, escrow.records.inputs],
  ["withdraw", withdraw, withdraw.records.inputs],
] as const;

const OTHER_ADDRESS = address("SysvarRent111111111111111111111111111111111");

function bytes(value: FixtureBytes): Uint8Array {
  return Uint8Array.from(value);
}

function bytes32(value: FixtureBytes): Bytes32 {
  return checkedBytes<Bytes32>(bytes(value), 32, "fixture bytes");
}

function senderKeypair(): ShieldedKeypair {
  return ShieldedKeypair.fromKeypair(
    SigningKey.fromEd25519Bytes(checkedBytes<Bytes32>(new Uint8Array(32).fill(5), 32, "seed")),
  );
}

function programData(value: FixtureData): ProgramData {
  return {
    records: value.records.map((record) => {
      switch (record.kind) {
        case "ringData":
        case "utxoData":
        case "memo":
          return { kind: record.kind, bytes: bytes(record.bytes) };
        default:
          throw new Error("invalid fixture data record");
      }
    }),
  };
}

function programUtxo(value: FixtureUtxo): ProgramUtxo {
  return {
    owner: bytes(value.owner),
    asset: { asset: value.asset.asset, assetId: BigInt(value.asset.assetId) },
    amount: BigInt(value.amount),
    blinding: bytes(value.blinding),
    ...(value.ringProgramId === undefined ? {} : { ringProgramId: value.ringProgramId }),
    data: programData(value.data),
  };
}

function programInput(value: FixtureInputUtxo): ProgramProofInputUtxo {
  return {
    utxo: programUtxo(value.utxo),
    nullifierPubkey: bytes(value.nullifierPubkey),
    utxoHash: bytes(value.utxoHash),
    nullifier: bytes(value.nullifier),
    ...(value.dataHash === undefined ? {} : { dataHash: bytes(value.dataHash) }),
    ...(value.ringDataHash === undefined ? {} : { ringDataHash: bytes(value.ringDataHash) }),
    treeId: value.treeId,
    leafIndex: BigInt(value.leafIndex),
  };
}

function programWalletUtxo(value: FixtureInputUtxo): ProgramWalletUtxo {
  return programInput(value);
}

function programOutput(value: FixtureOutputUtxo): ProgramProofOutputUtxo {
  return {
    asset: { asset: value.asset.asset, assetId: BigInt(value.asset.assetId) },
    amount: BigInt(value.amount),
    blinding: bytes(value.blinding),
    ...(value.ringProgramId === undefined ? {} : { ringProgramId: value.ringProgramId }),
    ...(value.ringDataHash === undefined ? {} : { ringDataHash: bytes(value.ringDataHash) }),
    ...(value.dataHash === undefined ? {} : { dataHash: bytes(value.dataHash) }),
    ...(value.ownerAddress === undefined ? {} : { ownerAddress: bytes(value.ownerAddress) }),
    ...(value.ownerTag === undefined ? {} : { ownerTag: bytes(value.ownerTag) }),
    ...(value.compact === undefined ? {} : { compact: value.compact }),
    data: programData(value.data),
  };
}

function programOwnerTag(value: FixtureOwnerTag): ProgramOwnerTag {
  if (value.kind === "inline" && value.value !== undefined)
    return { kind: "inline", value: bytes(value.value) };
  if (value.kind === "account" && value.index !== undefined)
    return { kind: "account", index: value.index };
  throw new Error("invalid fixture owner tag");
}

function programTransfer(value: FixtureTransfer): ProgramSettlementTransfer {
  return value.kind === "sol"
    ? { ...value, amount: BigInt(value.amount) }
    : { ...value, amount: BigInt(value.amount) };
}

function programTransaction(value: FixtureFinalizedTransaction): ProgramFinalizedTransaction {
  return {
    inputUtxos: value.inputUtxos.map(programInput),
    outputUtxos: value.outputUtxos.map(programOutput),
    outputHashes: value.outputHashes.map(bytes),
    ownerTags: value.ownerTags.map((entry) => ({
      tag: programOwnerTag(entry.tag),
      resolved: bytes(entry.resolved),
    })),
    interfaceTransfers: value.interfaceTransfers.map(programTransfer),
    firstNullifier: bytes(value.firstNullifier),
    blindingSeed: bytes(value.blindingSeed),
    privateTxBlinding: bytes(value.privateTxBlinding),
    paddingIndependentPrivateTxHash: bytes(value.paddingIndependentPrivateTxHash),
    outputTreeId: value.outputTreeId,
    payer: value.payer,
    sender: bytes(value.sender),
  };
}

async function sdkTransfer(value: FixtureTransfer) {
  if (value.kind === "sol") {
    return {
      kind: "sol",
      isDeposit: value.isDeposit,
      amount: BigInt(value.amount),
      userSolAccount: address(value.userSolAccount),
    };
  }
  const [, splInterfaceBump] = await splInterfaceWithBump(address(value.mint));
  return {
    kind: "spl",
    mint: address(value.mint),
    isDeposit: value.isDeposit,
    amount: BigInt(value.amount),
    tokenAccount: address(value.userSplToken),
    splInterfaceBump,
  };
}

function sdkWalletUtxo(value: FixtureInputUtxo, assets: AssetRegistry): WalletUtxo {
  return {
    utxo: new Utxo({
      owner: ShieldedPublicKey.fromBytes(
        checkedBytes<Bytes34>(bytes(value.utxo.owner), 34, "fixture owner"),
      ),
      asset: assets.resolve(BigInt(value.utxo.asset.assetId)),
      amount: BigInt(value.utxo.amount),
      blinding: bytes32(value.utxo.blinding),
      data: new Data(programData(value.utxo.data).records),
      ...(value.utxo.ringProgramId === undefined
        ? {}
        : { ringProgramId: address(value.utxo.ringProgramId) }),
    }),
    outputContext: {
      hash: bytes32(value.utxoHash),
      tree: treeAddress(value.treeId),
      leafIndex: BigInt(value.leafIndex),
    },
    nullifier: bytes32(value.nullifier),
    ...(value.dataHash === undefined ? {} : { dataHash: bytes32(value.dataHash) }),
    ...(value.ringDataHash === undefined ? {} : { ringDataHash: bytes32(value.ringDataHash) }),
    spent: false,
  };
}

describe.each(FIXTURES)("the %s program transaction", (_, fixture, walletUtxos) => {
  const wasm = programTransaction(fixture.transaction.finalizedTx);

  describe("bound wasm transaction", () => {
    interface Inputs {
      readonly private: { readonly state: ProgramWalletUtxo };
      readonly public: { readonly step: bigint };
    }
    const firstInput = walletUtxos[0];
    if (firstInput === undefined) throw new Error("fixture needs a wallet UTXO");
    const inputs: Inputs = {
      private: { state: programWalletUtxo(firstInput) },
      public: { step: 1n },
    };
    const result = () => ({
      finalizedTx: programTransaction(fixture.transaction.finalizedTx),
      proofInputs: {
        opening: "17",
        public_hash: bytesToBigInt(new Uint8Array(32).fill(1)).toString(),
      },
      publicHash: new Uint8Array(32).fill(1),
    });

    it("owns prover-ready inputs without caller-specific decoding", async () => {
      const raw = result();
      const transaction = bindProgramTransaction((_inputs: Inputs) => raw, {
        assets: new AssetRegistry(),
      });
      const decoded = await transaction(inputs, bytes(fixture.sender), fixture.payer);
      raw.proofInputs.opening = "changed";
      expect(decoded.proofInputs.opening).toEqual("17");
    });

    it.each([
      null,
      {},
      { opening: null },
      { opening: "01" },
      { opening: "-1" },
      { opening: "21888242871839275222246405745257275088548364400416034343698204186575808495617" },
    ])("rejects malformed scalar inputs before encryption or proving %#", async (invalidInputs) => {
      const transaction = bindProgramTransaction(
        (_inputs: Inputs) => ({ ...result(), proofInputs: invalidInputs }),
        { assets: new AssetRegistry() },
      );
      const encrypt = vi.spyOn(ViewingKey.prototype, "encryptSlot");
      const prove = vi.fn();
      try {
        await expect(
          transaction(inputs, bytes(fixture.sender), fixture.payer).then(prove),
        ).rejects.toMatchObject({ code: "TRANSACTION_DESERIALIZE" });
        expect([encrypt.mock.calls, prove.mock.calls]).toEqual([[], []]);
      } finally {
        encrypt.mockRestore();
      }
    });

    it("binds the proof's public hash before encryption or proving", async () => {
      const raw = result();
      raw.proofInputs.public_hash = "0";
      const transaction = bindProgramTransaction((_inputs: Inputs) => raw, {
        assets: new AssetRegistry(),
      });
      const encrypt = vi.spyOn(ViewingKey.prototype, "encryptSlot");
      const prove = vi.fn();
      try {
        await expect(
          transaction(inputs, bytes(fixture.sender), fixture.payer).then(prove),
        ).rejects.toMatchObject({ code: "TRANSACTION_PROGRAM_PUBLIC_HASH_MISMATCH" });
        expect([encrypt.mock.calls, prove.mock.calls]).toEqual([[], []]);
      } finally {
        encrypt.mockRestore();
      }
    });

    it("preserves generated input types and returns a transaction ready for encryption", async () => {
      const raw = result();
      const build = vi.fn((_inputs: Inputs, _sender: Uint8Array, _payer: string) => raw);
      const assets = new AssetRegistry();
      const transaction = bindProgramTransaction(build, { assets });
      expectTypeOf(transaction).parameter(0).toEqualTypeOf<Inputs>();
      expectTypeOf<Awaited<ReturnType<typeof transaction>>>().toEqualTypeOf<ProgramTransaction>();
      const lookup = vi.spyOn(assets, "assetId");
      const resolve = vi.spyOn(assets, "resolve");
      const keys = senderKeypair();
      try {
        const {
          proofInputs,
          publicHash,
          transaction: decoded,
        } = await transaction(inputs, bytes(fixture.sender), fixture.payer);
        const encrypted = decoded.encryptWithKeys(keys);
        expect({
          args: build.mock.calls,
          proofInputs,
          publicHash,
          mints: decoded.outputs.map((output) => output.mint),
          hashes: encrypted.externalData.outputs.map((output) => output.utxoHash),
          lookups: lookup.mock.calls,
          resolutions: resolve.mock.calls,
        }).toEqual({
          args: [[inputs, bytes(fixture.sender), fixture.payer]],
          proofInputs: raw.proofInputs,
          publicHash: raw.publicHash,
          mints: raw.finalizedTx.outputUtxos.map((output) => output.asset),
          hashes: fixture.encrypted.utxoHashes.map(bytes),
          lookups: [],
          resolutions: [],
        });
      } finally {
        lookup.mockRestore();
        resolve.mockRestore();
        keys.destroy();
      }
    });

    it("owns the returned input map and hash bytes and protects the caller's sender buffer", async () => {
      const raw = result();
      const sender = bytes(fixture.sender);
      const transaction = bindProgramTransaction(
        (_inputs: Inputs, senderArg, _payer) => {
          senderArg.fill(0);
          return raw;
        },
        { assets: new AssetRegistry() },
      );
      const decoded = await transaction(inputs, sender, fixture.payer);
      raw.proofInputs.opening = "9";
      raw.publicHash.fill(9);
      expect({ assignment: decoded.proofInputs, hash: decoded.publicHash, sender }).toEqual({
        assignment: {
          opening: "17",
          public_hash: bytesToBigInt(new Uint8Array(32).fill(1)).toString(),
        },
        hash: new Uint8Array(32).fill(1),
        sender: bytes(fixture.sender),
      });
    });

    it("snapshots registered assets at binding rather than trusting new wasm bindings", async () => {
      const raw = result();
      const output = raw.finalizedTx.outputUtxos[0];
      if (output === undefined) throw new Error("fixture needs an output");
      raw.finalizedTx.outputUtxos[0] = { ...output, asset: { asset: OTHER_ADDRESS, assetId: 7n } };
      const assets = new AssetRegistry();
      const transaction = bindProgramTransaction((_inputs: Inputs) => raw, {
        assets,
      });
      assets.insert(7n, OTHER_ADDRESS);
      const encrypt = vi.spyOn(ViewingKey.prototype, "encryptSlot");
      const prove = vi.fn();
      try {
        await expect(
          transaction(inputs, bytes(fixture.sender), fixture.payer).then(prove),
        ).rejects.toMatchObject({
          code: "TRANSACTION_UNKNOWN_ASSET",
        });
        expect([encrypt.mock.calls, prove.mock.calls]).toEqual([[], []]);
      } finally {
        encrypt.mockRestore();
      }
    });

    it.each([
      ["mint binding", "TRANSACTION_MINT_MISMATCH"],
      ["output commitment", "TRANSACTION_OUTPUT_HASH_MISMATCH"],
      ["input commitment", "TRANSACTION_INPUT_HASH_MISMATCH"],
      ["owner tag", "TRANSACTION_OWNER_TAG_MISMATCH"],
    ])("preserves the %s validation before encryption or proving", async (change, code) => {
      const raw = result();
      const output = raw.finalizedTx.outputUtxos[0];
      const input = raw.finalizedTx.inputUtxos[0];
      const tag = raw.finalizedTx.ownerTags[0];
      if (output === undefined || input === undefined || tag === undefined)
        throw new Error("fixture shape");
      if (change === "mint binding")
        raw.finalizedTx.outputUtxos[0] = {
          ...output,
          asset: { asset: OTHER_ADDRESS, assetId: 1n },
        };
      if (change === "output commitment") raw.finalizedTx.outputHashes[0] = new Uint8Array(32);
      if (change === "input commitment")
        raw.finalizedTx.inputUtxos[0] = { ...input, utxoHash: new Uint8Array(32) };
      if (change === "owner tag")
        raw.finalizedTx.ownerTags[0] = { ...tag, resolved: new Uint8Array(32) };
      const transaction = bindProgramTransaction((_inputs: Inputs) => raw, {
        assets: new AssetRegistry(),
      });
      const encrypt = vi.spyOn(ViewingKey.prototype, "encryptSlot");
      const prove = vi.fn();
      try {
        await expect(
          transaction(inputs, bytes(fixture.sender), fixture.payer).then(prove),
        ).rejects.toMatchObject({ code });
        expect([encrypt.mock.calls, prove.mock.calls]).toEqual([[], []]);
      } finally {
        encrypt.mockRestore();
      }
    });

    it("binds the returned sender and payer to the call", async () => {
      const other = ShieldedKeypair.generate();
      const transaction = bindProgramTransaction((_inputs: Inputs) => result(), {
        assets: new AssetRegistry(),
      });
      try {
        await expect(
          transaction(inputs, other.shieldedAddress().toBytes(), fixture.payer),
        ).rejects.toMatchObject({ code: "TRANSACTION_PROGRAM_SENDER_MISMATCH" });
        await expect(
          transaction(inputs, bytes(fixture.sender), OTHER_ADDRESS),
        ).rejects.toMatchObject({ code: "TRANSACTION_PROGRAM_PAYER_MISMATCH" });
      } finally {
        other.destroy();
      }
    });

    it("validates call identities before invoking wasm", async () => {
      const build = vi.fn((_inputs: Inputs) => result());
      const transaction = bindProgramTransaction(build, {
        assets: new AssetRegistry(),
      });
      await expect(transaction(inputs, new Uint8Array(), fixture.payer)).rejects.toMatchObject({
        code: "TRANSACTION_INVALID_LENGTH",
      });
      await expect(transaction(inputs, bytes(fixture.sender), "bad payer")).rejects.toMatchObject({
        code: "TRANSACTION_DESERIALIZE",
      });
      expect(build).not.toHaveBeenCalled();
    });

    it.each([false, true])(
      "sanitizes a wasm build failure (asynchronous: %s)",
      async (asynchronous) => {
        const secret = "never expose the circuit assignment or private input";
        const build = (_inputs: Inputs) => {
          if (asynchronous) return Promise.reject(new Error(secret));
          throw new Error(secret);
        };
        const transaction = bindProgramTransaction(build, {
          assets: new AssetRegistry(),
        });
        let failure: unknown;
        try {
          await transaction(inputs, bytes(fixture.sender), fixture.payer);
        } catch (error) {
          failure = error;
        }
        expect(failure).toMatchObject({
          code: "TRANSACTION_PROGRAM_BUILD",
          cause: { category: "external" },
        });
        expect(JSON.stringify(failure)).not.toContain(secret);
      },
    );

    it.each([
      null,
      {},
      { ...result(), extra: true },
      { ...result(), proofInputs: [] },
      { ...result(), proofInputs: new Uint8Array() },
      { ...result(), publicHash: new Uint8Array(31) },
      { ...result(), publicHash: new Uint8Array(32).fill(255) },
    ])("refuses malformed outer wasm result %#", async (raw) => {
      const transaction = bindProgramTransaction((_inputs: Inputs) => raw, {
        assets: new AssetRegistry(),
      });
      await expect(transaction(inputs, bytes(fixture.sender), fixture.payer)).rejects.toMatchObject(
        { name: "TransactionError" },
      );
    });
  });

  it("is finalized for the shielded address the Rust sender keypair derives", () => {
    expect(senderKeypair().shieldedAddress().toBytes()).toEqual(bytes(fixture.sender));
  });

  it("decodes into proof slots whose commitments are the Rust hashes", async () => {
    const decoded = await decodeProgramTransaction(wasm, new AssetRegistry());

    expect({
      inputs: decoded.inputs.map((input) => input.hash()),
      outputs: decoded.outputs.map((output) => output.hash(decoded.outputTreeId)),
    }).toEqual({
      inputs: fixture.transaction.finalizedTx.inputUtxos.map((input) => bytes(input.utxoHash)),
      outputs: fixture.transaction.finalizedTx.outputHashes.map(bytes),
    });
  });

  it("retains the registry-validated mint address and id on every UTXO", async () => {
    const decoded = await decodeProgramTransaction(wasm, new AssetRegistry());
    const pair = (mint: { readonly asset: string; readonly assetId: bigint } | undefined) =>
      mint === undefined ? undefined : { asset: mint.asset, assetId: mint.assetId };
    expect({
      inputs: decoded.inputs.map((input) => pair(input.utxo.mint)),
      outputs: decoded.outputs.map((output) => pair(output.mint)),
    }).toEqual({
      inputs: wasm.inputUtxos.map((input) => input.utxo.asset),
      outputs: wasm.outputUtxos.map((output) => output.asset),
    });
  });

  it("encrypts with the retained mint ids without consulting the registry again", async () => {
    const assets = new AssetRegistry();
    const decoded = await decodeProgramTransaction(wasm, assets);
    const lookup = vi.spyOn(assets, "assetId");
    const resolve = vi.spyOn(assets, "resolve");
    const sender = senderKeypair();
    try {
      const proofInputs = decoded.encryptWithKeys(sender);
      expect({
        hashes: proofInputs.externalData.outputs.map((output) => output.utxoHash),
        lookups: lookup.mock.calls,
        resolutions: resolve.mock.calls,
      }).toEqual({
        hashes: fixture.encrypted.utxoHashes.map(bytes),
        lookups: [],
        resolutions: [],
      });
    } finally {
      sender.destroy();
      lookup.mockRestore();
      resolve.mockRestore();
    }
  });

  it("seals into the external data Rust encrypts", async () => {
    const decoded = await decodeProgramTransaction(wasm, new AssetRegistry());
    const keys = LocalShieldedKeys.fromKeypair(senderKeypair());
    const [tx] = await keys.transactionKeys([
      {
        viewingPublicKey: decoded.sender.viewingPublicKey,
        firstNullifier: decoded.firstNullifier,
      },
    ]);
    if (tx === undefined) throw new Error("no transaction viewing key");
    try {
      const externalData = decoded.encrypt(tx);
      const expiring = decoded.encrypt(tx, { expiryUnixTs: 1_700_000_000n });

      expect({
        utxoHashes: externalData.outputs.map((output) => output.utxoHash),
        ownerTags: externalData.outputs.map((output) => output.ownerTag),
        resolvedOwnerTags: externalData.resolvedOwnerTags,
        interfaceTransfers: externalData.interfaceTransfers,
        expiries: [externalData.expiryUnixTs, expiring.expiryUnixTs],
      }).toEqual({
        utxoHashes: fixture.encrypted.utxoHashes.map(bytes),
        ownerTags: fixture.encrypted.ownerTags.map(programOwnerTag),
        resolvedOwnerTags: fixture.encrypted.resolvedOwnerTags.map(bytes),
        interfaceTransfers: await Promise.all(
          fixture.encrypted.interfaceTransfers.map(sdkTransfer),
        ),
        expiries: [0xffff_ffff_ffff_ffffn, 1_700_000_000n],
      });
    } finally {
      tx.destroy();
      keys.destroy();
    }
  });

  it("builds the wallet UTXOs the program reads", () => {
    const assets = new AssetRegistry();

    expect(
      walletUtxos.map((utxo) =>
        toProgramWalletUtxo(sdkWalletUtxo(utxo, assets), {
          nullifierPublicKey: bytes32(utxo.nullifierPubkey),
          treeId: utxo.treeId,
          assets,
        }),
      ),
    ).toEqual(walletUtxos.map(programWalletUtxo));
  });
});

describe("program transaction decoding", () => {
  const wasm = programTransaction(escrow.transaction.finalizedTx);
  const [first, second] = wasm.ownerTags;
  const [firstOutput, secondOutput] = wasm.outputUtxos;
  const [firstInput, ...otherInputs] = wasm.inputUtxos;
  if (!first || !second || !firstOutput || !secondOutput || !firstInput) {
    throw new Error("escrow fixture shape");
  }

  it("fills a padding slot with a length-matched random ciphertext under its tag", async () => {
    const raw = programTransaction(withdraw.transaction.finalizedTx);
    const compact = await decodeProgramTransaction(raw, new AssetRegistry());
    const padding = compact.outputs[1];
    if (padding === undefined) throw new Error("withdraw fixture needs padding");
    const ownerTag = checkedBytes<Bytes32>(new Uint8Array(32).fill(7), 32, "padding tag");
    const dummyHash = createProofOutput({ ...padding, compact: false, ownerTag }).hash(
      compact.outputTreeId,
    );
    const decoded = await decodeProgramTransaction(
      {
        ...raw,
        outputUtxos: raw.outputUtxos.map((output, index) =>
          index === 1 ? { ...output, compact: false, ownerTag } : output,
        ),
        outputHashes: raw.outputHashes.map((hash, index) => (index === 1 ? dummyHash : hash)),
        ownerTags: raw.ownerTags.map((entry, index) =>
          index === 1 ? { tag: { kind: "inline", value: ownerTag }, resolved: ownerTag } : entry,
        ),
      },
      new AssetRegistry(),
    );
    const tx = senderKeypair().transactionViewingKey(decoded.firstNullifier);
    try {
      const externalData = decoded.encrypt(tx);
      const slot = externalData.outputs[1];

      expect({
        dummy: decoded.outputs.map((output) => output.isDummy()),
        utxoHash: slot?.utxoHash,
        ownerTag: slot?.ownerTag,
        resolved: externalData.resolvedOwnerTags[1],
        length: slot?.data?.length,
      }).toEqual({
        dummy: [false, true],
        utxoHash: decoded.outputHashes[1],
        ownerTag: decoded.ownerTags[1],
        resolved: decoded.outputs[1]?.ownerTag,
        length: dummyCiphertextLength(externalData.salt),
      });
    } finally {
      tx.destroy();
    }
  });

  it("keeps compact padding in proof slots and leaves it out of encrypted outputs", async () => {
    const decoded = await decodeProgramTransaction(
      programTransaction(withdraw.transaction.finalizedTx),
      new AssetRegistry(),
    );
    const tx = senderKeypair().transactionViewingKey(decoded.firstNullifier);
    try {
      const externalData = decoded.encrypt(tx);
      expect({
        compact: decoded.outputs.map((output) => output.isCompact()),
        paddingHash: decoded.outputHashes[1],
        hashes: externalData.outputs.map((output) => output.utxoHash),
        tags: externalData.resolvedOwnerTags,
      }).toEqual({
        compact: [false, true],
        paddingHash: new Uint8Array(32),
        hashes: [decoded.outputHashes[0]],
        tags: [decoded.resolvedOwnerTags[0]],
      });
    } finally {
      tx.destroy();
    }
  });

  it("derives the SPL interface bump and token account of each settlement leg", async () => {
    const legs: readonly FixtureTransfer[] = [
      {
        kind: "spl",
        mint: OTHER_ADDRESS,
        isDeposit: false,
        amount: 5,
        userSplToken: withdraw.payer,
      },
      { kind: "sol", isDeposit: true, amount: 7, userSolAccount: withdraw.payer },
    ];
    const decoded = await decodeProgramTransaction(
      { ...wasm, interfaceTransfers: legs.map(programTransfer) },
      new AssetRegistry(),
    );

    expect(decoded.interfaceTransfers).toEqual(await Promise.all(legs.map(sdkTransfer)));
  });

  it.each([
    [
      "a resolved tag that is not the slot owner's view tag",
      { ...wasm, ownerTags: [first, { ...second, resolved: new Uint8Array(32).fill(1) }] },
      { code: "TRANSACTION_OWNER_TAG_MISMATCH", details: { slotIndex: 1, reason: "viewTag" } },
    ],
    [
      "an inline tag that differs from its resolved tag",
      {
        ...wasm,
        ownerTags: [first, { ...second, tag: { kind: "inline", value: new Uint8Array(32) } }],
      },
      { code: "TRANSACTION_OWNER_TAG_MISMATCH", details: { slotIndex: 1, reason: "inline" } },
    ],
    [
      "an account tag on a slot the payer does not own",
      { ...wasm, ownerTags: [first, { ...second, tag: { kind: "account", index: 0 } }] },
      { code: "TRANSACTION_OWNER_TAG_MISMATCH", details: { slotIndex: 1, reason: "account" } },
    ],
    [
      "one owner tag fewer than output slots",
      { ...wasm, ownerTags: [first] },
      { code: "TRANSACTION_OWNER_TAG_COUNT_MISMATCH", details: { got: 1, expected: 2 } },
    ],
    [
      "one output hash fewer than output slots",
      { ...wasm, outputHashes: wasm.outputHashes.slice(1) },
      { code: "TRANSACTION_OUTPUT_HASH_COUNT_MISMATCH", details: { got: 1, expected: 2 } },
    ],
    [
      "an output hash that is not the slot's commitment",
      { ...wasm, outputHashes: [new Uint8Array(32).fill(9), ...wasm.outputHashes.slice(1)] },
      { code: "TRANSACTION_OUTPUT_HASH_MISMATCH", details: { slotIndex: 0 } },
    ],
    [
      "an input hash that is not the input's commitment",
      {
        ...wasm,
        inputUtxos: [{ ...firstInput, utxoHash: new Uint8Array(32).fill(9) }, ...otherInputs],
      },
      { code: "TRANSACTION_INPUT_HASH_MISMATCH", details: { field: "inputUtxos[0]" } },
    ],
    [
      "a first nullifier that is not the first input's",
      { ...wasm, firstNullifier: new Uint8Array(32).fill(3) },
      { code: "TRANSACTION_FIRST_NULLIFIER_MISMATCH" },
    ],
    [
      "a mint the registry binds to another asset id",
      {
        ...wasm,
        outputUtxos: [
          { ...firstOutput, asset: { asset: OTHER_ADDRESS, assetId: 1n } },
          secondOutput,
        ],
      },
      { code: "TRANSACTION_MINT_MISMATCH", details: { field: "outputUtxos[0].asset" } },
    ],
    [
      "a byte field of the wrong length",
      {
        ...wasm,
        outputUtxos: [{ ...firstOutput, blinding: new Uint8Array(31) }, secondOutput],
      },
      {
        code: "TRANSACTION_INVALID_LENGTH",
        details: { name: "outputUtxos[0].blinding", expected: 32, actual: 31 },
      },
    ],
    [
      "an unknown owner tag kind",
      { ...wasm, ownerTags: [{ ...first, tag: { kind: "program", index: 0 } }, second] },
      { code: "TRANSACTION_BAD_DISCRIMINATOR", details: { field: "ownerTags[0].tag.kind" } },
    ],
    [
      "an unknown settlement transfer kind",
      { ...wasm, interfaceTransfers: [{ kind: "token", amount: 1n }] },
      {
        code: "TRANSACTION_BAD_DISCRIMINATOR",
        details: { field: "interfaceTransfers[0].kind" },
      },
    ],
    [
      "an unknown data record kind",
      {
        ...wasm,
        outputUtxos: [
          firstOutput,
          { ...secondOutput, data: { records: [{ kind: "note", bytes: new Uint8Array() }] } },
        ],
      },
      {
        code: "TRANSACTION_BAD_DISCRIMINATOR",
        details: { field: "outputUtxos[1].data.records[0].kind" },
      },
    ],
    [
      "a field the program transaction does not define",
      { ...wasm, expiryUnixTs: 0n },
      { code: "TRANSACTION_DESERIALIZE", details: { field: "finalizedTx.expiryUnixTs" } },
    ],
    [
      "an amount outside u64",
      { ...wasm, outputUtxos: [{ ...firstOutput, amount: 1n << 64n }, secondOutput] },
      {
        code: "TRANSACTION_INVALID_INTEGER",
        details: { field: "outputUtxos[0].amount", bits: 64 },
      },
    ],
  ] as const)("refuses %s", async (_, value, error) => {
    await expect(decodeProgramTransaction(value, new AssetRegistry())).rejects.toMatchObject(error);
  });
});

describe("program wallet UTXOs", () => {
  const [fixtureUtxo] = escrow.records.inputs;
  if (!fixtureUtxo) throw new Error("escrow fixture shape");
  const assets = new AssetRegistry();
  const utxo = sdkWalletUtxo(fixtureUtxo, assets);

  it.each([
    [
      "a tree id the UTXO does not live in",
      { nullifierPublicKey: bytes32(fixtureUtxo.nullifierPubkey), treeId: fixtureUtxo.treeId + 1 },
      "TRANSACTION_INPUT_TREE_MISMATCH",
    ],
    [
      "a nullifier public key that does not open the commitment",
      { nullifierPublicKey: bytes32(fixtureUtxo.nullifier), treeId: fixtureUtxo.treeId },
      "TRANSACTION_INPUT_OWNER_MISMATCH",
    ],
  ] as const)("refuses %s", (_, input, code) => {
    expect(() => toProgramWalletUtxo(utxo, { ...input, assets })).toThrow(
      expect.objectContaining({ code }),
    );
  });
});
