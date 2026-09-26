import { readFileSync } from "node:fs";

import { address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import type { Bytes32 } from "../src/interface/index.js";
import { splInterfaceWithBump, treeAddress } from "../src/interface/pda/index.js";
import { checkedBytes, type Bytes34 } from "../src/keypair/bytes.js";
import {
  P256_PUBLIC_KEY_LENGTH,
  ShieldedKeypair,
  ShieldedPublicKey,
  SigningKey,
} from "../src/keypair/index.js";
import {
  AssetRegistry,
  Data,
  LocalShieldedKeys,
  Utxo,
  decodeConfidential,
  decodeOutputData,
  decodeProgramTransaction,
  toProgramWalletUtxo,
  type ProgramData,
  type ProgramFinalizedTransaction,
  type ProgramOwnerTag,
  type ProgramProofInputUtxo,
  type ProgramProofOutputUtxo,
  type ProgramSettlementTransfer,
  type ProgramUtxo,
  type ProgramWalletUtxo,
  type WalletUtxo,
} from "../src/transaction/index.js";

type FixtureBytes = readonly number[];

interface FixtureMint {
  readonly asset: string;
  readonly assetId: number;
}

interface FixtureData {
  readonly records: readonly Readonly<{
    kind: "ringData" | "utxoData" | "memo";
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
  readonly data: FixtureData;
}

type FixtureOwnerTag =
  | Readonly<{ kind: "inline"; value: FixtureBytes }>
  | Readonly<{ kind: "account"; index: number }>;

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
  readonly paddingOwner: FixtureBytes;
}

interface Fixture<Private> {
  readonly sender: FixtureBytes;
  readonly payer: string;
  readonly inputs: Readonly<{ private: Private }>;
  readonly transaction: Readonly<{ finalizedTx: FixtureFinalizedTransaction }>;
  readonly encrypted: Readonly<{
    utxoHashes: readonly FixtureBytes[];
    ownerTags: readonly FixtureOwnerTag[];
    resolvedOwnerTags: readonly FixtureBytes[];
    interfaceTransfers: readonly FixtureTransfer[];
  }>;
}

type EscrowFixture = Fixture<Readonly<{ tokenUtxosAssetA: readonly FixtureInputUtxo[] }>>;
type WithdrawFixture = Fixture<Readonly<{ escrow: FixtureInputUtxo }>>;

function readFixture(name: string): string {
  return readFileSync(
    new URL(`../../../sdk-tests/timelock-escrow/wasm/tests/fixtures/${name}`, import.meta.url),
    "utf8",
  );
}

const escrow = JSON.parse(readFixture("escrow.json")) as EscrowFixture;
const withdraw = JSON.parse(readFixture("withdraw.json")) as WithdrawFixture;

const FIXTURES = [
  [
    "escrow",
    escrow,
    escrow.inputs.private.tokenUtxosAssetA.filter((utxo) => utxo.utxo.owner.some(Boolean)),
  ],
  ["withdraw", withdraw, [withdraw.inputs.private.escrow]],
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
    records: value.records.map((record) => ({ kind: record.kind, bytes: bytes(record.bytes) })),
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
    data: programData(value.data),
  };
}

function programOwnerTag(value: FixtureOwnerTag): ProgramOwnerTag {
  return value.kind === "inline"
    ? { kind: "inline", value: bytes(value.value) }
    : { kind: "account", index: value.index };
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
    paddingOwner: bytes(value.paddingOwner),
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
  if (!first || !second || !firstOutput || !secondOutput) throw new Error("escrow fixture shape");

  it("seals a padding slot to the padding owner", async () => {
    const base = programTransaction(withdraw.transaction.finalizedTx);
    const padding = new Uint8Array(32).fill(7);
    const hash = new Uint8Array(32).fill(9);
    const decoded = await decodeProgramTransaction(
      {
        ...base,
        outputUtxos: [
          ...base.outputUtxos,
          {
            asset: { asset: "11111111111111111111111111111111", assetId: 1n },
            amount: 0n,
            blinding: padding,
            data: { records: [] },
          },
        ],
        outputHashes: [...base.outputHashes, hash],
        ownerTags: [...base.ownerTags, ...base.ownerTags],
      },
      new AssetRegistry(),
    );
    const keypair = senderKeypair();
    const tx = keypair.transactionViewingKey(decoded.firstNullifier);
    const viewing = keypair.viewingKey();
    try {
      const externalData = decoded.encrypt(tx);
      const slot = externalData.outputs[1];
      const body = decodeOutputData(slot?.data ?? new Uint8Array()).body;
      const plaintext = decodeConfidential(
        viewing.decryptUtxo(
          body.slice(P256_PUBLIC_KEY_LENGTH),
          externalData.txViewingPublicKey,
          externalData.salt,
          1,
        ),
      );

      expect({
        dummy: decoded.outputs[1]?.isDummy(),
        utxoHash: slot?.utxoHash,
        ownerTag: slot?.ownerTag,
        recipient: body.slice(0, P256_PUBLIC_KEY_LENGTH),
        plaintext: { ...plaintext, data: plaintext.data.records() },
      }).toEqual({
        dummy: true,
        utxoHash: hash,
        ownerTag: { kind: "account", index: 0 },
        recipient: decoded.paddingOwner.viewingPublicKey.toBytes(),
        plaintext: { assetId: 1n, amount: 0n, blinding: padding, data: [] },
      });
    } finally {
      tx.destroy();
      viewing.destroy();
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
  const [fixtureUtxo] = escrow.inputs.private.tokenUtxosAssetA;
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
