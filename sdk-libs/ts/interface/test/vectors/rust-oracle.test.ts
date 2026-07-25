import { describe, expect, it } from "vitest";

import oracle from "../rust-oracle.json" with { type: "json" };
import * as rootSurface from "../../src/index.js";
import * as codecsSurface from "../../src/codecs/index.js";
import * as instructionsSurface from "../../src/instructions/index.js";
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  ADDRESS_TREE_HEIGHT,
  ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE,
  ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
  ADDRESS_TREE_ROOT_HISTORY_CAPACITY,
  DEFAULT_TREE_ADDRESS,
  FIRST_ASSET_ID,
  InstructionTag,
  MERGE_ENCRYPTED_UTXO_LENGTH,
  MERGE_ENCRYPTED_UTXO_TYPE_PREFIX,
  MERGE_INPUT_COUNT,
  P256_PROOF_LENGTH,
  SHIELDED_POOL_CPI_AUTHORITY,
  SHIELDED_POOL_PROGRAM_ID,
  SOL_INTERFACE,
  SPL_TOKEN_PROGRAM_ID,
  SPP_SUPPORTED_SHAPES,
  STATE_HEIGHT,
  STATE_ROOT_OFFSET,
  ShieldedPoolError,
  StateDiscriminator,
  TREE_ACCOUNT_SIZE,
  UTXO_DOMAIN,
  addressTreeParams,
  ciphertextHash,
  decodeProtocolConfig,
  decodeSplAssetCounter,
  decodeSplAssetRegistry,
  decodeZoneConfig,
  externalDataHash,
  fetchTag,
  ownerPkFieldCompressed,
  pack33,
  pkFieldCompressed,
  selectSppShape,
  type Address,
  type Bytes16,
  type Bytes31,
  type Bytes32,
  type Bytes33,
  type Bytes64,
  type Instruction,
  type MergeTransactInstructionData,
  type TransactInstructionData,
  type TransactWithdrawal,
} from "../../src/index.js";
import {
  addressTreeParamsCodec,
  batchUpdateNullifierTreeDataCodec,
  createTreeDataCodec,
  createZoneConfigDataCodec,
  updateZoneConfigDataCodec,
  updateZoneConfigOwnerDataCodec,
  mergeExternalDataHash,
  depositInstructionDataCodec,
  mergeTransactInstructionDataCodec,
  mergeZoneInstructionDataCodec,
  protocolConfigAccountCodec,
  splAssetCounterAccountCodec,
  splAssetRegistryAccountCodec,
  transactInstructionDataCodec,
  zoneConfigAccountCodec,
  zoneDepositInstructionDataCodec,
} from "../../src/codecs/index.js";
import {
  associatedTokenAddress,
  protocolConfigAddress,
  shieldedPoolCpiAuthorityAddress,
  solInterfaceAddress,
  splAssetCounterAddress,
  splAssetRegistryAddress,
  splAssetVaultAddress,
  zoneAuthAddress,
  zoneConfigAddress,
} from "../../src/pda/index.js";
import {
  createAssetCounterInstruction,
  createAssociatedTokenAccountInstruction,
  createProtocolConfigInstruction,
  createSplInterfaceInstruction,
  createTreeInstruction,
  createZoneConfigInstruction,
  depositInstruction,
  mergeTransactInstruction,
  mergeZoneInstruction,
  pauseTreeInstruction,
  transactInstruction,
  updateProtocolConfigInstruction,
  updateZoneConfigInstruction,
  updateZoneConfigOwnerInstruction,
  zoneAuthorityTransactInstruction,
  zoneDepositInstruction,
  zoneTransactInstruction,
  type ProtocolConfigUpdate,
} from "../../src/instructions/index.js";

/**
 * Compares `@zolana/interface` against `sdk-libs/ts/interface/test/rust-oracle.json`,
 * regenerated from the `zolana-interface` crate by
 * `cargo run -p xtask --bin ts-interface-oracle -- --write`. Every expectation
 * here is a value current Rust produced, not a value transcribed by hand, so a
 * Rust change the port has not followed fails this suite.
 */

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function bytes(value: string): Uint8Array {
  const out = new Uint8Array(value.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}

/** Same deterministic filler the Rust oracle uses for its inputs. */
function filler(seed: number, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let index = 0; index < length; index += 1) {
    out[index] = (((seed + index * 7) & 0xff) | 1) & 0xff;
  }
  return out;
}

function account(index: number): Address {
  return oracle.accounts[String(index) as keyof typeof oracle.accounts] as Address;
}

type OracleInstruction = {
  programAddress: string;
  data: string;
  accounts: { address: string; isSigner: boolean; isWritable: boolean }[];
};

function expectInstruction(built: Instruction, expected: OracleInstruction): void {
  expect({
    programAddress: String(built.programAddress),
    data: hex(built.data),
    accounts: built.accounts.map((meta) => ({
      address: String(meta.address),
      isSigner: meta.isSigner,
      isWritable: meta.isWritable,
    })),
  }).toEqual(expected);
}

const builders = oracle.builders as Record<string, OracleInstruction>;

describe("constants and tags", () => {
  it("matches the Rust program ids and protocol constants", () => {
    expect(SHIELDED_POOL_PROGRAM_ID).toBe(oracle.constants.shieldedPoolProgramId);
    expect(DEFAULT_TREE_ADDRESS).toBe(oracle.constants.defaultTreeAddress);
    expect(SOL_INTERFACE).toBe(oracle.constants.solInterface);
    expect(SHIELDED_POOL_CPI_AUTHORITY).toBe(oracle.constants.shieldedPoolCpiAuthority);
    expect(SPL_TOKEN_PROGRAM_ID).toBe(oracle.constants.splTokenProgramId);
    expect(ASSOCIATED_TOKEN_PROGRAM_ID).toBe(oracle.constants.associatedTokenProgramId);
    expect(UTXO_DOMAIN).toBe(oracle.constants.utxoDomain);
    expect(P256_PROOF_LENGTH).toBe(oracle.constants.p256ProofLength);
    expect(MERGE_INPUT_COUNT).toBe(oracle.constants.mergeInputCount);
    expect(MERGE_ENCRYPTED_UTXO_LENGTH).toBe(oracle.constants.mergeEncryptedUtxoLength);
    expect(MERGE_ENCRYPTED_UTXO_TYPE_PREFIX).toBe(oracle.constants.mergeEncryptedUtxoTypePrefix);
  });

  it("matches the Rust instruction tag table exactly", () => {
    expect({ ...InstructionTag }).toEqual(oracle.tags);
  });
});

describe("errors", () => {
  it("matches every Rust error code and message", () => {
    const actual = Object.fromEntries(
      Object.entries(oracle.errors).map(([name]) => [
        name,
        { code: ShieldedPoolError[name as keyof typeof ShieldedPoolError] },
      ]),
    );
    const expected = Object.fromEntries(
      Object.entries(oracle.errors).map(([name, value]) => [name, { code: value.code }]),
    );
    expect(actual).toEqual(expected);
  });

  it("exports no code Rust does not define and omits none Rust does", () => {
    expect(Object.keys(ShieldedPoolError).sort()).toEqual(Object.keys(oracle.errors).sort());
  });
});

describe("shape", () => {
  it("matches the Rust supported-shape list in order", () => {
    expect(SPP_SUPPORTED_SHAPES.map((shape) => ({ ...shape }))).toEqual(oracle.shapes);
  });

  it("selects the first shape that covers the request, as Rust orders them", () => {
    for (const shape of oracle.shapes) {
      expect(selectSppShape(shape.inputs, shape.outputs)).toEqual(shape);
    }
    expect(selectSppShape(0, 0)).toEqual(oracle.shapes[0]);
  });
});

describe("merge utils", () => {
  it("matches Rust ciphertext_hash across chunk boundaries", () => {
    for (const vector of oracle.mergeUtils.ciphertextHashes) {
      const ciphertext = Uint8Array.from({ length: vector.length }, (_, index) => index % 251);
      expect(hex(ciphertextHash(ciphertext))).toBe(vector.hash);
    }
  });

  it("rejects the same unsupported chunk counts Rust rejects", () => {
    expect(oracle.mergeUtils.ciphertextHashRejects.empty).toBe(true);
    expect(oracle.mergeUtils.ciphertextHashRejects.over192).toBe(true);
    expect(() => ciphertextHash(new Uint8Array(0))).toThrow();
    expect(() => ciphertextHash(new Uint8Array(193))).toThrow();
    expect(() => ciphertextHash(new Uint8Array(192))).not.toThrow();
  });

  it("matches Rust pk_field, owner_pk_field, and pack33", () => {
    const even = bytes(oracle.mergeUtils.compressedKeyEven);
    const odd = bytes(oracle.mergeUtils.compressedKeyOdd);
    expect(hex(pkFieldCompressed(even))).toBe(oracle.mergeUtils.pkFieldEven);
    expect(hex(pkFieldCompressed(odd))).toBe(oracle.mergeUtils.pkFieldOdd);
    expect(hex(ownerPkFieldCompressed(even))).toBe(oracle.mergeUtils.ownerPkFieldEven);
    expect(hex(ownerPkFieldCompressed(odd))).toBe(oracle.mergeUtils.ownerPkFieldOdd);
    const [low, high] = pack33(even);
    expect(hex(low)).toBe(oracle.mergeUtils.pack33Low);
    expect(hex(high)).toBe(oracle.mergeUtils.pack33High);
  });

  it("rejects the same compressed prefixes Rust rejects", () => {
    for (const prefix of oracle.mergeUtils.rejectedPrefixes) {
      const key = bytes(oracle.mergeUtils.compressedKeyEven);
      key[0] = prefix;
      expect(() => pkFieldCompressed(key)).toThrow();
      expect(() => ownerPkFieldCompressed(key)).toThrow();
    }
  });
});

describe("pda", () => {
  it("derives every canonical address and bump Rust derives", () => {
    const mint = oracle.pdas.mint as Address;
    const owner = oracle.pdas.owner as Address;
    const zone = oracle.pdas.zoneProgram as Address;
    expect(protocolConfigAddress()).toBe(oracle.pdas.protocolConfig);
    expect(solInterfaceAddress()).toBe(oracle.pdas.solInterface);
    expect(shieldedPoolCpiAuthorityAddress()).toBe(oracle.pdas.cpiAuthority);
    expect(splAssetCounterAddress()).toBe(oracle.pdas.splAssetCounter);
    expect(splAssetRegistryAddress(mint)).toBe(oracle.pdas.splAssetRegistry);
    expect(splAssetVaultAddress(mint)).toBe(oracle.pdas.splAssetVault);
    expect(zoneConfigAddress(zone)).toEqual([
      oracle.pdas.zoneConfig.address,
      oracle.pdas.zoneConfig.bump,
    ]);
    expect(zoneAuthAddress(zone)).toEqual([
      oracle.pdas.zoneAuth.address,
      oracle.pdas.zoneAuth.bump,
    ]);
    expect(associatedTokenAddress(owner, mint)).toBe(oracle.pdas.associatedToken);
  });
});

describe("state", () => {
  it("matches Rust discriminators, sizes, and tree parameters", () => {
    expect({ ...StateDiscriminator }).toEqual(oracle.state.discriminators);
    expect(FIRST_ASSET_ID).toBe(BigInt(oracle.state.firstAssetId));
    expect(TREE_ACCOUNT_SIZE).toBe(oracle.state.tree.accountSize);
    expect(STATE_ROOT_OFFSET).toBe(oracle.state.tree.stateRootOffset);
    expect(STATE_HEIGHT).toBe(oracle.state.tree.stateHeight);
    expect(ADDRESS_TREE_HEIGHT).toBe(oracle.state.tree.addressTreeHeight);
    expect(ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE).toBe(BigInt(oracle.state.tree.inputQueueBatchSize));
    expect(ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE).toBe(
      BigInt(oracle.state.tree.inputQueueZkpBatchSize),
    );
    expect(ADDRESS_TREE_ROOT_HISTORY_CAPACITY).toBe(oracle.state.tree.rootHistoryCapacity);
  });

  it("matches the canonical Rust nullifier tree parameters", () => {
    expect(addressTreeParams()).toEqual({
      index: 0n,
      inputQueueBatchSize: BigInt(oracle.state.tree.inputQueueBatchSize),
      inputQueueZkpBatchSize: BigInt(oracle.state.tree.inputQueueZkpBatchSize),
      rootHistoryCapacity: oracle.state.tree.rootHistoryCapacity,
      height: oracle.state.tree.addressTreeHeight,
    });
  });

  it("decodes and re-encodes the exact bytes Rust writes for each account", () => {
    const protocol = oracle.stateAccounts.protocolConfig;
    expect(decodeProtocolConfig(bytes(protocol.bytes))).toEqual(protocol.value);
    expect(hex(protocolConfigAccountCodec.encode(protocol.value as never))).toBe(protocol.bytes);
    expect(protocolConfigAccountCodec.encode(protocol.value as never)).toHaveLength(
      oracle.state.sizes.protocolConfig,
    );

    const counter = oracle.stateAccounts.splAssetCounter;
    expect(decodeSplAssetCounter(bytes(counter.bytes))).toEqual({ nextId: BigInt(counter.nextId) });
    expect(hex(splAssetCounterAccountCodec.encode({ nextId: BigInt(counter.nextId) }))).toBe(
      counter.bytes,
    );

    const counterMax = oracle.stateAccounts.splAssetCounterMax;
    expect(decodeSplAssetCounter(bytes(counterMax.bytes))).toEqual({
      nextId: BigInt(counterMax.nextId),
    });

    const registry = oracle.stateAccounts.splAssetRegistry;
    expect(decodeSplAssetRegistry(bytes(registry.bytes))).toEqual({
      mint: registry.mint,
      assetId: BigInt(registry.assetId),
    });
    expect(
      hex(
        splAssetRegistryAccountCodec.encode({
          mint: registry.mint as Address,
          assetId: BigInt(registry.assetId),
        }),
      ),
    ).toBe(registry.bytes);

    const zone = oracle.stateAccounts.zoneConfig;
    expect(decodeZoneConfig(bytes(zone.bytes))).toEqual(zone.value);
    expect(hex(zoneConfigAccountCodec.encode(zone.value as never))).toBe(zone.bytes);
  });

  it("accepts the nonzero flag bytes Rust decodes as true", () => {
    const protocol = oracle.stateAccounts.protocolConfigNoncanonicalFlag;
    expect(decodeProtocolConfig(bytes(protocol.bytes)).zoneCreationIsPermissionless).toBe(
      protocol.zoneCreationIsPermissionless,
    );
    const zone = oracle.stateAccounts.zoneConfigNoncanonicalFlag;
    expect(decodeZoneConfig(bytes(zone.bytes)).zoneAuthorityTransactIsEnabled).toBe(
      zone.zoneAuthorityTransactIsEnabled,
    );
  });
});

const depositData = {
  viewTag: filler(1, 32) as Bytes32,
  owner: filler(2, 32) as Bytes32,
  blinding: filler(4, 31) as Bytes31,
  amount: 1_234_567_890_123n,
  utxoData: { dataHash: filler(3, 32) as Bytes32, data: Uint8Array.of(9, 8, 7, 6, 5) },
  memo: Uint8Array.of(1, 2, 3),
};

const zoneDepositData = {
  viewTag: filler(1, 32) as Bytes32,
  owner: filler(2, 32) as Bytes32,
  blinding: filler(4, 31) as Bytes31,
  amount: 42n,
  zoneDataHash: filler(5, 32) as Bytes32,
  zoneData: Uint8Array.of(4, 4, 4, 4),
  utxoData: { dataHash: filler(3, 32) as Bytes32, data: Uint8Array.of(9, 8, 7, 6, 5) },
};

function transactData(p256: boolean): TransactInstructionData {
  const viewingKey = filler(8, 33);
  viewingKey[0] = 0x02;
  return {
    expiryUnixTs: 1_700_000_000n,
    relayerFee: 4_242,
    privateTxHash: filler(6, 32) as Bytes32,
    ...(p256 ? { p256SigningPkX: filler(7, 32) as Bytes32 } : {}),
    txViewingPk: viewingKey as Bytes33,
    salt: filler(10, 16) as Bytes16,
    proof: p256
      ? {
          rail: "p256" as const,
          a: filler(11, 32) as Bytes32,
          b: filler(12, 64) as Bytes64,
          c: filler(13, 32) as Bytes32,
          commitment: filler(14, 32) as Bytes32,
          commitmentPok: filler(15, 32) as Bytes32,
        }
      : {
          rail: "eddsa" as const,
          a: filler(11, 32) as Bytes32,
          b: filler(12, 64) as Bytes64,
          c: filler(13, 32) as Bytes32,
        },
    inputs: [
      {
        nullifierHash: filler(16, 32) as Bytes32,
        nullifierTreeRootIndex: 3,
        utxoTreeRootIndex: 9,
        treeIndex: 1,
        eddsaSignerIndex: 0,
      },
      {
        nullifierHash: filler(17, 32) as Bytes32,
        nullifierTreeRootIndex: 65_535,
        utxoTreeRootIndex: 0,
        treeIndex: 255,
        eddsaSignerIndex: 2,
      },
    ],
    publicSolAmount: -9n,
    dataHash: filler(18, 32) as Bytes32,
    outputs: [
      {
        utxoHash: filler(19, 32) as Bytes32,
        ownerTag: { kind: "inline" as const, value: filler(20, 32) as Bytes32 },
        data: Uint8Array.of(1, 2, 3, 4, 5, 6, 7),
      },
      {
        utxoHash: filler(21, 32) as Bytes32,
        ownerTag: { kind: "account" as const, index: 4 },
      },
      {
        utxoHash: filler(22, 32) as Bytes32,
        ownerTag: { kind: "p256SigningKey" as const },
        data: new Uint8Array(0),
      },
    ],
    messages: [{ viewTag: filler(23, 32) as Bytes32, data: new Uint8Array(40).fill(7) }],
  };
}

function mergeData(): MergeTransactInstructionData {
  const encrypted = Uint8Array.from({ length: 110 }, (_, index) => index % 251);
  encrypted[0] = 2;
  return {
    expiryUnixTs: (1n << 64n) - 1n,
    proof: {
      a: filler(24, 32) as Bytes32,
      b: filler(25, 64) as Bytes64,
      c: filler(26, 32) as Bytes32,
      commitment: filler(27, 32) as Bytes32,
      commitmentPok: filler(28, 32) as Bytes32,
    },
    outputUtxoHash: filler(29, 32) as Bytes32,
    nullifiers: Array.from({ length: 8 }, (_, index) => filler(30 + index, 32) as Bytes32),
    utxoTreeRootIndexes: [0, 1, 2, 3, 4, 5, 6, 65_535],
    nullifierTreeRootIndexes: [65_535, 6, 5, 4, 3, 2, 1, 0],
    privateTxHash: filler(40, 32) as Bytes32,
    encryptedUtxo: encrypted,
    eddsaOwner: true,
  };
}

describe("instruction data codecs", () => {
  it("encodes deposit data to the exact Rust wincode bytes", () => {
    expect(hex(depositInstructionDataCodec.encode(depositData))).toBe(
      oracle.instructionData.deposit,
    );
    expect(depositInstructionDataCodec.decode(bytes(oracle.instructionData.deposit))).toEqual(
      depositData,
    );
  });

  it("encodes zone-deposit data to the exact Rust wincode bytes", () => {
    expect(hex(zoneDepositInstructionDataCodec.encode(zoneDepositData))).toBe(
      oracle.instructionData.zoneDeposit,
    );
    expect(
      zoneDepositInstructionDataCodec.decode(bytes(oracle.instructionData.zoneDeposit)),
    ).toEqual(zoneDepositData);
  });

  it("encodes both transact proof rails to the exact Rust wincode bytes", () => {
    expect(hex(transactInstructionDataCodec.encode(transactData(false)))).toBe(
      oracle.instructionData.transactEddsa,
    );
    expect(hex(transactInstructionDataCodec.encode(transactData(true)))).toBe(
      oracle.instructionData.transactP256,
    );
    expect(transactInstructionDataCodec.decode(bytes(oracle.instructionData.transactP256))).toEqual(
      transactData(true),
    );
  });

  it("encodes merge and merge-zone data to the exact Rust wincode bytes", () => {
    expect(hex(mergeTransactInstructionDataCodec.encode(mergeData()))).toBe(
      oracle.instructionData.mergeTransact,
    );
    expect(
      hex(
        mergeZoneInstructionDataCodec.encode({
          mergeViewTag: filler(41, 32) as Bytes32,
          merge: mergeData(),
        }),
      ),
    ).toBe(oracle.instructionData.mergeZone);
    expect(
      mergeTransactInstructionDataCodec.decode(bytes(oracle.instructionData.mergeTransact)),
    ).toEqual(mergeData());
  });

  it("round-trips the payload Rust builders emit for every remaining data type", () => {
    const payload = (name: keyof typeof builders, from = 1, to?: number): Uint8Array => {
      const data = bytes(builders[name].data);
      return data.subarray(from, to ?? data.length);
    };

    const batch = payload("batchUpdateNullifierTree");
    expect(
      hex(
        batchUpdateNullifierTreeDataCodec.encode(batchUpdateNullifierTreeDataCodec.decode(batch)),
      ),
    ).toBe(hex(batch));

    const createTree = payload("createTree");
    expect(hex(createTreeDataCodec.encode(createTreeDataCodec.decode(createTree)))).toBe(
      hex(createTree),
    );

    // Rust appends the nullifier parameters bare, with no Option tag: the
    // program tells the two forms apart by instruction-data length alone.
    const custom = payload("createTreeWithNullifierParams");
    expect(custom.length).toBe(32 + 37);
    expect(
      hex(createTreeDataCodec.encode(createTreeDataCodec.decode(custom.subarray(0, 32)))),
    ).toBe(hex(custom.subarray(0, 32)));
    const params = custom.subarray(32);
    expect(hex(addressTreeParamsCodec.encode(addressTreeParamsCodec.decode(params)))).toBe(
      hex(params),
    );
    expect(addressTreeParamsCodec.decode(params)).toEqual(addressTreeParams());

    for (const [name, codec] of [
      ["createZoneConfig", createZoneConfigDataCodec],
      ["updateZoneConfig", updateZoneConfigDataCodec],
      ["updateZoneConfigOwner", updateZoneConfigOwnerDataCodec],
    ] as const) {
      const encoded = payload(name);
      expect(hex(codec.encode(codec.decode(encoded) as never)), name).toBe(hex(encoded));
    }
  });
});

describe("builders", () => {
  const mint = oracle.pdas.mint as Address;
  const owner = oracle.pdas.owner as Address;
  const zone = oracle.pdas.zoneProgram as Address;
  const tree = account(20);
  const depositor = account(21);
  const payer = account(30);
  const spl = {
    userToken: account(22),
    splTokenInterface: account(23),
    registry: account(24),
    tokenProgram: SPL_TOKEN_PROGRAM_ID,
  };
  const solWithdrawal: TransactWithdrawal = { kind: "sol", recipient: account(31) };
  const splWithdrawal: TransactWithdrawal = {
    kind: "spl",
    cpiAuthority: oracle.pdas.cpiAuthority as Address,
    splTokenInterface: account(32),
    recipient: account(33),
    userTokenAccount: account(34),
    tokenProgram: SPL_TOKEN_PROGRAM_ID,
  };

  it("matches create-asset-counter, create-spl-interface, and create-ATA", () => {
    expectInstruction(
      createAssetCounterInstruction({ authority: owner }),
      builders.createAssetCounter,
    );
    expectInstruction(
      createSplInterfaceInstruction({ authority: owner, mint }),
      builders.createSplInterface,
    );
    expectInstruction(
      createAssociatedTokenAccountInstruction({ payer: account(35), owner, mint }),
      builders.createAssociatedTokenAccount,
    );
  });

  it("matches create-tree with default and custom nullifier parameters", () => {
    expectInstruction(
      createTreeInstruction({ authority: owner, tree, owner: account(36) }),
      builders.createTree,
    );
    expectInstruction(
      createTreeInstruction({
        authority: owner,
        tree,
        owner: account(36),
        nullifierTreeParams: addressTreeParams(),
      }),
      builders.createTreeWithNullifierParams,
    );
  });

  it("matches SOL and SPL deposits", () => {
    expectInstruction(
      depositInstruction({ tree, depositor, data: depositData }),
      builders.depositSol,
    );
    expectInstruction(
      depositInstruction({ tree, depositor, spl, data: depositData }),
      builders.depositSpl,
    );
  });

  it("matches SOL and SPL zone deposits on the outer and CPI routes", () => {
    const base = { tree, depositor, zoneProgramId: zone, ...zoneDepositData };
    expectInstruction(zoneDepositInstruction(base), builders.zoneDepositSol);
    expectInstruction(zoneDepositInstruction({ ...base, cpi: true }), builders.zoneDepositSolCpi);
    expectInstruction(zoneDepositInstruction({ ...base, spl }), builders.zoneDepositSpl);
    expectInstruction(
      zoneDepositInstruction({ ...base, spl, cpi: true }),
      builders.zoneDepositSplCpi,
    );
  });

  it("matches transact with no withdrawal and both settlement rails", () => {
    const data = transactData(false);
    expectInstruction(transactInstruction({ payer, tree, data }), builders.transactNoWithdrawal);
    expectInstruction(
      transactInstruction({ payer, tree, withdrawal: solWithdrawal, data }),
      builders.transactSolWithdrawal,
    );
    expectInstruction(
      transactInstruction({ payer, tree, withdrawal: splWithdrawal, data }),
      builders.transactSplWithdrawal,
    );
    const withoutAuthority: TransactWithdrawal = {
      kind: "spl",
      splTokenInterface: account(32),
      recipient: account(33),
      userTokenAccount: account(34),
      tokenProgram: SPL_TOKEN_PROGRAM_ID,
    };
    expectInstruction(
      transactInstruction({ payer, tree, withdrawal: withoutAuthority, data }),
      builders.transactSplWithdrawalNoCpiAuthority,
    );
  });

  it("matches zone transact and zone-authority transact on both routes", () => {
    const data = transactData(false);
    const base = { payer, tree, zoneProgramId: zone, data };
    expectInstruction(
      zoneTransactInstruction({ ...base, withdrawal: solWithdrawal }),
      builders.zoneTransactSol,
    );
    expectInstruction(
      zoneTransactInstruction({ ...base, withdrawal: solWithdrawal, cpi: true }),
      builders.zoneTransactSolCpi,
    );
    expectInstruction(
      zoneTransactInstruction({ ...base, withdrawal: splWithdrawal }),
      builders.zoneTransactSpl,
    );
    expectInstruction(
      zoneTransactInstruction({ ...base, withdrawal: splWithdrawal, cpi: true }),
      builders.zoneTransactSplCpi,
    );
    expectInstruction(
      zoneAuthorityTransactInstruction({ ...base, withdrawal: splWithdrawal }),
      builders.zoneAuthorityTransactSpl,
    );
    expectInstruction(
      zoneAuthorityTransactInstruction({ ...base, withdrawal: splWithdrawal, cpi: true }),
      builders.zoneAuthorityTransactSplCpi,
    );
  });

  it("matches merge transact and merge zone on both routes", () => {
    expectInstruction(
      mergeTransactInstruction({ tree, payer, userRecord: account(37), data: mergeData() }),
      builders.mergeTransact,
    );
    const zoneMerge = {
      tree,
      zoneProgramId: zone,
      payer,
      data: mergeData(),
      mergeViewTag: filler(41, 32) as Bytes32,
    };
    expectInstruction(mergeZoneInstruction(zoneMerge), builders.mergeZone);
    expectInstruction(mergeZoneInstruction({ ...zoneMerge, cpi: true }), builders.mergeZoneCpi);
  });

  it("matches protocol-config creation, every update variant, and pause-tree", () => {
    expectInstruction(
      createProtocolConfigInstruction({
        authority: owner,
        protocolAuthority: account(11),
        treeCreationAuthority: account(12),
        treeCreationIsPermissionless: true,
        foresterAuthority: account(13),
        zoneCreationAuthority: account(14),
        zoneCreationIsPermissionless: false,
        splInterfaceCreationIsPermissionless: true,
      }),
      builders.createProtocolConfig,
    );
    const updates: [string, ProtocolConfigUpdate][] = [
      ["updateProtocolAuthority", { field: "protocolAuthority", value: account(11) }],
      ["updateTreeCreationAuthority", { field: "treeCreationAuthority", value: account(12) }],
      ["updateForesterAuthority", { field: "foresterAuthority", value: account(13) }],
      ["updateZoneCreationAuthority", { field: "zoneCreationAuthority", value: account(14) }],
      ["updateTreeCreationPermissionless", { field: "treeCreationPermissionless", value: true }],
      ["updateZoneCreationPermissionless", { field: "zoneCreationPermissionless", value: false }],
      [
        "updateSplInterfaceCreationPermissionless",
        { field: "splInterfaceCreationPermissionless", value: true },
      ],
    ];
    for (const [name, update] of updates) {
      expectInstruction(
        updateProtocolConfigInstruction({ authority: owner, update }),
        builders[name],
      );
    }
    expectInstruction(
      pauseTreeInstruction({ authority: owner, tree, paused: true }),
      builders.pauseTree,
    );
  });

  it("matches zone-config creation and both updates", () => {
    expectInstruction(
      createZoneConfigInstruction({
        payer: account(35),
        programId: zone,
        authority: account(15),
        zoneAuthorityTransactIsEnabled: true,
      }),
      builders.createZoneConfig,
    );
    expectInstruction(
      updateZoneConfigInstruction({
        authority: account(15),
        zoneConfig: account(38),
        zoneAuthorityTransactIsEnabled: false,
      }),
      builders.updateZoneConfig,
    );
    expectInstruction(
      updateZoneConfigOwnerInstruction({
        authority: account(15),
        zoneConfig: account(38),
        newAuthority: account(39),
      }),
      builders.updateZoneConfigOwner,
    );
  });
});

describe("external data hash", () => {
  const inputs = oracle.externalDataHashes.inputs;

  it("matches the Rust transact external_data_hash", () => {
    expect(
      hex(
        externalDataHash({
          instructionDiscriminator: InstructionTag.transact,
          expiryUnixTs: 1_700_000_000n,
          relayerFee: 4_242,
          publicSolAmount: -9n,
          publicSplAmount: 11n,
          userSolAccount: inputs.userSolAccount as Address,
          userSplTokenAccount: inputs.userSplTokenAccount as Address,
          splTokenInterface: inputs.splTokenInterface as Address,
          dataHash: bytes(inputs.dataHash) as Bytes32,
          outputs: [
            {
              utxoHash: bytes(inputs.outputUtxoHashA) as Bytes32,
              ownerTag: bytes(inputs.ownerTagA) as Bytes32,
              data: bytes(inputs.outputData),
            },
            {
              utxoHash: bytes(inputs.outputUtxoHashB) as Bytes32,
              ownerTag: bytes(inputs.ownerTagB) as Bytes32,
            },
          ],
          messages: [
            {
              viewTag: bytes(inputs.messageViewTag) as Bytes32,
              data: bytes(inputs.messageData),
            },
          ],
        }),
      ),
    ).toBe(oracle.externalDataHashes.full);
  });

  it("matches the Rust all-defaults hash", () => {
    const zero = "11111111111111111111111111111111" as Address;
    expect(
      hex(
        externalDataHash({
          instructionDiscriminator: InstructionTag.zoneTransact,
          expiryUnixTs: 0n,
          relayerFee: 0,
          userSolAccount: zero,
          userSplTokenAccount: zero,
          splTokenInterface: zero,
          outputs: [],
          messages: [],
        }),
      ),
    ).toBe(oracle.externalDataHashes.minimal);
  });

  it("distinguishes empty output data from absent output data, as Rust does", () => {
    const base = {
      instructionDiscriminator: InstructionTag.transact,
      expiryUnixTs: 1n,
      relayerFee: 2,
      userSolAccount: inputs.userSolAccount as Address,
      userSplTokenAccount: inputs.userSplTokenAccount as Address,
      splTokenInterface: inputs.splTokenInterface as Address,
      messages: [],
    };
    const utxoHash = bytes(inputs.outputUtxoHashA) as Bytes32;
    const ownerTag = bytes(inputs.ownerTagA) as Bytes32;
    expect(
      hex(
        externalDataHash({
          ...base,
          outputs: [{ utxoHash, ownerTag, data: new Uint8Array(0) }],
        }),
      ),
    ).toBe(oracle.externalDataHashes.outputWithEmptyData);
    expect(hex(externalDataHash({ ...base, outputs: [{ utxoHash, ownerTag }] }))).toBe(
      oracle.externalDataHashes.outputWithNoData,
    );
    expect(oracle.externalDataHashes.outputWithEmptyData).not.toBe(
      oracle.externalDataHashes.outputWithNoData,
    );
  });

  it("matches the Rust merge external_data_hash on both instruction tags", () => {
    const merge = {
      expiryUnixTs: BigInt(inputs.mergeExpiryUnixTs),
      outputUtxoHash: bytes(inputs.mergeOutputUtxoHash) as Bytes32,
      encryptedUtxo: bytes(inputs.mergeEncryptedUtxo),
    };
    expect(
      hex(mergeExternalDataHash({ instructionTag: InstructionTag.mergeTransact, ...merge })),
    ).toBe(oracle.externalDataHashes.mergeTransact);
    expect(
      hex(mergeExternalDataHash({ instructionTag: InstructionTag.zoneMergeTransact, ...merge })),
    ).toBe(oracle.externalDataHashes.mergeZone);
  });
});

describe("re-export ledgers", () => {
  /**
   * The aggregate rows own the Rust `pub use` ledgers. Each Rust name maps to
   * the TypeScript surface that discharges it, or to `null` where the port
   * deliberately has no counterpart, with the reason. The oracle reads the
   * ledgers out of the crate source, so a name added to Rust fails here until
   * it is mapped.
   */
  function assertLedger(
    rustNames: readonly string[],
    mapping: Readonly<Record<string, string | null>>,
    surface: Readonly<Record<string, unknown>>,
  ): void {
    expect(Object.keys(mapping).sort()).toEqual([...rustNames].sort());
    for (const [rustName, tsName] of Object.entries(mapping)) {
      if (tsName === null) continue;
      expect(surface, `${rustName} -> ${tsName}`).toHaveProperty(tsName);
    }
  }

  it("maps every builders/mod.rs re-export", () => {
    assertLedger(
      oracle.ledgers.builders,
      {
        CreateAssetCounter: "createAssetCounterInstruction",
        CreateAssociatedTokenAccount: "createAssociatedTokenAccountInstruction",
        CreateProtocolConfig: "createProtocolConfigInstruction",
        CreateSplInterface: "createSplInterfaceInstruction",
        CreateTree: "createTreeInstruction",
        CreateZoneConfig: "createZoneConfigInstruction",
        Deposit: "depositInstruction",
        MergeTransact: "mergeTransactInstruction",
        MergeZone: "mergeZoneInstruction",
        PauseTree: "pauseTreeInstruction",
        Transact: "transactInstruction",
        UpdateProtocolConfig: "updateProtocolConfigInstruction",
        UpdateZoneConfig: "updateZoneConfigInstruction",
        UpdateZoneConfigOwner: "updateZoneConfigOwnerInstruction",
        ZoneAuthorityTransact: "zoneAuthorityTransactInstruction",
        ZoneDeposit: "zoneDepositInstruction",
        ZoneTransact: "zoneTransactInstruction",
        // Withdrawn from the public surface: the builder needs an address-append
        // proof no TypeScript path can produce. The decoder stays.
        BatchUpdateNullifierTree: null,
        // Argument types, erased into the builder input types at the TypeScript
        // boundary: `DepositSplAccounts` and the `TransactWithdrawal` union.
        DepositSplAccounts: null,
        TransactSolWithdrawal: null,
        TransactSplWithdrawal: null,
        TransactWithdrawal: null,
      },
      instructionsSurface,
    );
  });

  it("maps every instruction_data/mod.rs re-export", () => {
    assertLedger(
      oracle.ledgers.instructionData,
      {
        BatchUpdateNullifierTreeData: "batchUpdateNullifierTreeDataCodec",
        CreateTreeData: "createTreeDataCodec",
        CreateZoneConfigData: "createZoneConfigDataCodec",
        DepositIxData: "depositInstructionDataCodec",
        MergeTransactIxData: "mergeTransactInstructionDataCodec",
        MergeZoneIxData: "mergeZoneInstructionDataCodec",
        TransactIxData: "transactInstructionDataCodec",
        UpdateZoneConfigData: "updateZoneConfigDataCodec",
        UpdateZoneConfigOwnerData: "updateZoneConfigOwnerDataCodec",
        ZoneDepositIxData: "zoneDepositInstructionDataCodec",
        MergeExternalDataHash: "mergeExternalDataHash",
        // Component types carried inside the codecs above rather than exported
        // as codecs of their own.
        CompressedProof: null,
        InputUtxo: null,
        MessageData: null,
        OutputUtxo: null,
        OwnerTag: null,
        P256Proof: null,
        ResolvedOutput: null,
        TransactOutput: null,
        TransactProof: null,
        UtxoData: null,
        PauseTreeData: null,
        // Zero-copy borrowed views; a decoding TypeScript client has no
        // borrowed-buffer equivalent and uses the owned codecs.
        MergeTransactIxDataRef: null,
        MergeZoneIxDataRef: null,
        OutputDataRef: null,
        P256ProofRef: null,
        TransactIxDataRef: null,
        TransactOutputRef: null,
        // Written inline by `createProtocolConfigInstruction` / the update union
        // rather than through an exported codec.
        CreateProtocolConfigData: null,
        UpdateProtocolConfigData: null,
        // Constants and the tag resolver live on the package root.
        MERGE_ENCRYPTED_UTXO_LEN: null,
        MERGE_INPUT_COUNT: null,
        fetch_tag: null,
      },
      codecsSurface,
    );
  });

  it("maps every state/mod.rs re-export", () => {
    assertLedger(
      oracle.ledgers.state,
      {
        ADDRESS_TREE_HEIGHT: "ADDRESS_TREE_HEIGHT",
        ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE: "ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE",
        ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE: "ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE",
        ADDRESS_TREE_ROOT_HISTORY_CAPACITY: "ADDRESS_TREE_ROOT_HISTORY_CAPACITY",
        STATE_HEIGHT: "STATE_HEIGHT",
        ProtocolConfig: "decodeProtocolConfig",
        SplAssetCounter: "decodeSplAssetCounter",
        SplAssetRegistry: "decodeSplAssetRegistry",
        ZoneConfig: "decodeZoneConfig",
        address_tree_params: "addressTreeParams",
        state_root_offset: "STATE_ROOT_OFFSET",
        tree_account_size: "TREE_ACCOUNT_SIZE",
      },
      rootSurface,
    );
  });

  it("maps every instruction/mod.rs re-export the package root owns", () => {
    expect(oracle.ledgers.instruction).toContain("tag");
    expect(oracle.ledgers.instruction).toContain("InstructionTag");
    expect(Object.keys(InstructionTag).length).toBe(Object.keys(oracle.tags).length);
  });
});

describe("decoder acceptance", () => {
  const acceptance = oracle.decodeAcceptance;

  it("rejects exactly what the Rust decoders reject", () => {
    expect(acceptance.depositAcceptsTrailingByte).toBe(false);
    expect(() =>
      depositInstructionDataCodec.decode(bytes(acceptance.depositTrailingByteBytes)),
    ).toThrow();

    expect(acceptance.mergeAcceptsNonCanonicalBool).toBe(false);
    expect(() =>
      mergeTransactInstructionDataCodec.decode(bytes(acceptance.mergeNonCanonicalBoolBytes)),
    ).toThrow();

    expect(acceptance.protocolConfigAcceptsWrongDiscriminator).toBe(false);
    expect(() =>
      decodeProtocolConfig(bytes(acceptance.protocolConfigWrongDiscriminatorBytes)),
    ).toThrow();

    expect(acceptance.protocolConfigAcceptsShort).toBe(false);
    expect(() => decodeProtocolConfig(bytes(acceptance.protocolConfigShortBytes))).toThrow();
  });

  /**
   * The `encrypted_utxo` type prefix is not part of the merge layout, so both
   * languages read and write any first byte and the shielded-pool program is
   * what rejects a non-canonical one, with `InvalidMergeOutputScheme`. A codec
   * guard on either side would make TypeScript unable to read or rebuild an
   * instruction Rust reads, without protecting anything the program does not.
   *
   * Rust's own recorded bytes are the oracle: they are the canonical merge
   * payload with the prefix set to `0` and nothing else changed, so decoding
   * them and re-encoding the result back to the same bytes falsifies a guard at
   * either end.
   */
  it("reads and rebuilds the non-canonical merge prefix Rust reads", () => {
    expect(acceptance.mergeAcceptsNonCanonicalPrefix).toBe(true);
    expect(acceptance.mergeZoneAcceptsNonCanonicalPrefix).toBe(true);

    const canonical = bytes(oracle.instructionData.mergeTransact);
    const nonCanonical = bytes(acceptance.mergeNonCanonicalPrefixBytes);
    // `encryptedUtxo` is the last blob before the trailing `eddsaOwner` byte.
    const prefixOffset = canonical.length - MERGE_ENCRYPTED_UTXO_LENGTH - 1;
    expect(canonical[prefixOffset]).toBe(MERGE_ENCRYPTED_UTXO_TYPE_PREFIX);
    expect(
      [...canonical].flatMap((byte, index) => (byte === nonCanonical[index] ? [] : [index])),
    ).toEqual([prefixOffset]);

    const merge = mergeTransactInstructionDataCodec.decode(nonCanonical);
    expect(merge.encryptedUtxo[0]).not.toBe(MERGE_ENCRYPTED_UTXO_TYPE_PREFIX);
    expect(hex(mergeTransactInstructionDataCodec.encode(merge))).toBe(
      acceptance.mergeNonCanonicalPrefixBytes,
    );

    const zone = mergeZoneInstructionDataCodec.decode(
      bytes(acceptance.mergeZoneNonCanonicalPrefixBytes),
    );
    expect(zone.merge.encryptedUtxo).toEqual(merge.encryptedUtxo);
    expect(hex(mergeZoneInstructionDataCodec.encode(zone))).toBe(
      acceptance.mergeZoneNonCanonicalPrefixBytes,
    );

    expect(ShieldedPoolError.InvalidMergeOutputScheme).toBe(
      oracle.errors.InvalidMergeOutputScheme.code,
    );
  });

  /**
   * The write half of the same divergence, which rows I20 and I21 rest on.
   * Rust reaches its non-canonical bytes by serializing the canonical value and
   * overwriting one byte, so the vectors differ from the canonical encoding at
   * the prefix offset and nowhere else: that is what makes the prefix, rather
   * than any other field, the reason TypeScript refuses to build them.
   */
  it("pins the merge prefix guard on the encode side against Rust's own bytes", () => {
    const nonCanonical = (): MergeTransactInstructionData => {
      const value = mergeData();
      const encryptedUtxo = Uint8Array.from(value.encryptedUtxo);
      encryptedUtxo[0] = 0;
      return { ...value, encryptedUtxo };
    };
    const mergeViewTag = filler(41, 32) as Bytes32;

    const canonical = bytes(oracle.instructionData.mergeTransact);
    const rustNonCanonical = bytes(acceptance.mergeNonCanonicalPrefixBytes);
    const differing = [...canonical]
      .map((byte, index) => (byte === rustNonCanonical[index] ? -1 : index))
      .filter((index) => index >= 0);
    expect(differing).toEqual([canonical.length - 111]);
    expect(rustNonCanonical[canonical.length - 111]).toBe(0);

    expect(() => mergeTransactInstructionDataCodec.encode(nonCanonical())).toThrow(
      /INTERFACE_CODEC/,
    );
    expect(() =>
      mergeZoneInstructionDataCodec.encode({ mergeViewTag, merge: nonCanonical() }),
    ).toThrow(/INTERFACE_CODEC/);
  });
});

describe("fetch tag", () => {
  it("resolves and rejects exactly as Rust fetch_tag does", () => {
    const accounts = oracle.fetchTag.accounts.map((value) => bytes(value) as Bytes32);
    const resolve = (index: number): Bytes32 | undefined => accounts[index];
    const signingKey = bytes(oracle.fetchTag.p256SigningKey) as Bytes32;
    expect(
      hex(
        fetchTag(
          { kind: "inline", value: bytes(oracle.fetchTag.inlineValue) as Bytes32 },
          signingKey,
          resolve,
        ),
      ),
    ).toBe(oracle.fetchTag.inline);
    expect(hex(fetchTag({ kind: "account", index: 1 }, signingKey, resolve))).toBe(
      oracle.fetchTag.account1,
    );
    expect(hex(fetchTag({ kind: "p256SigningKey" }, signingKey, resolve))).toBe(
      oracle.fetchTag.p256,
    );
    expect(oracle.fetchTag.accountOutOfRangeRejects).toBe(true);
    expect(() => fetchTag({ kind: "account", index: 9 }, signingKey, resolve)).toThrow();
    expect(oracle.fetchTag.missingP256Rejects).toBe(true);
    expect(() => fetchTag({ kind: "p256SigningKey" }, undefined, resolve)).toThrow();
  });
});
