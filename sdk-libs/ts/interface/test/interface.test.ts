import { describe, expect, it } from "vitest";

import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  ADDRESS_TREE_HEIGHT,
  ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE,
  ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
  ADDRESS_TREE_ROOT_HISTORY_CAPACITY,
  DEFAULT_TREE_ADDRESS,
  FIRST_ASSET_ID,
  InstructionTag,
  InterfaceError,
  SPP_SUPPORTED_SHAPES,
  STATE_HEIGHT,
  STATE_ROOT_OFFSET,
  StateDiscriminator,
  TREE_ACCOUNT_SIZE,
  addressTreeParams,
  SHIELDED_POOL_PROGRAM_ID,
  ShieldedPoolError,
  SOL_INTERFACE,
  SPL_TOKEN_PROGRAM_ID,
  ciphertextHash,
  decodeShieldedPoolError,
  externalDataHash,
  ownerPkFieldCompressed,
  pack33,
  pkFieldCompressed,
  selectSppShape,
  validateSppShape,
  type Address,
  type Bytes16,
  type Bytes31,
  type Bytes32,
  type Bytes33,
  type Bytes64,
  type DepositInstructionData,
  type ExternalDataHashInput,
  type TransactInstructionData,
} from "../src/index.js";
import {
  addressTreeParamsCodec,
  batchUpdateNullifierTreeDataCodec,
  createZoneConfigDataCodec,
  depositInstructionDataCodec,
  mergeTransactInstructionDataCodec,
  mergeZoneInstructionDataCodec,
  updateZoneConfigDataCodec,
  updateZoneConfigOwnerDataCodec,
  zoneDepositInstructionDataCodec,
  protocolConfigAccountCodec,
  splAssetCounterAccountCodec,
  splAssetRegistryAccountCodec,
  transactInstructionDataCodec,
  zoneConfigAccountCodec,
} from "../src/codecs/index.js";
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
} from "../src/pda/index.js";
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
  type MergeTransactInstructionData,
} from "../src/instructions/index.js";
import { hexBytes, readDepositFixture } from "./fixture.js";
import { CURRENT_RUST_INTERFACE_FIXTURE } from "./current-rust-fixture.js";

const ZERO = "11111111111111111111111111111111" as Address;
const b16 = (value: number): Bytes16 => new Uint8Array(16).fill(value) as Bytes16;
const b31 = (value: number): Bytes31 => new Uint8Array(31).fill(value) as Bytes31;
const b32 = (value: number): Bytes32 => new Uint8Array(32).fill(value) as Bytes32;
const b33 = (value: number): Bytes33 => new Uint8Array(33).fill(value) as Bytes33;
const b64 = (value: number): Bytes64 => new Uint8Array(64).fill(value) as Bytes64;
const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");
const account = (address: Address, isSigner: boolean, isWritable: boolean) => ({
  address,
  isSigner,
  isWritable,
});
const pdaAddress = (index: number): Address => {
  const vector = CURRENT_RUST_INTERFACE_FIXTURE.pda.vectors[index];
  if (vector === undefined) throw new Error("missing PDA fixture");
  return vector.address;
};

function transactData(
  publicAmount?: Readonly<{ kind: "sol" | "spl"; amount: bigint }>,
): TransactInstructionData {
  return {
    proof: { rail: "eddsa", a: b32(1), b: b64(2), c: b32(3) },
    expiryUnixTs: 42n,
    relayerFee: 7,
    privateTxHash: b32(4),
    txViewingPk: b33(5),
    salt: b16(6),
    inputs: [
      {
        nullifierHash: b32(7),
        nullifierTreeRootIndex: 8,
        utxoTreeRootIndex: 9,
        treeIndex: 10,
        eddsaSignerIndex: 11,
      },
    ],
    outputs: [
      {
        utxoHash: b32(12),
        ownerTag: { kind: "inline", value: b32(13) },
        data: Uint8Array.of(14),
      },
      {
        utxoHash: b32(15),
        ownerTag: { kind: "account", index: 2 },
      },
      {
        utxoHash: b32(16),
        ownerTag: { kind: "p256SigningKey" },
      },
    ],
    messages: [{ viewTag: b32(17), data: Uint8Array.of(18, 19) }],
    ...(publicAmount?.kind === "sol" ? { publicSolAmount: publicAmount.amount } : {}),
    ...(publicAmount?.kind === "spl" ? { publicSplAmount: publicAmount.amount } : {}),
  };
}

describe("canonical values and PDAs", () => {
  it("test-interface-root-const-instruction-tag", () => {
    expect(InstructionTag).toEqual({
      transact: 0,
      deposit: 1,
      zoneTransact: 2,
      zoneAuthorityTransact: 3,
      createSplInterface: 4,
      createTree: 5,
      createProtocolConfig: 6,
      updateProtocolConfig: 7,
      pauseTree: 8,
      createZoneConfig: 9,
      updateZoneConfigOwner: 10,
      updateZoneConfig: 11,
      mergeTransact: 12,
      zoneMergeTransact: 13,
      emitEvent: 14,
      zoneDeposit: 15,
      createAssetCounter: 16,
      batchUpdateNullifierTree: 51,
    });
  });

  it("pins current Rust state and tree authorities", () => {
    expect(StateDiscriminator).toEqual(CURRENT_RUST_INTERFACE_FIXTURE.discriminators);
    expect({
      accountSize: TREE_ACCOUNT_SIZE,
      stateRootOffset: STATE_ROOT_OFFSET,
      stateHeight: STATE_HEIGHT,
      addressTreeHeight: ADDRESS_TREE_HEIGHT,
      inputQueueBatchSize: ADDRESS_TREE_INPUT_QUEUE_BATCH_SIZE,
      inputQueueZkpBatchSize: ADDRESS_TREE_INPUT_QUEUE_ZKP_BATCH_SIZE,
      rootHistoryCapacity: ADDRESS_TREE_ROOT_HISTORY_CAPACITY,
    }).toEqual(CURRENT_RUST_INTERFACE_FIXTURE.tree);
    expect(FIRST_ASSET_ID).toBe(2n);
    expect(addressTreeParams()).toEqual({
      inputQueueBatchSize: 30_000n,
      inputQueueZkpBatchSize: 250n,
      rootHistoryCapacity: 120,
      height: 40,
    });
  });

  it("matches all current Rust PDA vectors and canonical zone bumps", () => {
    const fixture = CURRENT_RUST_INTERFACE_FIXTURE.pda;
    const actual = [
      protocolConfigAddress(),
      solInterfaceAddress(),
      shieldedPoolCpiAuthorityAddress(),
      splAssetCounterAddress(),
      splAssetRegistryAddress(fixture.mint),
      splAssetVaultAddress(fixture.mint),
      zoneConfigAddress(fixture.zoneProgram)[0],
      zoneAuthAddress(fixture.zoneProgram)[0],
      associatedTokenAddress(fixture.owner, fixture.mint),
    ];
    expect(actual).toEqual(fixture.vectors.map((vector) => vector.address));
    expect(zoneConfigAddress(fixture.zoneProgram)[1]).toBe(fixture.vectors[6]?.bump);
    expect(zoneAuthAddress(fixture.zoneProgram)[1]).toBe(fixture.vectors[7]?.bump);
  });

  it("rejects malformed addresses in every PDA argument position", () => {
    const invalid = "not-an-address" as Address;
    const fixture = CURRENT_RUST_INTERFACE_FIXTURE.pda;
    for (const derive of [
      () => splAssetRegistryAddress(invalid),
      () => splAssetVaultAddress(invalid),
      () => zoneConfigAddress(invalid),
      () => zoneAuthAddress(invalid),
      () => associatedTokenAddress(invalid, fixture.mint),
      () => associatedTokenAddress(fixture.owner, invalid),
    ]) {
      expect(derive).toThrow(expect.objectContaining({ code: "INTERFACE_INVALID_ADDRESS" }));
    }
  });
});

describe("program errors and shapes", () => {
  it("pins the complete program-error map and preserves unknown codes", () => {
    expect(Object.values(ShieldedPoolError)).toEqual(
      Array.from({ length: 29 }, (_, index) => 7000 + index),
    );
    expect(decodeShieldedPoolError(7023)).toEqual({
      kind: "known",
      code: 7023,
      name: "BothPublicAmountsSet",
    });
    expect(decodeShieldedPoolError(7999)).toEqual({ kind: "unknown", code: 7999 });
    expect(() => decodeShieldedPoolError(-1)).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_INTEGER" }),
    );
  });

  it("uses the ordered immutable Rust shape set for padded selection", () => {
    expect(SPP_SUPPORTED_SHAPES.map(({ inputs, outputs }) => [inputs, outputs])).toEqual([
      [1, 1],
      [1, 2],
      [2, 2],
      [2, 3],
      [3, 3],
      [4, 3],
      [4, 4],
      [5, 3],
      [5, 4],
      [1, 8],
    ]);
    expect(selectSppShape(0, 0)).toBe(SPP_SUPPORTED_SHAPES[0]);
    expect(selectSppShape(0, 2)).toBe(SPP_SUPPORTED_SHAPES[1]);
    expect(validateSppShape(1, 1, { inputs: 2, outputs: 3 })).toBe(SPP_SUPPORTED_SHAPES[3]);
    expect(Object.isFrozen(SPP_SUPPORTED_SHAPES[0])).toBe(true);
    expect(() => selectSppShape(Number.NaN, 1)).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_SHAPE" }),
    );
  });
});

describe("merge utilities", () => {
  const compressed = hexBytes("02fb50388f29498d0a93ad25ec4c34037b9d3cc3cca4787eb6fedabe2b3003eac8");

  it("matches the current Rust packing and ciphertext hash vector", () => {
    const [low, high] = pack33(compressed);
    expect(low.slice(1)).toEqual(compressed.slice(0, 31));
    expect(high.slice(30)).toEqual(compressed.slice(31));
    const ciphertext = hexBytes(
      "d52cccc7053c653d83c840fcb12c3a1dd6ac2263a9f4c705d784dfd894234b6b5271590160bddbb7191a0eeb96646aa5397e0acb27b605aec6f1ceadcd2726cab1a675d511f202",
    );
    expect(hex(ciphertextHash(ciphertext))).toBe(
      "2418c4f8d103a80bcc365a28f6172e7cd9cbfe71a301c19f775a64187ed2f453",
    );
    for (const vector of CURRENT_RUST_INTERFACE_FIXTURE.ciphertextHashes) {
      const bytes = Uint8Array.from({ length: vector.length }, (_, index) => index % 251);
      expect(hex(ciphertextHash(bytes))).toBe(vector.hash);
    }
  });

  it("validates fixed lengths and SEC1 prefixes without curve parsing", () => {
    const odd = compressed.slice();
    odd[0] = 3;
    expect(pkFieldCompressed(odd)).not.toEqual(pkFieldCompressed(compressed));
    expect(ownerPkFieldCompressed(odd)).toEqual(ownerPkFieldCompressed(compressed));
    expect(() => pack33(compressed.slice(1))).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_LENGTH" }),
    );
    const badPrefix = compressed.slice();
    badPrefix[0] = 4;
    expect(() => pkFieldCompressed(badPrefix)).toThrow(
      expect.objectContaining({ code: "INTERFACE_CODEC" }),
    );
    expect(() => ciphertextHash(new Uint8Array())).toThrow(
      expect.objectContaining({ code: "INTERFACE_HASH" }),
    );
    expect(() => ciphertextHash(new Uint8Array(193))).toThrow(
      expect.objectContaining({ code: "INTERFACE_HASH" }),
    );
  });
});

describe("external data hash", () => {
  it("matches the exact current Rust preimage and binds nested bytes", () => {
    const fixture = CURRENT_RUST_INTERFACE_FIXTURE.externalDataHash;
    const outputData = Uint8Array.of(8, 9);
    const messageData = Uint8Array.of(11, 12, 13);
    const input = {
      instructionDiscriminator: fixture.instructionDiscriminator,
      expiryUnixTs: fixture.expiryUnixTs,
      relayerFee: fixture.relayerFee,
      publicSolAmount: fixture.publicSolAmount,
      publicSplAmount: fixture.publicSplAmount,
      userSolAccount: "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi" as Address,
      userSplTokenAccount: "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR" as Address,
      splTokenInterface: "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8" as Address,
      dataHash: b32(4),
      zoneDataHash: b32(5),
      outputs: [{ utxoHash: b32(6), ownerTag: b32(7), data: outputData }],
      messages: [{ viewTag: b32(10), data: messageData }],
    };
    expect(hex(externalDataHash(input))).toBe(fixture.expected);
    const expected = externalDataHash(input);
    outputData.fill(0xff);
    messageData.fill(0xff);
    expect(externalDataHash(input)).not.toEqual(expected);
  });

  it("rejects malformed nested lengths and positions", () => {
    expect(() =>
      externalDataHash({
        instructionDiscriminator: 0,
        expiryUnixTs: 0n,
        relayerFee: 0,
        userSolAccount: ZERO,
        userSplTokenAccount: ZERO,
        splTokenInterface: ZERO,
        outputs: [{ utxoHash: b32(1), ownerTag: new Uint8Array(31) as Bytes32 }],
        messages: [],
      }),
    ).toThrow(expect.objectContaining({ code: "INTERFACE_INVALID_LENGTH" }));
  });

  /**
   * The preimage writes four `u16` prefixes: the output count, each output's
   * data length, the message count, and each message's data length. The Rust
   * `program-libs/interface` casts instead of checking, so an oversized input
   * there hashes a shortened preimage. Both SDKs refuse it, at a size no Solana
   * transaction can carry, so the disagreement with the deployed program is
   * unreachable. `@zolana/transaction` refuses first with the Rust SDK's own
   * overflow variants; a caller reaching this function directly gets the
   * refusal here instead, and must learn which prefix overflowed rather than
   * receive a digest over truncated bytes.
   */
  describe("at the u16 prefix bounds", () => {
    const MAX = 0xffff;
    const output = Object.freeze({ utxoHash: b32(6), ownerTag: b32(7) });
    const message = Object.freeze({ viewTag: b32(10), data: new Uint8Array() });

    const bounded = (overrides: Partial<ExternalDataHashInput>): ExternalDataHashInput => ({
      instructionDiscriminator: 0,
      expiryUnixTs: 0n,
      relayerFee: 0,
      userSolAccount: ZERO,
      userSplTokenAccount: ZERO,
      splTokenInterface: ZERO,
      outputs: [],
      messages: [],
      ...overrides,
    });

    it.each([
      ["outputs", { outputs: Array.from({ length: MAX + 1 }, () => output) }],
      ["messages", { messages: Array.from({ length: MAX + 1 }, () => message) }],
      ["outputs[0].data", { outputs: [{ ...output, data: new Uint8Array(MAX + 1) }] }],
      ["messages[0].data", { messages: [{ ...message, data: new Uint8Array(MAX + 1) }] }],
      ["outputs[1].data", { outputs: [output, { ...output, data: new Uint8Array(MAX + 1) }] }],
    ])("refuses %s past the prefix and names it", (name, overrides) => {
      expect(() => externalDataHash(bounded(overrides))).toThrow(
        expect.objectContaining({
          code: "INTERFACE_INVALID_INTEGER",
          details: expect.objectContaining({ name, maximum: MAX, actual: MAX + 1 }),
        }),
      );
    });

    // The bound is inclusive, so the largest representable payload still hashes.
    // `@zolana/transaction`'s oracle test pins these digests against Rust; here
    // only the accept-or-refuse boundary itself is under test.
    it.each([
      ["output data", { outputs: [{ ...output, data: new Uint8Array(MAX) }] }],
      ["message data", { messages: [{ ...message, data: new Uint8Array(MAX) }] }],
    ])("hashes the largest %s the prefix can carry", (_name, overrides) => {
      const digest = externalDataHash(bounded(overrides));
      expect(digest).toHaveLength(32);
      expect(digest[0]).toBe(0);
    });
  });
});

describe("instruction data codecs", () => {
  it("test-interface-codecs-const-deposit-instruction-data-codec", () => {
    const fixture = readDepositFixture(
      new URL("../../fixtures/interface/deposit-instruction-v1.json", import.meta.url),
    );
    const value: DepositInstructionData = {
      viewTag: hexBytes(fixture.inputs.viewTagBytes) as Bytes32,
      owner: hexBytes(fixture.inputs.ownerBytes) as Bytes32,
      blinding: hexBytes(fixture.inputs.blindingBytes) as Bytes31,
      amount: BigInt(fixture.inputs.amount),
      memo: hexBytes(fixture.inputs.memoBytes),
    };
    const encoded = depositInstructionDataCodec.encode(value);
    expect(hex(encoded)).toBe(fixture.expected.dataBytes.slice(2));
    expect(depositInstructionDataCodec.decode(encoded)).toEqual(value);
  });

  it("strictly encodes fixed admin and zone payloads", () => {
    const batch = {
      newRoot: b32(1),
      oldRoot: b32(2),
      zkpBatchIndex: 0x1234,
      compressedProof: { a: b32(3), b: b64(4), c: b32(5) },
    };
    const batchBytes = batchUpdateNullifierTreeDataCodec.encode(batch);
    expect(batchBytes).toHaveLength(194);
    expect(batchBytes.slice(64, 66)).toEqual(Uint8Array.of(0x34, 0x12));
    expect(batchUpdateNullifierTreeDataCodec.decode(batchBytes)).toEqual(batch);
    expect(() => batchUpdateNullifierTreeDataCodec.decode(batchBytes.slice(1))).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_LENGTH" }),
    );

    const params = CURRENT_RUST_INTERFACE_FIXTURE.customTreeParams;
    expect(addressTreeParamsCodec.decode(addressTreeParamsCodec.encode(params))).toEqual(params);

    const createZone = {
      programId: SHIELDED_POOL_PROGRAM_ID,
      authority: ZERO,
      zoneAuthorityTransactIsEnabled: true,
    };
    expect(createZoneConfigDataCodec.decode(createZoneConfigDataCodec.encode(createZone))).toEqual(
      createZone,
    );
    expect(
      updateZoneConfigOwnerDataCodec.decode(
        updateZoneConfigOwnerDataCodec.encode({ newAuthority: ZERO }),
      ),
    ).toEqual({ newAuthority: ZERO });
    expect(
      updateZoneConfigDataCodec.decode(
        updateZoneConfigDataCodec.encode({ zoneAuthorityTransactIsEnabled: false }),
      ),
    ).toEqual({ zoneAuthorityTransactIsEnabled: false });
  });

  it("owns nested bytes in zone and transact decoders", () => {
    const zone = {
      viewTag: b32(1),
      owner: b32(2),
      blinding: b31(3),
      amount: 4n,
      zoneDataHash: b32(5),
      zoneData: Uint8Array.of(6),
      utxoData: { dataHash: b32(7), data: Uint8Array.of(8) },
      memo: Uint8Array.of(9),
    };
    const encodedZone = zoneDepositInstructionDataCodec.encode(zone);
    const decodedZone = zoneDepositInstructionDataCodec.decode(encodedZone);
    decodedZone.zoneData.fill(0);
    decodedZone.utxoData?.data.fill(0);
    expect(zoneDepositInstructionDataCodec.decode(encodedZone)).toEqual(zone);

    const encodedTransact = transactInstructionDataCodec.encode(transactData());
    const decodedTransact = transactInstructionDataCodec.decode(encodedTransact);
    decodedTransact.outputs[0]?.data?.fill(0);
    decodedTransact.messages[0]?.data.fill(0);
    expect(transactInstructionDataCodec.decode(encodedTransact)).toEqual(transactData());
  });

  it("test-interface-codecs-const-transact-instruction-data-codec", () => {
    const value = transactData();
    const encoded = transactInstructionDataCodec.encode(value);
    expect(encoded.slice(0, 8)).toEqual(Uint8Array.of(42, 0, 0, 0, 0, 0, 0, 0));
    expect(transactInstructionDataCodec.decode(encoded)).toEqual(value);
    expect(() => transactInstructionDataCodec.decode(Uint8Array.from([...encoded, 0]))).toThrow(
      expect.objectContaining({ code: "INTERFACE_CODEC" }),
    );
  });

  it("preserves both proof rails and every owner-tag variant", () => {
    const value: TransactInstructionData = {
      ...transactData(),
      p256SigningPkX: b32(20),
      proof: {
        rail: "p256",
        a: b32(1),
        b: b64(2),
        c: b32(3),
        commitment: b32(4),
        commitmentPok: b32(5),
      },
    };
    expect(transactInstructionDataCodec.decode(transactInstructionDataCodec.encode(value))).toEqual(
      value,
    );
  });

  it("rejects mutated lengths, variants, and integers", () => {
    expect(() =>
      depositInstructionDataCodec.encode({
        viewTag: new Uint8Array(31) as Bytes32,
        owner: b32(0),
        blinding: b31(0),
        amount: 0n,
      }),
    ).toThrow(expect.objectContaining({ code: "INTERFACE_INVALID_LENGTH" }));
    expect(() =>
      transactInstructionDataCodec.encode({
        ...transactData(),
        relayerFee: 65_536,
      }),
    ).toThrow(expect.objectContaining({ code: "INTERFACE_INVALID_INTEGER" }));
    const encoded = transactInstructionDataCodec.encode(transactData());
    encoded[92] = 9;
    expect(() => transactInstructionDataCodec.decode(encoded)).toThrow(InterfaceError);
  });

  it("round-trips boundary values and returns owned bytes", () => {
    for (const amount of [0n, 1n, (1n << 64n) - 1n]) {
      for (const memoLength of [0, 1, 255, 256]) {
        const original = new Uint8Array(memoLength).fill(memoLength & 0xff);
        const memo = original.slice();
        const value: DepositInstructionData = {
          viewTag: b32(1),
          owner: b32(2),
          blinding: b31(3),
          amount,
          memo,
        };
        const encoded = depositInstructionDataCodec.encode(value);
        memo.fill(0);
        const decoded = depositInstructionDataCodec.decode(encoded);
        expect(decoded.amount).toBe(amount);
        expect(decoded.memo).toEqual(original);
        decoded.viewTag.fill(9);
        expect(depositInstructionDataCodec.decode(encoded).viewTag).toEqual(b32(1));
      }
    }
  });
});

describe("state account codecs", () => {
  it("test-interface-account-codecs", () => {
    const protocol = {
      authority: ZERO,
      treeCreationAuthority: SHIELDED_POOL_PROGRAM_ID,
      treeCreationIsPermissionless: true,
      foresterAuthority: SOL_INTERFACE,
      zoneCreationAuthority: SPL_TOKEN_PROGRAM_ID,
      zoneCreationIsPermissionless: false,
      splInterfaceCreationIsPermissionless: true,
    } as const;
    expect(protocolConfigAccountCodec.decode(protocolConfigAccountCodec.encode(protocol))).toEqual(
      protocol,
    );
    expect(
      splAssetCounterAccountCodec.decode(splAssetCounterAccountCodec.encode({ nextId: 2n })),
    ).toEqual({ nextId: 2n });
    const registry = { mint: ZERO, assetId: 9n };
    expect(
      splAssetRegistryAccountCodec.decode(splAssetRegistryAccountCodec.encode(registry)),
    ).toEqual(registry);
    const zone = {
      authority: ZERO,
      programId: SHIELDED_POOL_PROGRAM_ID,
      zoneAuthorityTransactIsEnabled: true,
      bump: 254,
    };
    expect(zoneConfigAccountCodec.decode(zoneConfigAccountCodec.encode(zone))).toEqual(zone);
  });

  it("rejects account size and discriminator mutations", () => {
    const counter = splAssetCounterAccountCodec.encode({ nextId: 2n });
    expect(() => splAssetCounterAccountCodec.decode(counter.slice(1))).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_ACCOUNT_DATA" }),
    );
    counter[0] ^= 1;
    expect(() => splAssetCounterAccountCodec.decode(counter)).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_DISCRIMINATOR" }),
    );
  });

  it("matches Rust nonzero state flags and ignores reserved bytes", () => {
    const protocol = protocolConfigAccountCodec.encode({
      authority: ZERO,
      treeCreationAuthority: ZERO,
      treeCreationIsPermissionless: false,
      foresterAuthority: ZERO,
      zoneCreationAuthority: ZERO,
      zoneCreationIsPermissionless: false,
      splInterfaceCreationIsPermissionless: false,
    });
    protocol[129] = 2;
    protocol[130] = 0xff;
    expect(protocolConfigAccountCodec.decode(protocol)).toMatchObject({
      treeCreationIsPermissionless: true,
      zoneCreationIsPermissionless: true,
      splInterfaceCreationIsPermissionless: false,
    });

    const zone = zoneConfigAccountCodec.encode({
      authority: ZERO,
      programId: SHIELDED_POOL_PROGRAM_ID,
      zoneAuthorityTransactIsEnabled: false,
      bump: 1,
    });
    zone[65] = 2;
    expect(zoneConfigAccountCodec.decode(zone).zoneAuthorityTransactIsEnabled).toBe(true);

    const counter = splAssetCounterAccountCodec.encode({ nextId: 2n });
    counter.fill(0xff, 1, 8);
    expect(splAssetCounterAccountCodec.decode(counter)).toEqual({ nextId: 2n });
  });
});

describe("instruction builders", () => {
  const merge: MergeTransactInstructionData = {
    expiryUnixTs: 1n,
    proof: {
      a: b32(1),
      b: b64(2),
      c: b32(3),
      commitment: b32(4),
      commitmentPok: b32(5),
    },
    outputUtxoHash: b32(6),
    nullifiers: Array.from({ length: 8 }, (_, index) => b32(index)),
    utxoTreeRootIndexes: [0, 1, 2, 3, 4, 5, 6, 7],
    nullifierTreeRootIndexes: [8, 9, 10, 11, 12, 13, 14, 15],
    privateTxHash: b32(7),
    encryptedUtxo: Uint8Array.from({ length: 110 }, (_, index) => (index === 0 ? 2 : 0)),
    eddsaOwner: false,
  };

  it("strictly decodes merge and zone-merge payloads", () => {
    const encoded = mergeTransactInstructionDataCodec.encode(merge);
    expect(encoded).toHaveLength(668);
    expect(mergeTransactInstructionDataCodec.decode(encoded)).toEqual(merge);
    const zone = { mergeViewTag: b32(9), merge };
    const encodedZone = mergeZoneInstructionDataCodec.encode(zone);
    expect(encodedZone).toHaveLength(700);
    expect(mergeZoneInstructionDataCodec.decode(encodedZone)).toEqual(zone);
    encoded[232] = 7;
    expect(() => mergeTransactInstructionDataCodec.decode(encoded)).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_LENGTH" }),
    );
  });

  it("test-interface-instructions-function-deposit-instruction", () => {
    const data = {
      viewTag: b32(3),
      owner: b32(4),
      blinding: b31(5),
      amount: 42n,
      memo: new TextEncoder().encode("fixture"),
    };
    const built = depositInstruction({
      tree: "4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi" as Address,
      depositor: "8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR" as Address,
      data,
    });
    const fixture = readDepositFixture(
      new URL("../../fixtures/interface/deposit-instruction-v1.json", import.meta.url),
    );
    expect(hex(built.data)).toBe(fixture.expected.dataBytes);
    expect(built.programAddress).toBe(fixture.expected.programId);
    expect(built.accounts).toHaveLength(fixture.expected.accounts.length);
  });

  it("builds every admin and setup instruction with exact tags", () => {
    const instructions = [
      [createAssetCounterInstruction({ authority: ZERO }), 16],
      [createSplInterfaceInstruction({ authority: ZERO, mint: ZERO }), 4],
      [
        createTreeInstruction({
          authority: ZERO,
          tree: DEFAULT_TREE_ADDRESS,
        }),
        5,
      ],
      [
        createTreeInstruction({
          authority: ZERO,
          tree: DEFAULT_TREE_ADDRESS,
          nullifierTreeParams: CURRENT_RUST_INTERFACE_FIXTURE.customTreeParams,
        }),
        5,
      ],
      [
        createProtocolConfigInstruction({
          authority: ZERO,
          protocolAuthority: ZERO,
          treeCreationAuthority: ZERO,
          treeCreationIsPermissionless: true,
          foresterAuthority: ZERO,
          zoneCreationAuthority: ZERO,
          zoneCreationIsPermissionless: false,
          splInterfaceCreationIsPermissionless: true,
        }),
        6,
      ],
      [
        updateProtocolConfigInstruction({
          authority: ZERO,
          update: { field: "protocolAuthority", value: ZERO },
        }),
        7,
      ],
      [
        pauseTreeInstruction({
          authority: ZERO,
          tree: DEFAULT_TREE_ADDRESS,
          paused: true,
        }),
        8,
      ],
      [
        createZoneConfigInstruction({
          payer: ZERO,
          programId: SHIELDED_POOL_PROGRAM_ID,
          authority: ZERO,
          zoneAuthorityTransactIsEnabled: true,
        }),
        9,
      ],
      [
        updateZoneConfigOwnerInstruction({
          authority: ZERO,
          zoneConfig: ZERO,
          newAuthority: SHIELDED_POOL_PROGRAM_ID,
        }),
        10,
      ],
      [
        updateZoneConfigInstruction({
          authority: ZERO,
          zoneConfig: ZERO,
          zoneAuthorityTransactIsEnabled: true,
        }),
        11,
      ],
    ] as const;
    for (const [built, tag] of instructions) {
      expect(built.programAddress).toBe(SHIELDED_POOL_PROGRAM_ID);
      expect(built.data[0]).toBe(tag);
    }
  });

  it("matches exact current Rust asset-counter and SPL-interface builders", () => {
    const fixture = CURRENT_RUST_INTERFACE_FIXTURE.builders;
    const assetCounter = createAssetCounterInstruction({
      authority: CURRENT_RUST_INTERFACE_FIXTURE.pda.owner,
    });
    const splInterface = createSplInterfaceInstruction({
      authority: CURRENT_RUST_INTERFACE_FIXTURE.pda.owner,
      mint: CURRENT_RUST_INTERFACE_FIXTURE.pda.mint,
    });
    expect({
      programAddress: assetCounter.programAddress,
      data: hex(assetCounter.data),
      accounts: assetCounter.accounts,
    }).toEqual({
      programAddress: fixture.programAddress,
      ...fixture.createAssetCounter,
    });
    expect({
      programAddress: splInterface.programAddress,
      data: hex(splInterface.data),
      accounts: splInterface.accounts,
    }).toEqual({
      programAddress: fixture.programAddress,
      ...fixture.createSplInterface,
    });

    assetCounter.data[0] = 0;
    const assetAuthority = assetCounter.accounts[0];
    const splMint = splInterface.accounts[4];
    if (assetAuthority === undefined || splMint === undefined)
      throw new Error("missing fixture meta");
    assetAuthority.address = ZERO;
    splInterface.data[0] = 0;
    splMint.address = ZERO;
    expect(
      hex(
        createAssetCounterInstruction({ authority: CURRENT_RUST_INTERFACE_FIXTURE.pda.owner }).data,
      ),
    ).toBe(fixture.createAssetCounter.data);
    expect(
      createSplInterfaceInstruction({
        authority: CURRENT_RUST_INTERFACE_FIXTURE.pda.owner,
        mint: CURRENT_RUST_INTERFACE_FIXTURE.pda.mint,
      }).accounts,
    ).toEqual(fixture.createSplInterface.accounts);
  });

  it("rejects malformed asset-counter and SPL-interface addresses", () => {
    const invalid = "invalid" as Address;
    expect(() => createAssetCounterInstruction({ authority: invalid })).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_ADDRESS" }),
    );
    expect(() =>
      createSplInterfaceInstruction({
        authority: CURRENT_RUST_INTERFACE_FIXTURE.pda.owner,
        mint: invalid,
      }),
    ).toThrow(expect.objectContaining({ code: "INTERFACE_INVALID_ADDRESS" }));
  });

  it("builds ATA, transact, zone, and merge variants", () => {
    const ata = createAssociatedTokenAccountInstruction({
      payer: ZERO,
      owner: ZERO,
      mint: ZERO,
    });
    expect(ata.programAddress).toBe(ASSOCIATED_TOKEN_PROGRAM_ID);
    expect(ata.data).toEqual(Uint8Array.of(1));

    const privateData = transactData();
    expect(
      transactInstruction({
        payer: ZERO,
        tree: DEFAULT_TREE_ADDRESS,
        data: privateData,
      }).data[0],
    ).toBe(0);
    const solData = transactData({ kind: "sol", amount: -1n });
    expect(
      transactInstruction({
        payer: ZERO,
        tree: DEFAULT_TREE_ADDRESS,
        withdrawal: { kind: "sol", recipient: ZERO },
        data: solData,
      }).accounts,
    ).toHaveLength(6);
    const splData = transactData({ kind: "spl", amount: -1n });
    expect(
      transactInstruction({
        payer: ZERO,
        tree: DEFAULT_TREE_ADDRESS,
        withdrawal: {
          kind: "spl",
          cpiAuthority: ZERO,
          splTokenInterface: ZERO,
          recipient: ZERO,
          userTokenAccount: ZERO,
          tokenProgram: SPL_TOKEN_PROGRAM_ID,
        },
        data: splData,
      }).accounts,
    ).toHaveLength(9);

    const zoneInput = {
      payer: ZERO,
      tree: DEFAULT_TREE_ADDRESS,
      zoneProgramId: SHIELDED_POOL_PROGRAM_ID,
      data: privateData,
    };
    expect(zoneTransactInstruction(zoneInput).data[0]).toBe(2);
    expect(zoneAuthorityTransactInstruction(zoneInput).data[0]).toBe(3);
    expect(
      zoneDepositInstruction({
        tree: DEFAULT_TREE_ADDRESS,
        depositor: ZERO,
        viewTag: b32(1),
        owner: b32(2),
        blinding: b31(3),
        amount: 4n,
        zoneProgramId: SHIELDED_POOL_PROGRAM_ID,
        zoneDataHash: b32(5),
        zoneData: Uint8Array.of(6),
      }).data[0],
    ).toBe(15);
    expect(
      mergeTransactInstruction({
        tree: DEFAULT_TREE_ADDRESS,
        payer: ZERO,
        userRecord: ZERO,
        data: merge,
      }).data[0],
    ).toBe(12);
    expect(
      mergeZoneInstruction({
        tree: DEFAULT_TREE_ADDRESS,
        zoneProgramId: SHIELDED_POOL_PROGRAM_ID,
        payer: ZERO,
        data: merge,
        mergeViewTag: b32(9),
      }).data[0],
    ).toBe(13);
  });

  it("routes exact default and policy-zone merge accounts in both modes", () => {
    const { mint: payer, owner: tree, zoneProgram } = CURRENT_RUST_INTERFACE_FIXTURE.pda;
    const defaultMerge = mergeTransactInstruction({
      tree,
      payer,
      userRecord: ZERO,
      data: merge,
    });
    expect(defaultMerge).toEqual({
      programAddress: SHIELDED_POOL_PROGRAM_ID,
      accounts: [
        account(tree, false, true),
        account(payer, true, true),
        account(ZERO, false, false),
        account(ZERO, false, false),
        account(SHIELDED_POOL_PROGRAM_ID, false, false),
      ],
      data: Uint8Array.from([
        InstructionTag.mergeTransact,
        ...mergeTransactInstructionDataCodec.encode(merge),
      ]),
    });

    const mergeViewTag = b32(9);
    const outer = mergeZoneInstruction({
      tree,
      zoneProgramId: zoneProgram,
      payer,
      data: merge,
      mergeViewTag,
    });
    const cpi = mergeZoneInstruction({
      tree,
      zoneProgramId: zoneProgram,
      payer,
      data: merge,
      mergeViewTag,
      cpi: true,
    });
    const zoneAuthority = pdaAddress(7);
    const payload = Uint8Array.from([
      13,
      ...mergeZoneInstructionDataCodec.encode({ mergeViewTag, merge }),
    ]);
    expect(outer).toEqual({
      programAddress: zoneProgram,
      accounts: [
        account(tree, false, true),
        account(zoneAuthority, false, false),
        account(payer, true, true),
        account(ZERO, false, false),
        account(SHIELDED_POOL_PROGRAM_ID, false, false),
      ],
      data: payload,
    });
    expect(cpi).toEqual({
      ...outer,
      programAddress: SHIELDED_POOL_PROGRAM_ID,
      accounts: [
        account(tree, false, true),
        account(zoneAuthority, true, false),
        account(payer, true, true),
        account(ZERO, false, false),
        account(SHIELDED_POOL_PROGRAM_ID, false, false),
      ],
    });
  });

  it("routes exact zone-config and SOL/SPL deposit outer and CPI accounts", () => {
    const { mint: payer, owner: tree, zoneProgram } = CURRENT_RUST_INTERFACE_FIXTURE.pda;
    const zoneAuthority = pdaAddress(7);
    const create = createZoneConfigInstruction({
      payer,
      programId: zoneProgram,
      authority: tree,
      zoneAuthorityTransactIsEnabled: true,
    });
    expect(create.accounts).toEqual([
      account(payer, true, true),
      account(protocolConfigAddress(), false, false),
      account(zoneAuthority, true, true),
      account(ZERO, false, false),
    ]);

    const common = {
      tree,
      depositor: payer,
      viewTag: b32(1),
      owner: b32(2),
      blinding: b31(3),
      amount: 4n,
      zoneProgramId: zoneProgram,
      zoneDataHash: b32(5),
      zoneData: Uint8Array.of(6),
    };
    const solOuter = zoneDepositInstruction(common);
    const solCpi = zoneDepositInstruction({ ...common, cpi: true });
    expect(solOuter.programAddress).toBe(zoneProgram);
    expect(solOuter.accounts).toEqual([
      account(tree, false, true),
      account(payer, true, true),
      account(zoneAuthority, false, false),
      account(ZERO, false, false),
      account(SOL_INTERFACE, false, true),
      account(payer, false, true),
      account(SHIELDED_POOL_PROGRAM_ID, false, false),
    ]);
    expect(solCpi.accounts).toEqual([
      ...solOuter.accounts.slice(0, 2),
      account(zoneAuthority, true, false),
      ...solOuter.accounts.slice(3),
    ]);
    expect(solCpi.programAddress).toBe(SHIELDED_POOL_PROGRAM_ID);
    expect(solCpi.data).toEqual(solOuter.data);

    const spl = {
      userToken: payer,
      splTokenInterface: pdaAddress(5),
      registry: pdaAddress(4),
      tokenProgram: SPL_TOKEN_PROGRAM_ID,
    };
    const splOuter = zoneDepositInstruction({ ...common, spl });
    const splCpi = zoneDepositInstruction({ ...common, spl, cpi: true });
    expect(splOuter.accounts).toEqual([
      account(tree, false, true),
      account(payer, true, true),
      account(zoneAuthority, false, false),
      account(spl.userToken, false, true),
      account(spl.splTokenInterface, false, true),
      account(spl.registry, false, false),
      account(SPL_TOKEN_PROGRAM_ID, false, false),
      account(SHIELDED_POOL_PROGRAM_ID, false, false),
    ]);
    expect(splCpi.accounts[2]).toEqual(account(zoneAuthority, true, false));
    expect(splCpi.data).toEqual(splOuter.data);
  });

  it("routes exact SOL/SPL zone transact accounts and owner index", () => {
    const { mint: payer, owner: tree, zoneProgram } = CURRENT_RUST_INTERFACE_FIXTURE.pda;
    const zoneAuthority = pdaAddress(7);
    const solData = transactData({ kind: "sol", amount: -1n });
    const solWithdrawal = { kind: "sol" as const, recipient: payer };
    for (const build of [zoneTransactInstruction, zoneAuthorityTransactInstruction]) {
      const outer = build({
        payer,
        tree,
        zoneProgramId: zoneProgram,
        withdrawal: solWithdrawal,
        data: solData,
      });
      const cpi = build({
        payer,
        tree,
        zoneProgramId: zoneProgram,
        withdrawal: solWithdrawal,
        data: solData,
        cpi: true,
      });
      expect(outer.accounts).toEqual([
        account(payer, true, true),
        account(tree, false, true),
        account(zoneAuthority, false, false),
        account(SOL_INTERFACE, false, true),
        account(payer, false, true),
        account(ZERO, false, false),
        account(SHIELDED_POOL_PROGRAM_ID, false, false),
      ]);
      expect(cpi.accounts[2]).toEqual(account(zoneAuthority, true, false));
      expect(cpi.data).toEqual(outer.data);
      expect(transactInstructionDataCodec.decode(outer.data.slice(1)).outputs[1]?.ownerTag).toEqual(
        {
          kind: "account",
          index: 2,
        },
      );
    }

    const splData = transactData({ kind: "spl", amount: -1n });
    const splWithdrawal = {
      kind: "spl" as const,
      cpiAuthority: zoneAuthority,
      splTokenInterface: pdaAddress(5),
      recipient: payer,
      userTokenAccount: tree,
      tokenProgram: SPL_TOKEN_PROGRAM_ID,
    };
    for (const build of [zoneTransactInstruction, zoneAuthorityTransactInstruction]) {
      const outer = build({
        payer,
        tree,
        zoneProgramId: zoneProgram,
        withdrawal: splWithdrawal,
        data: splData,
      });
      const cpi = build({
        payer,
        tree,
        zoneProgramId: zoneProgram,
        withdrawal: splWithdrawal,
        data: splData,
        cpi: true,
      });
      expect(outer.accounts).toEqual([
        account(payer, true, true),
        account(tree, false, true),
        account(zoneAuthority, false, false),
        account(zoneAuthority, false, false),
        account(splWithdrawal.splTokenInterface, false, true),
        account(payer, false, true),
        account(tree, false, true),
        account(SPL_TOKEN_PROGRAM_ID, false, false),
        account(ZERO, false, false),
        account(SHIELDED_POOL_PROGRAM_ID, false, false),
      ]);
      expect(cpi.accounts[2]).toEqual(account(zoneAuthority, true, false));
      expect(cpi.data).toEqual(outer.data);
    }
  });

  it("preserves malformed settlement combinations for program validation", () => {
    expect(
      transactInstruction({
        payer: ZERO,
        tree: DEFAULT_TREE_ADDRESS,
        withdrawal: { kind: "sol", recipient: ZERO },
        data: transactData(),
      }).accounts,
    ).toHaveLength(6);
  });

  it("rejects merge-shape mutations", () => {
    expect(() =>
      mergeTransactInstruction({
        tree: DEFAULT_TREE_ADDRESS,
        payer: ZERO,
        userRecord: ZERO,
        data: { ...merge, nullifiers: merge.nullifiers.slice(1) },
      }),
    ).toThrow(expect.objectContaining({ code: "INTERFACE_INVALID_LENGTH" }));
  });
});
