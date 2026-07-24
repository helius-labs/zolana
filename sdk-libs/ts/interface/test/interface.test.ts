import { describe, expect, it } from "vitest";

import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  DEFAULT_TREE_ADDRESS,
  InstructionTag,
  InterfaceError,
  SHIELDED_POOL_PROGRAM_ID,
  SOL_INTERFACE,
  SPL_TOKEN_PROGRAM_ID,
  type Address,
  type Bytes16,
  type Bytes31,
  type Bytes32,
  type Bytes33,
  type Bytes64,
  type DepositInstructionData,
  type TransactInstructionData,
} from "../src/index.js";
import {
  depositInstructionDataCodec,
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
  zoneConfigAddress,
} from "../src/pda/index.js";
import {
  batchUpdateNullifierTreeInstruction,
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

const ZERO = "11111111111111111111111111111111" as Address;
const b16 = (value: number): Bytes16 => new Uint8Array(16).fill(value) as Bytes16;
const b31 = (value: number): Bytes31 => new Uint8Array(31).fill(value) as Bytes31;
const b32 = (value: number): Bytes32 => new Uint8Array(32).fill(value) as Bytes32;
const b33 = (value: number): Bytes33 => new Uint8Array(33).fill(value) as Bytes33;
const b64 = (value: number): Bytes64 => new Uint8Array(64).fill(value) as Bytes64;
const hex = (value: Uint8Array): string =>
  [...value].map((byte) => byte.toString(16).padStart(2, "0")).join("");

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

  it("test-interface-pda-functions", () => {
    expect(protocolConfigAddress()).toBe("5jjGnt3aqRhhzpaNBSSBJfQcZsAZQBCdhzDuaLRmgZcj");
    expect(solInterfaceAddress()).toBe(SOL_INTERFACE);
    expect(shieldedPoolCpiAuthorityAddress()).toBe("6zQNhLqFHhWaP8JNYeHzQ9a1DfBH627gzibFv1ZaaM8E");
    expect(splAssetCounterAddress()).toBe("77YYUwfwXB5BS7bEWpj4aNGkiqz6H6PE2mz7BUVLdwPn");
    expect(splAssetRegistryAddress(ZERO)).toBe("2hvmk7fEKrgvYor9L3cBuBBa7m4AhguKJoCpN9yck43g");
    expect(splAssetVaultAddress(ZERO)).toBe("AZR8qq1GyNwnZTRwvui7bLb7fkdu5MmxBzae1AtVnxnd");
    expect(zoneConfigAddress(ZERO)).toEqual(["C5NTe24T2Z4avgpPBhZYUvysKUwudWRTiPHP9GKeJq6y", 255]);
    expect(associatedTokenAddress(ZERO, ZERO)).toBe("2a8MS8dWyyYNgBHgtzeTwrsDKsE6RnCoUqnonB4C8Xc3");
  });

  it("rejects malformed addresses before derivation", () => {
    expect(() => splAssetRegistryAddress("0" as Address)).toThrow(
      expect.objectContaining({ code: "INTERFACE_INVALID_ADDRESS" }),
    );
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
    encryptedUtxo: new Uint8Array(110),
    eddsaOwner: false,
  };

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
      [
        batchUpdateNullifierTreeInstruction({
          authority: ZERO,
          tree: DEFAULT_TREE_ADDRESS,
          newRoot: b32(1),
          oldRoot: b32(2),
          zkpBatchIndex: 3,
          compressedProofA: b32(4),
          compressedProofB: b64(5),
          compressedProofC: b32(6),
        }),
        51,
      ],
      [createAssetCounterInstruction({ authority: ZERO }), 16],
      [createSplInterfaceInstruction({ authority: ZERO, mint: ZERO }), 4],
      [
        createTreeInstruction({
          authority: ZERO,
          tree: DEFAULT_TREE_ADDRESS,
          owner: ZERO,
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
    ).toHaveLength(8);

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

  it("rejects settlement and merge-shape mutations", () => {
    expect(() =>
      transactInstruction({
        payer: ZERO,
        tree: DEFAULT_TREE_ADDRESS,
        withdrawal: { kind: "sol", recipient: ZERO },
        data: transactData(),
      }),
    ).toThrow(expect.objectContaining({ code: "INTERFACE_CODEC" }));
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
