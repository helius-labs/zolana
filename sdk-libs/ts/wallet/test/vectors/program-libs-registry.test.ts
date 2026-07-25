import { describe, expect, it } from "vitest";

import fixture from "../../../vectors/program-libs-parity-v1.json" with { type: "json" };
import { decodeUserRecordAccount, senderViewingPublicKey } from "../../src/registry.js";

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

const registry = fixture.userRegistry;

function account(dataHex: string): Parameters<typeof decodeUserRecordAccount>[0] {
  return {
    owner: registry.constants.programId,
    lamports: 0n,
    data: hexToBytes(dataHex),
    executable: false,
    rentEpoch: 0n,
  } as Parameters<typeof decodeUserRecordAccount>[0];
}

describe("program-libs/user-registry-interface/src/lib.rs constants", () => {
  it("uses the Rust program id", () => {
    expect(registry.constants.programId).toBe("EXM6UUA56UJySzRDCx4dKwN6Xdcrkq3kmizqgZwgwNEc");
  });

  it("uses the Rust record seed", () => {
    expect(registry.constants.recordSeed).toBe("zolana/registry/v0");
    expect(new TextDecoder().decode(hexToBytes(registry.constants.recordSeedHex))).toBe(
      "zolana/registry/v0",
    );
  });

  it("agrees on the key widths", () => {
    expect(registry.constants.p256PubkeyLen).toBe(33);
    expect(registry.constants.nullifierPubkeyLen).toBe(32);
    expect(registry.constants.syncDelegateEntrySerializedLen).toBe(106);
  });
});

describe("program-libs/user-registry-interface/src/state.rs against decodeUserRecordAccount", () => {
  for (const vector of registry.state.records) {
    it(`decodes the Rust account bytes for ${vector.name}`, () => {
      const record = decodeUserRecordAccount(account(vector.accountData));
      expect(record.owner).toBe(vector.value.owner);
      expect(record.bump).toBe(vector.value.bump);
      expect(record.mergingEnabled).toBe(vector.value.mergingEnabled);
      expect(bytesToHex(record.nullifierPublicKey)).toBe(vector.value.nullifierPubkey);
      expect(bytesToHex(record.viewingPublicKey)).toBe(vector.value.viewingPubkey);
      expect(record.ownerP256 === undefined ? null : bytesToHex(record.ownerP256)).toBe(
        vector.value.ownerP256,
      );
      expect(record.syncDelegate === undefined ? null : bytesToHex(record.syncDelegate)).toBe(
        vector.value.syncDelegate,
      );
      expect(record.entries).toHaveLength(vector.entryCount);
      record.entries.forEach((entry, index) => {
        const expected = vector.value.entries[index];
        expect(expected).toBeDefined();
        if (expected === undefined) return;
        expect(bytesToHex(entry.delegate)).toBe(expected.delegate);
        expect(bytesToHex(entry.syncPublicKey)).toBe(expected.syncPubkey);
        expect(bytesToHex(entry.viewingPublicKey)).toBe(expected.viewingPubkey);
        expect(entry.createdAt).toBe(BigInt(expected.createdAt));
      });
    });

    it(`derives the same sender viewing key as sender_viewing_pubkey for ${vector.name}`, () => {
      const record = decodeUserRecordAccount(account(vector.accountData));
      expect(bytesToHex(senderViewingPublicKey(record))).toBe(vector.senderViewingPubkey);
    });
  }

  it("falls back to the record's own viewing key when a delegate has no entries", () => {
    // The Rust `sender_viewing_pubkey` reads `entries.last()` only when
    // `sync_delegate` is set, and falls back when the list is empty.
    const vector = registry.state.records.find(
      (entry) => entry.name === "delegate-without-entries",
    );
    expect(vector).toBeDefined();
    if (vector === undefined) return;
    expect(vector.senderViewingPubkey).toBe(vector.value.viewingPubkey);
    const record = decodeUserRecordAccount(account(vector.accountData));
    expect(bytesToHex(senderViewingPublicKey(record))).toBe(vector.value.viewingPubkey);
  });

  it("prefers the newest delegate entry when one exists", () => {
    const vector = registry.state.records.find((entry) => entry.name === "full");
    expect(vector).toBeDefined();
    if (vector === undefined) return;
    const last = vector.value.entries.at(-1);
    expect(vector.senderViewingPubkey).toBe(last?.viewingPubkey);
  });

  it("refuses account data whose first byte is not the discriminator", () => {
    const vector = registry.state.records[0];
    expect(vector).toBeDefined();
    if (vector === undefined) return;
    expect(registry.constants.userRecordDiscriminator).toBe(1);
    const wrong = hexToBytes(vector.accountData);
    wrong[0] = 9;
    expect(() => decodeUserRecordAccount(account(bytesToHex(wrong)))).toThrow();
  });

  it("refuses a record whose merging flag is neither 0 nor 1", () => {
    const vector = registry.state.records[0];
    expect(vector).toBeDefined();
    if (vector === undefined) return;
    const bytes = hexToBytes(vector.accountData);
    bytes[bytes.length - 1] = 2;
    expect(() => decodeUserRecordAccount(account(bytesToHex(bytes)))).toThrow();
  });

  it("fits inside the space_for allocation, which reserves the Some form of each Option", () => {
    // `space_for` counts `1 + P256_PUBKEY_LEN` for `owner_p256` and `1 + 32` for
    // `sync_delegate` whether or not they are set, so a record with either
    // absent is shorter than its allocation rather than equal to it. The full
    // record is the one that lands on the bound.
    for (const vector of registry.state.records) {
      expect(hexToBytes(vector.accountData).length).toBeLessThanOrEqual(vector.spaceFor);
    }
    const full = registry.state.records.find((entry) => entry.name === "full");
    expect(full).toBeDefined();
    if (full === undefined) return;
    expect(hexToBytes(full.accountData)).toHaveLength(full.spaceFor);
  });
});

describe("program-libs/user-registry-interface/src/instruction.rs discriminators", () => {
  it("numbers the six instructions the way Rust does", () => {
    expect(registry.instruction.discriminators).toEqual({
      register: 0,
      setSyncDelegate: 1,
      rotateSyncDelegateKey: 2,
      revokeSyncDelegate: 3,
      setMergingEnabled: 4,
      updateKeys: 5,
    });
  });

  it("encodes the merging flag as a single borsh bool", () => {
    expect(registry.instruction.payloads.setMergingEnabledTrue).toBe("01");
    expect(registry.instruction.payloads.setMergingEnabledFalse).toBe("00");
  });
});
