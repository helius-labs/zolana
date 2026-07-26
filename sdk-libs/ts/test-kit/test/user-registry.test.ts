import type { Address, Bytes32, Signature, Transaction } from "@zolana/interface";
import { describe, expect, it } from "vitest";

import {
  createTestNativeSigner,
  enableMerging,
  setMergingEnabledInstruction,
  TestRpc,
  userRecordAddress,
} from "../src/node/index.js";

const REGISTRY_PROGRAM = "EXM6UUA56UJySzRDCx4dKwN6Xdcrkq3kmizqgZwgwNEc" as Address;
const SIGNATURE = "1111111111111111111111111111111111111111111111111111111111111111" as Signature;

function bytes32(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

/**
 * A legacy message requiring only `signer`: the three privilege counts, the
 * account count, that one key, a blockhash, and no instructions. The signer
 * locates its own slot by scanning these keys, so a stand-in transaction has to
 * carry a real account list.
 */
function oneSignerMessage(signer: Address): Uint8Array {
  return Uint8Array.from([1, 0, 0, 1, ...decodeBase58(signer), ...new Uint8Array(32), 0]);
}

function recordData(owner: Address, bump: number, enabled: boolean): Uint8Array {
  const ownerBytes = decodeBase58(owner);
  return Uint8Array.from([
    1,
    ...ownerBytes,
    bump,
    0,
    ...new Uint8Array(32),
    ...new Uint8Array(33),
    0,
    0,
    0,
    0,
    0,
    enabled ? 1 : 0,
  ]);
}

describe("user registry merge setup", () => {
  it("constructs the frozen set-merging instruction accounts and data", () => {
    const owner = createTestNativeSigner(bytes32(7)).address;
    const record = userRecordAddress(owner);
    expect(
      setMergingEnabledInstruction({ owner, userRecord: record.address, enabled: true }),
    ).toEqual({
      programAddress: REGISTRY_PROGRAM,
      accounts: [
        { address: record.address, isSigner: false, isWritable: true },
        { address: owner, isSigner: true, isWritable: false },
      ],
      data: Uint8Array.of(4, 1),
    });
  });

  it("places each native signature in its reserved account-key slot", async () => {
    const first = createTestNativeSigner(bytes32(14));
    const second = createTestNativeSigner(bytes32(15));
    const unsigned: Transaction = {
      messageBytes: Uint8Array.of(
        2,
        0,
        0,
        2,
        ...decodeBase58(first.address),
        ...decodeBase58(second.address),
        ...new Uint8Array(32),
        0,
      ),
      signatures: [undefined, undefined],
    };
    const once = await first.signNativeTransaction(unsigned);
    expect(once.signatures[0]).toBeTypeOf("string");
    expect(once.signatures[1]).toBeUndefined();
    const twice = await second.signNativeTransaction(once);
    expect(twice.signatures[0]).toBe(once.signatures[0]);
    expect(twice.signatures[1]).toBeTypeOf("string");
  });

  it("signs, sends, and confirms opt-in once, then no-ops when enabled", async () => {
    const signer = createTestNativeSigner(bytes32(8));
    const record = userRecordAddress(signer.address);
    const rpc = new TestRpc();
    rpc.nextSignature = SIGNATURE;
    rpc.setConfirmation(SIGNATURE, true);
    rpc.setAccount(record.address, {
      owner: REGISTRY_PROGRAM,
      data: recordData(signer.address, record.bump, false),
      lamports: 1n,
    });

    await expect(enableMerging({ rpc, owner: signer.address, signer })).resolves.toEqual({
      changed: true,
      signature: SIGNATURE,
      userRecord: record.address,
    });
    expect(rpc.sent).toHaveLength(1);
    expect(rpc.sent[0]?.signatures[0]).toBeDefined();

    rpc.setAccount(record.address, {
      owner: REGISTRY_PROGRAM,
      data: recordData(signer.address, record.bump, true),
      lamports: 1n,
    });
    await expect(enableMerging({ rpc, owner: signer.address, signer })).resolves.toEqual({
      changed: false,
      userRecord: record.address,
    });
    expect(rpc.sent).toHaveLength(1);
  });

  it("rejects unauthorized signers and preserves typed context failures", async () => {
    const owner = createTestNativeSigner(bytes32(9));
    const stranger = createTestNativeSigner(bytes32(10));
    const record = userRecordAddress(owner.address);
    const rpc = new TestRpc();
    rpc.setAccount(record.address, {
      owner: REGISTRY_PROGRAM,
      data: recordData(owner.address, record.bump, false),
      lamports: 1n,
    });

    await expect(
      enableMerging({ rpc, owner: owner.address, signer: stranger }),
    ).rejects.toMatchObject({
      code: "TEST_KIT_INVALID_CONFIG",
      details: { field: "signer", reason: "ownerMismatch" },
    });
    const controller = new AbortController();
    controller.abort();
    await expect(
      enableMerging({ rpc, owner: owner.address, signer: owner }, { signal: controller.signal }),
    ).rejects.toMatchObject({ code: "TEST_KIT_ABORTED" });
    await expect(
      enableMerging({ rpc, owner: owner.address, signer: owner }, { timeoutMs: 0 }),
    ).rejects.toMatchObject({ code: "TEST_KIT_TIMEOUT" });
    expect(rpc.sent).toHaveLength(0);
  });

  it("rejects invalid record accounts and wraps RPC failures", async () => {
    const signer = createTestNativeSigner(bytes32(12));
    const record = userRecordAddress(signer.address);
    const rpc = new TestRpc();
    rpc.setAccount(record.address, {
      owner: signer.address,
      data: recordData(signer.address, record.bump, false),
      lamports: 1n,
    });
    await expect(enableMerging({ rpc, owner: signer.address, signer })).rejects.toMatchObject({
      code: "TEST_KIT_INVALID_CONFIG",
      details: { field: "userRecord", reason: "programOwner" },
    });
    await expect(
      enableMerging({ rpc: new FailingRpc(), owner: signer.address, signer }),
    ).rejects.toMatchObject({ code: "TEST_KIT_RPC" });
  });

  it("submits registration before opt-in and reports confirmation failures", async () => {
    const signer = createTestNativeSigner(bytes32(11));
    const record = userRecordAddress(signer.address);
    const rpc = new RegisteringRpc(record.address, recordData(signer.address, record.bump, false));
    rpc.nextSignature = SIGNATURE;
    rpc.setConfirmation(SIGNATURE, true);
    const registration: Transaction = {
      messageBytes: oneSignerMessage(signer.address),
      signatures: [SIGNATURE],
    };

    await expect(
      enableMerging({ rpc, owner: signer.address, signer, registration }),
    ).resolves.toMatchObject({ changed: true, signature: SIGNATURE });
    expect(rpc.sent).toHaveLength(2);

    const rejecting = new TestRpc();
    rejecting.setAccount(record.address, {
      owner: REGISTRY_PROGRAM,
      data: recordData(signer.address, record.bump, false),
      lamports: 1n,
    });
    await expect(
      enableMerging({ rpc: rejecting, owner: signer.address, signer }, { timeoutMs: 1 }),
    ).rejects.toMatchObject({
      code: "TEST_KIT_TIMEOUT",
      details: { stage: "confirmMerging", timeoutMs: 1 },
    });
  });

  it("submits a registration update without repeating an existing opt-in", async () => {
    const signer = createTestNativeSigner(bytes32(13));
    const record = userRecordAddress(signer.address);
    const rpc = new TestRpc();
    rpc.nextSignature = SIGNATURE;
    rpc.setConfirmation(SIGNATURE, true);
    rpc.setAccount(record.address, {
      owner: REGISTRY_PROGRAM,
      data: recordData(signer.address, record.bump, true),
      lamports: 1n,
    });
    const registration: Transaction = {
      messageBytes: oneSignerMessage(signer.address),
      signatures: [SIGNATURE],
    };

    await expect(
      enableMerging({ rpc, owner: signer.address, signer, registration }),
    ).resolves.toEqual({
      changed: false,
      userRecord: record.address,
    });
    expect(rpc.sent).toHaveLength(1);
  });
});

class RegisteringRpc extends TestRpc {
  readonly #record: Address;
  readonly #data: Uint8Array;

  constructor(record: Address, data: Uint8Array) {
    super();
    this.#record = record;
    this.#data = data;
  }

  override confirmTransaction(signature: Signature): Promise<boolean> {
    if (this.sent.length === 1) {
      this.setAccount(this.#record, {
        owner: REGISTRY_PROGRAM,
        data: this.#data,
        lamports: 1n,
      });
    }
    return super.confirmTransaction(signature);
  }
}

class FailingRpc extends TestRpc {
  override getAccount(): Promise<never> {
    return Promise.reject(new Error("RPC unavailable"));
  }
}

function decodeBase58(value: string): Uint8Array {
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let decoded = 0n;
  for (const character of value) {
    decoded = decoded * 58n + BigInt(alphabet.indexOf(character));
  }
  const bytes: number[] = [];
  while (decoded > 0n) {
    bytes.push(Number(decoded & 255n));
    decoded >>= 8n;
  }
  const zeros = value.match(/^1*/u)?.[0].length ?? 0;
  return Uint8Array.from([...new Array<number>(zeros).fill(0), ...bytes.reverse()]);
}
