import { address } from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import { bytes32, ShieldedKeypair } from "../src/keypair/index.js";
import {
  AssetRegistry,
  Mint,
  SOL_MINT,
  createProofOutput,
  decodeOutputData,
  encryptConfidentialTransfer,
} from "../src/transaction/index.js";
import { decryptConfidentialAsSender } from "../src/transaction/serialization/codecs.js";

const TOKEN = address("So11111111111111111111111111111111111111112");

describe("retained mint metadata", () => {
  it("only constructs known address/id pairs and keeps them immutable", () => {
    const assets = new AssetRegistry([[7n, TOKEN]]);
    const mint = Mint.fromRegistry(assets, TOKEN);
    expect({
      asset: mint.asset,
      assetId: mint.assetId,
      mutated: Reflect.set(mint, "assetId", 8n),
      retainedId: mint.assetId,
    }).toEqual({ asset: TOKEN, assetId: 7n, mutated: false, retainedId: 7n });
    expect(() => Mint.fromRegistry(new AssetRegistry(), TOKEN)).toThrow(
      expect.objectContaining({ code: "TRANSACTION_UNKNOWN_MINT" }),
    );
    expect(() => Reflect.construct(Mint, [TOKEN, 7n])).toThrow(
      expect.objectContaining({ code: "TRANSACTION_DESERIALIZE" }),
    );
  });

  it("preserves an SPL asset id through output builders and encryption without a registry", () => {
    const assets = new AssetRegistry([[7n, TOKEN]]);
    const sender = ShieldedKeypair.generate();
    const tx = sender.transactionViewingKey(bytes32(new Uint8Array(32).fill(1)));
    try {
      const mint = Mint.fromRegistry(assets, TOKEN);
      const output = createProofOutput({
        ownerAddress: sender.shieldedAddress(),
        asset: TOKEN,
        mint,
        amount: 5n,
      }).withMemo(Uint8Array.of(9));
      const encrypted = encryptConfidentialTransfer(tx, { outputs: [output] });
      const slot = encrypted.payload[0];
      if (slot === undefined) throw new Error("a real output has a ciphertext");
      const frame = decodeOutputData(slot.data);
      if (frame.encoding !== "encrypted") throw new Error("expected encrypted output");
      const plaintext = decryptConfidentialAsSender(tx, frame.body, encrypted.salt, 0);
      expect({
        mint: output.mint,
        assetId: plaintext.assetId,
        amount: plaintext.amount,
        memo: plaintext.data.memo(),
      }).toEqual({ mint, assetId: 7n, amount: 5n, memo: Uint8Array.of(9) });
    } finally {
      tx.destroy();
      sender.destroy();
    }
  });

  it("rejects conflicting metadata before encrypting and requires metadata or a registry", () => {
    const assets = new AssetRegistry([[7n, TOKEN]]);
    const mint = Mint.fromRegistry(assets, TOKEN);
    const sender = ShieldedKeypair.generate();
    const tx = sender.transactionViewingKey(bytes32(new Uint8Array(32).fill(1)));
    const encrypt = vi.spyOn(tx, "encryptSlot");
    try {
      expect(() => createProofOutput({ asset: SOL_MINT, mint, amount: 1n })).toThrow(
        expect.objectContaining({ code: "TRANSACTION_MINT_MISMATCH" }),
      );
      const output = createProofOutput({
        ownerAddress: sender.shieldedAddress(),
        asset: TOKEN,
        mint,
        amount: 1n,
      });
      expect(() =>
        encryptConfidentialTransfer(tx, {
          outputs: [output],
          assets: new AssetRegistry([[8n, TOKEN]]),
        }),
      ).toThrow(expect.objectContaining({ code: "TRANSACTION_MINT_MISMATCH" }));
      const unbound = createProofOutput({
        ownerAddress: sender.shieldedAddress(),
        asset: TOKEN,
        amount: 1n,
      });
      expect(() => encryptConfidentialTransfer(tx, { outputs: [unbound] })).toThrow(
        expect.objectContaining({ code: "TRANSACTION_UNKNOWN_MINT" }),
      );
      expect(encrypt).not.toHaveBeenCalled();
    } finally {
      encrypt.mockRestore();
      tx.destroy();
      sender.destroy();
    }
  });
});
