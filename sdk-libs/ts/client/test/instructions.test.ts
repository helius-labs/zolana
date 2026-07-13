import { Keypair, PublicKey } from "@solana/web3.js";
import { describe, expect, it } from "vitest";
import {
  ASSOCIATED_TOKEN_PROGRAM_ID,
  Deposit,
  InstructionTag,
  SHIELDED_POOL_PROGRAM_ID,
  SOL_INTERFACE,
  SOL_MINT,
  SPL_TOKEN_PROGRAM_ID,
  ShieldedKeypair,
  associatedTokenAddress,
  depositInstruction,
  serializeDepositIxData,
  shieldedPoolCpiAuthority,
  solInterface,
  splAccounts,
  splAssetRegistry,
  splAssetVault,
} from "../src/index.js";

describe("instructions and PDAs", () => {
  it("pins canonical PDA constants and derivations", () => {
    expect(solInterface().toBase58()).toBe(SOL_INTERFACE.toBase58());
    expect(shieldedPoolCpiAuthority().toBase58()).toBe("6zQNhLqFHhWaP8JNYeHzQ9a1DfBH627gzibFv1ZaaM8E");

    const owner = Keypair.generate().publicKey;
    const mint = Keypair.generate().publicKey;
    const expectedAta = PublicKey.findProgramAddressSync(
      [owner.toBytes(), SPL_TOKEN_PROGRAM_ID.toBytes(), mint.toBytes()],
      ASSOCIATED_TOKEN_PROGRAM_ID,
    )[0];
    expect(associatedTokenAddress(owner, mint).toBase58()).toBe(expectedAta.toBase58());
  });

  it("serializes deposit data with the same field order as Rust", () => {
    const data = serializeDepositIxData({
      viewTag: new Uint8Array(32).fill(1),
      owner: new Uint8Array(32).fill(2),
      blinding: new Uint8Array(31).fill(3),
      publicAmount: 0x0102n,
      utxoData: { dataHash: new Uint8Array(32).fill(4), data: new Uint8Array([5, 6]) },
      memo: new Uint8Array([7]),
    });

    expect(data[0]).toBe(1);
    expect(data[32]).toBe(2);
    expect(data[64]).toBe(3);
    expect([...data.slice(95, 104)]).toEqual([1, 0x02, 0x01, 0, 0, 0, 0, 0, 0]);
    expect(data[104]).toBe(1);
    expect(data[137]).toBe(2);
    expect(data[138]).toBe(0);
    expect([...data.slice(139, 141)]).toEqual([5, 6]);
    expect([...data.slice(141)]).toEqual([1, 1, 0, 7]);
  });

  it("builds SOL deposit instructions with Rust account order", () => {
    const tree = Keypair.generate().publicKey;
    const depositor = Keypair.generate().publicKey;
    const ix = depositInstruction({
      tree,
      depositor,
      viewTag: new Uint8Array(32).fill(1),
      owner: new Uint8Array(32).fill(2),
      blinding: new Uint8Array(31).fill(3),
      publicAmount: 9n,
    });

    expect(ix.programId.toBase58()).toBe(SHIELDED_POOL_PROGRAM_ID.toBase58());
    expect(ix.data[0]).toBe(InstructionTag.Deposit);
    expect(ix.keys.map((key) => key.pubkey.toBase58())).toEqual([
      tree.toBase58(),
      depositor.toBase58(),
      PublicKey.default.toBase58(),
      SOL_INTERFACE.toBase58(),
      depositor.toBase58(),
      SHIELDED_POOL_PROGRAM_ID.toBase58(),
    ]);
    expect(ix.keys.map((key) => key.isWritable)).toEqual([true, true, false, true, true, false]);
  });

  it("builds SPL deposit settlement accounts", () => {
    const mint = Keypair.generate().publicKey;
    const userToken = Keypair.generate().publicKey;
    expect(splAccounts(SOL_MINT, null)).toBeUndefined();
    expect(() => splAccounts(mint, null)).toThrow(/SPL token account/);
    expect(splAccounts(mint, userToken)).toEqual({
      userToken,
      splTokenInterface: splAssetVault(mint),
      registry: splAssetRegistry(mint),
      tokenProgram: SPL_TOKEN_PROGRAM_ID,
    });
  });

  it("prepares deposits from shielded addresses", () => {
    const recipient = ShieldedKeypair.fromKeys(
      // Keep the fixture deterministic without asserting random blinding bytes.
      // The action only needs public address material plus fresh blinding.
      (ShieldedKeypair.new()).signingKey,
      (ShieldedKeypair.new()).viewingKey,
    ).shieldedAddress();
    const deposit = Deposit.new({ recipient, asset: SOL_MINT, amount: 123n });

    expect(deposit.data.viewTag).toEqual(recipient.viewingPubkey.x());
    expect(deposit.data.owner).toEqual(recipient.ownerHash());
    expect(deposit.data.blinding).toHaveLength(31);
    expect(deposit.utxoHash).toHaveLength(32);
  });
});
