import { AccountRole, getAddressDecoder } from "@solana/kit";
import { describe, expect, it } from "vitest";

import vector from "../../../test-vectors/deposit_owner_authorization.json" with { type: "json" };
import { encodeDepositInstructionData } from "../src/interface/codecs/index.js";
import { depositInstruction } from "../src/interface/instructions/index.js";
import type { AssetDeposit, Bytes32, UtxoData } from "../src/interface/types.js";

function filled(byte: number): Bytes32 {
  const bytes = new Uint8Array(32).fill(byte);
  if (bytes.length !== 32) throw new Error("expected 32 bytes");
  return bytes as Bytes32;
}

const tree = getAddressDecoder().decode(filled(1));
const depositor = getAddressDecoder().decode(filled(2));
const signingPk = getAddressDecoder().decode(filled(11));
const utxoData: UtxoData = {
  dataHash: filled(10),
  nullifierPk: filled(12),
  data: Uint8Array.of(7, 8),
};
const entry: AssetDeposit = {
  asset: { kind: "sol" },
  viewTag: filled(7),
  recipientOwnerHash: filled(8),
  amount: 8n,
  utxoData: { signingPk, data: utxoData },
  memo: Uint8Array.of(9, 10),
};

describe("deposit owner authorization", () => {
  it("matches the Rust wire vector including the owner hash preimage", () => {
    const bytes = encodeDepositInstructionData({
      assets: [{ kind: "sol" }],
      deposits: [{ ...entry, assetIndex: 0, utxoData }],
    });
    expect(Buffer.from(bytes).toString("hex")).toBe(vector.wireHex);
  });

  it("requires a signer slot for each nonzero data hash, including repeated owners", async () => {
    const ix = await depositInstruction({ tree, depositor, deposits: [entry, entry] });
    expect(ix.accounts?.slice(5)).toEqual([
      { address: signingPk, role: AccountRole.READONLY_SIGNER },
      { address: signingPk, role: AccountRole.READONLY_SIGNER },
    ]);
  });

  it("requires no owner signer for absent application data", async () => {
    const { utxoData: authorization, ...plain } = entry;
    expect(authorization).toBeDefined();
    const ix = await depositInstruction({ tree, depositor, deposits: [plain] });
    expect(ix.accounts).toHaveLength(5);
  });

  it("rejects zero data hashes with empty or nonempty payloads", async () => {
    for (const data of [new Uint8Array(), Uint8Array.of(1, 2, 3)]) {
      const zero = {
        ...entry,
        utxoData: { signingPk, data: { dataHash: filled(0), nullifierPk: filled(12), data } },
      };
      expect(() =>
        encodeDepositInstructionData({
          assets: [{ kind: "sol" }],
          deposits: [{ ...zero, assetIndex: 0, utxoData: zero.utxoData.data }],
        }),
      ).toThrow(expect.objectContaining({ code: "INTERFACE_CODEC" }));
      await expect(depositInstruction({ tree, depositor, deposits: [zero] })).rejects.toMatchObject(
        {
          code: "INTERFACE_CODEC",
        },
      );
    }
  });

  it("rejects application data without a builder owner signer", async () => {
    const unsigned = { ...entry, utxoData: { data: utxoData } };
    await expect(
      // @ts-expect-error JavaScript callers can omit the required nested signer.
      depositInstruction({ tree, depositor, deposits: [unsigned] }),
    ).rejects.toMatchObject({
      code: "INTERFACE_CODEC",
    });
  });

  it("rejects a signer wrapper without application data", async () => {
    const missingData = { ...entry, utxoData: { signingPk } };
    await expect(
      // @ts-expect-error JavaScript callers can omit the required nested data.
      depositInstruction({ tree, depositor, deposits: [missingData] }),
    ).rejects.toMatchObject({
      code: "INTERFACE_CODEC",
    });
  });
});
