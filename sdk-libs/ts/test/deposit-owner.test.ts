import { AccountRole, getAddressDecoder } from "@solana/kit";
import { describe, expect, it } from "vitest";

import vector from "../../../test-vectors/deposit_owner_authorization.json" with { type: "json" };
import { encodeDepositInstructionData } from "../src/interface/codecs/index.js";
import { depositInstruction } from "../src/interface/instructions/index.js";
import type { AssetDeposit, Bytes32 } from "../src/interface/types.js";

function filled(byte: number): Bytes32 {
  const bytes = new Uint8Array(32).fill(byte);
  if (bytes.length !== 32) throw new Error("expected 32 bytes");
  return bytes as Bytes32;
}

const tree = getAddressDecoder().decode(filled(1));
const depositor = getAddressDecoder().decode(filled(2));
const signingPk = getAddressDecoder().decode(filled(11));
const entry: AssetDeposit = {
  asset: { kind: "sol" },
  viewTag: filled(7),
  recipientOwnerHash: filled(8),
  amount: 8n,
  utxoData: {
    dataHash: filled(10),
    signingPk,
    nullifierPk: filled(12),
    data: Uint8Array.of(7, 8),
  },
  memo: Uint8Array.of(9, 10),
};

describe("deposit owner authorization", () => {
  it("matches the Rust wire vector including the owner hash preimage", () => {
    const bytes = encodeDepositInstructionData({
      assets: [{ kind: "sol" }],
      deposits: [{ ...entry, assetIndex: 0 }],
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

  it("requires no owner signer for absent or zero data hashes", async () => {
    const { utxoData, ...plain } = entry;
    expect(utxoData).toBeDefined();
    const zero = {
      ...entry,
      utxoData: { dataHash: filled(0), signingPk, nullifierPk: filled(12), data: new Uint8Array() },
    };
    const ix = await depositInstruction({ tree, depositor, deposits: [plain, zero] });
    expect(ix.accounts).toHaveLength(5);
    expect(ix.accounts?.filter((account) => account.role === AccountRole.READONLY_SIGNER)).toEqual(
      [],
    );
  });
});
