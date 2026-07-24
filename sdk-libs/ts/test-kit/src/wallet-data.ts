import type { Bytes31, Bytes32, DepositInstructionData } from "@zolana/interface";
import type { ShieldedAddress } from "@zolana/keypair";
import { deriveBlinding } from "@zolana/transaction";

export function depositData(
  input: Readonly<{
    amount: bigint;
    owner: Bytes32;
    blinding: Bytes31;
    viewTag?: Bytes32;
    memo?: Uint8Array;
  }>,
): DepositInstructionData {
  return Object.freeze({
    viewTag: new Uint8Array(input.viewTag ?? new Uint8Array(32)) as Bytes32,
    owner: new Uint8Array(input.owner) as Bytes32,
    blinding: new Uint8Array(input.blinding) as Bytes31,
    amount: input.amount,
    ...(input.memo === undefined ? {} : { memo: new Uint8Array(input.memo) }),
  });
}

export function walletDepositData(
  input: Readonly<{
    amount: bigint;
    recipient: ShieldedAddress;
    blindingSeed: Bytes31;
    position: number;
    memo?: Uint8Array;
  }>,
): DepositInstructionData {
  return depositData({
    amount: input.amount,
    owner: input.recipient.ownerHash(),
    blinding: deriveBlinding(input.blindingSeed, input.position),
    viewTag: input.recipient.viewingPublicKey.x(),
    ...(input.memo === undefined ? {} : { memo: input.memo }),
  });
}
