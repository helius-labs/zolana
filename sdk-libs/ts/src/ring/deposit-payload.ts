import { decryptRingDepositUtxo as decryptRawDeposit } from "../transaction/serialization/ring-deposit.js";
import { readRingDepositCapsule } from "./deposit-capsule.js";

export function customRingDepositPayload(bytes: Uint8Array): Uint8Array {
  return readRingDepositCapsule(bytes)?.recipientCiphertext ?? bytes;
}

export function decryptRingDepositUtxo(
  ...[output, key, owner]: Parameters<typeof decryptRawDeposit>
): ReturnType<typeof decryptRawDeposit> {
  return decryptRawDeposit(
    {
      ...output,
      encrypted: {
        ...output.encrypted,
        ciphertext: customRingDepositPayload(output.encrypted.ciphertext),
      },
    },
    key,
    owner,
  );
}
