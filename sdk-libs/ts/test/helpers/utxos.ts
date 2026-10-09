import { ShieldedKeypair, randomBlinding } from "../../src/keypair/index.js";
import { ProofInputUtxo, SOL_MINT, Utxo } from "../../src/transaction/index.js";

export function solInput(keypair: ShieldedKeypair, amount: bigint): ProofInputUtxo {
  return ProofInputUtxo.fromKeypair(
    new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount,
      blinding: randomBlinding(),
    }),
    keypair,
  );
}
