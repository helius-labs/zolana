import {
  compileTransaction,
  createTransactionMessage,
  pipe,
  setTransactionMessageFeePayer,
  setTransactionMessageLifetimeUsingBlockhash,
  type Address,
  type Blockhash,
  type Transaction,
} from "@solana/kit";

const BLOCKHASH = "11111111111111111111111111111111" as Blockhash;

export function emptyTransaction(feePayer: Address): Transaction {
  return compileTransaction(
    pipe(
      createTransactionMessage({ version: 0 }),
      (message) => setTransactionMessageFeePayer(feePayer, message),
      (message) =>
        setTransactionMessageLifetimeUsingBlockhash(
          { blockhash: BLOCKHASH, lastValidBlockHeight: 1n },
          message,
        ),
    ),
  );
}
