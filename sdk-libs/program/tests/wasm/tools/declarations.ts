import {
  Schema, ProvingSession, beginKeyTranscode, proveStreaming,
  proofInputContext, proofInputUtxo, proofToSnarkjs, verifyingKeyToSnarkjs,
  escrowTransaction, checkProvingKey,
  type Bytes, type ProofInputs, type ProverOptions, type SnarkjsProof,
  type WalletUtxo,
} from "../web/pkg/wasm_test_program";
import type { WorkerPool } from "../web/pkg/xark/pool";

declare const schema: Schema;
declare const session: ProvingSession;
declare const bytes: Uint8Array;
declare const pool: WorkerPool;
declare const wallet: WalletUtxo;

const encoded: Record<string, string> = schema.encodeInputs("{}");
const nested: ProofInputs = { private: { amount: 1n, flags: [true, false] } };
const options: ProverOptions = { pool, r1cs: bytes, residentKey: true, sources: "{}", msmChunk: 4096 };
session.prove(encoded);
session.prove(nested);
session.prove(nested, { pool });
proveStreaming(bytes, bytes, encoded, options);
beginKeyTranscode({ pool });
checkProvingKey(bytes, bytes);
proofInputContext({ blindingSeed: bytes, outputTreeId: null });
proofInputUtxo(wallet);
proofInputUtxo();
escrowTransaction({}, { inputs: [wallet], addresses: [[1, 2]], mints: [] }, bytes, "payer");
const proof: SnarkjsProof = proofToSnarkjs(bytes);
const coordinate: string = proof.pi_b[0][0];
const count: number = verifyingKeyToSnarkjs(bytes).nPublic;
const payload: Bytes = bytes.buffer as ArrayBuffer;
void [coordinate, count, payload];

// @ts-expect-error Schema encoding produces decimal strings, not numbers.
const numericInputs: Record<string, number> = schema.encodeInputs("{}");
// @ts-expect-error Prover options have numeric chunk sizes.
proveStreaming(bytes, bytes, encoded, { msmChunk: "large" });
// @ts-expect-error Proof input scalars cannot be undefined.
session.prove({ amount: undefined });
// @ts-expect-error Session options require a worker pool, not a thread count.
session.prove(nested, { pool: 2 });
// @ts-expect-error Native transaction records require wallet arrays.
escrowTransaction({}, { inputs: "wallet", addresses: [] }, bytes, "payer");
// @ts-expect-error Snarkjs point coordinates are decimal strings.
const numericCoordinate: number = proofToSnarkjs(bytes).pi_a[0];
// @ts-expect-error Proving key pins must be byte arrays.
checkProvingKey(bytes, "sha256");
void [numericInputs, numericCoordinate];
