import {
  Schema, ProvingSession, beginKeyTranscode, proveStreaming,
  proofInputContext, proofInputUtxo, proofToSnarkjs, verifyingKeyToSnarkjs,
  escrowTransaction, checkProvingKey,
  type Bytes, type SnarkjsProof,
  type WalletUtxo,
} from "../web/pkg/wasm_test_program";
import type { WorkerPool } from "../web/pkg/xark/pool";

declare const schema: Schema;
declare const session: ProvingSession;
declare const bytes: Uint8Array;
declare const pool: WorkerPool;
declare const wallet: WalletUtxo;

// Xark 0.3.0's runtime takes proof inputs and prover options untyped, so these
// only check that the module exports it.
const encoded = schema.encodeInputs("{}");
session.prove(encoded, { pool });
proveStreaming(bytes, bytes, encoded, { pool, r1cs: bytes, msmChunk: 4096 });
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

// @ts-expect-error Native transaction records require wallet arrays.
escrowTransaction({}, { inputs: "wallet", addresses: [] }, bytes, "payer");
// @ts-expect-error Snarkjs point coordinates are decimal strings.
const numericCoordinate: number = proofToSnarkjs(bytes).pi_a[0];
// @ts-expect-error Proving key pins must be byte arrays.
checkProvingKey(bytes, "sha256");
void [numericCoordinate];
