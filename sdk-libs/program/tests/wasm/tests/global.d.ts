type PlainProof = { proof: Uint8Array; publicInputs: Uint8Array; numPublicInputs: number };
type PlainTransaction = { finalizedTx: Record<string, any>; proofInputs: Record<string, string>; publicHash: number[] };
type Attempt<T> = { value?: T; error?: { name: string; message: string } };
interface ProgramHarness {
  moduleLoadMs: number;
  workerInfo(): Promise<{ crossOriginIsolated: boolean; threads: number; stats?: { fftCalls: number; msmCalls: number } }>;
  transaction(program: string, inputs: unknown, sender: number[], payer: string): Promise<{ transaction: PlainTransaction }>;
  prove(program: string, format: string, url: string, inputs: Record<string, string>): Promise<PlainProof>;
  proveWithClient(program: string, inputs: Record<string, unknown>): Promise<boolean>;
  verify(program: string, proof: PlainProof): Promise<boolean>;
  verifyIndependent(program: string, proof: PlainProof, publicHash: number[]): Promise<boolean>;
  attempt<T>(method: string, ...args: unknown[]): Promise<Attempt<T>>;
  timeKeyLoad(program: string, format: string, url: string): Promise<number>;
  timeProof(program: string, format: string, url: string, inputs: Record<string, string>): Promise<number>;
  timeTransaction(program: string, inputs: unknown, sender: number[], payer: string): number;
}
interface Window { zkProgram: ProgramHarness; }
