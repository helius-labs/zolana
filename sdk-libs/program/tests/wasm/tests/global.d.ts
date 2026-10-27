type PlainProof = { proof: Uint8Array; publicInputs: Uint8Array; numPublicInputs: number };
type PlainTransaction = { finalizedTx: Record<string, any>; proofInputs: Record<string, any>; publicHash: number[] };
type Attempt<T> = { value?: T; error?: { name: string; message: string } };
interface ProgramHarness {
  moduleLoadMs: number;
  workerInfo(): Promise<{ crossOriginIsolated: boolean; threads: number }>;
  transaction(program: string, inputs: unknown, sender: number[], payer: string): Promise<{ transaction: PlainTransaction }>;
  prove(program: string, format: string, url: string, inputs: Record<string, any>): Promise<PlainProof>;
  verify(program: string, proof: PlainProof): Promise<boolean>;
  verifyIndependent(program: string, proof: PlainProof, publicHash: number[]): Promise<boolean>;
  attempt<T>(method: string, ...args: unknown[]): Promise<Attempt<T>>;
  timeKeyLoad(program: string, format: string, url: string): Promise<number>;
  timeProof(program: string, format: string, url: string, inputs: Record<string, any>): Promise<number>;
  timeTransaction(program: string, inputs: unknown, sender: number[], payer: string): number;
}
interface Window { zkProgram: ProgramHarness; }
