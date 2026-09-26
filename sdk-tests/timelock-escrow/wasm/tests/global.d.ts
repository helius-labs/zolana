type PlainProof = {
  proof: { a: number[]; b: number[]; c: number[] };
  compressedProof: { a: number[]; b: number[]; c: number[] };
  publicHash: number[];
};

type PlainTransaction = {
  finalizedTx: Record<string, unknown>;
  proofInputs: number[];
  publicHash: number[];
};

type Attempt<T> = { value: T } | { error: { name: string; message: string } };

interface EscrowHarness {
  moduleLoadMs: number;
  workerInfo(): Promise<{ crossOriginIsolated: boolean; threads: number }>;
  transaction(
    program: string,
    inputs: unknown,
    sender: number[],
    payer: string,
  ): Promise<{
    transaction: PlainTransaction;
    proofInputsSha256: string;
    amountType: string;
    proofInputsType: string;
  }>;
  prove(program: string, format: string, url: string, proofInputs: number[]): Promise<PlainProof>;
  proveInWorker(
    program: string,
    format: string,
    url: string,
    proofInputs: number[],
  ): Promise<PlainProof>;
  verify(source: string | number[], proof: PlainProof): Promise<boolean>;
  dummyWalletUtxo(treeId: number): Record<string, unknown>;
  attempt<T>(method: string, ...args: unknown[]): Promise<Attempt<T>>;
  timeKeyLoad(program: string, format: string, url: string): Promise<number>;
  timeProof(program: string, format: string, url: string, proofInputs: number[]): Promise<number>;
  timeTransaction(program: string, inputs: unknown, sender: number[], payer: string): number;
  timeSnarkjs(
    zkeyUrl: string,
    proofInputs: number[],
    runs: number,
  ): Promise<{ proofMs: number[]; publicSignal: string }>;
}

interface Window {
  escrow: EscrowHarness;
}
