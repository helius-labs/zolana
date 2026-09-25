import { compressProof, parseProof } from "../src/client/prover/proof.js";
import { wireDecoder } from "../src/interface/decode.js";
import { resolvedTrees } from "../src/client/prover/indexed.js";
import { NO_UTXO_ROOT } from "../src/interface/tree-slot.js";
import { prepareTransfer } from "../src/client/prover/assembly.js";
import {
  SOLANA_ERROR__JSON_RPC__METHOD_NOT_FOUND,
  SolanaError,
  address,
  getBase58Decoder,
  type Address,
  type Signature,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import {
  ClientError,
  LocalKeys,
  NullifierKeyProofAuthority,
  ZolanaClient,
  proverRequestBody,
  type GetMerkleProofsResponse,
  type GetNonInclusionProofsResponse,
  type SpendProof,
  type ZolanaClientConfig,
} from "../src/client/index.js";
import { defaultSolanaRpcSubscriptionsUrl, runKitRpc } from "../src/client/kit.js";
import { BN254_MODULUS, bigintToBytes, bytesField, checkedBytes } from "../src/client/internal.js";
import { asField, assemble } from "../src/client/prover/assembly.js";
import type { NonInclusionProof } from "../src/client/rpc.js";
import type { Bytes16, Bytes31, Bytes32 } from "../src/interface/index.js";
import { treeAddress } from "../src/interface/pda/index.js";
import { NullifierKey, ShieldedKeypair, ShieldedPublicKey } from "../src/keypair/index.js";
import { withRecordSlotSecret } from "../src/ring/velocity.js";
import { proofFor } from "./helpers/proofs.js";
import {
  ProofInputUtxo,
  SOL_MINT,
  SppProofInputs,
  Utxo,
  createExternalData,
  createProofOutput,
  outputBlindingSeed,
  transactOutputBlinding,
} from "../src/transaction/index.js";

/** The client defaults to tree id 0; its address must be the PDA of that id. */
const TREE_ID = 0;
const TREE = treeAddress(TREE_ID);
/** A PDA of no tree id the tests use, to check the id/address consistency gate. */
const FOREIGN_TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const RPC_URL = "https://rpc.example.com/zolana";
const INDEXER_URL = "https://indexer.example.com/api";
const PROVER_URL = "https://prover.example.com/api";

function bytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

/** A root blinding seed is a field element, so its leading byte stays zero. */
function blindingSeed(value: number): Bytes32 {
  const seed = bytes(value);
  seed[0] = 0;
  return seed;
}

type ProofFixture = Readonly<{
  proofInputs: SppProofInputs;
  spendProof: SpendProof;
  /** One non-inclusion proof per padding input, at the spend proof's nullifier root. */
  dummyProofs: readonly NonInclusionProof[];
  keypair: ShieldedKeypair;
}>;

/**
 * One real spend of tree 0 plus `dummyInputs` padding slots, every output
 * blinding derived from the first nullifier and the root seed the way the
 * circuit checks it.
 */
function proofFixture(
  options: Readonly<{ dummyInputs?: number; outputTreeId?: number; ring?: Address }> = {},
): ProofFixture {
  const outputTreeId = options.outputTreeId ?? TREE_ID;
  const keypair = ShieldedKeypair.generate();
  const input = ProofInputUtxo.fromKeypair(
    new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 7n,
      blinding: bytes(1),
      ...(options.ring === undefined ? {} : { ringProgramId: options.ring }),
    }),
    keypair,
  );
  const dummyInputs = Array.from({ length: options.dummyInputs ?? 0 }, (_, index) =>
    ProofInputUtxo.dummy(bytes(10 + index)),
  );
  const seed = blindingSeed(9);
  const firstNullifier = input.nullifier();
  const outputSeed = outputBlindingSeed(firstNullifier, seed);
  const slotBlinding = (index: number): Bytes32 =>
    transactOutputBlinding(firstNullifier, outputSeed, index);
  const ownerTag = bytes(8);
  const output = createProofOutput({
    ownerAddress: keypair.shieldedAddress(),
    asset: SOL_MINT,
    amount: 7n,
    blinding: slotBlinding(0),
    ...(options.ring === undefined ? {} : { ringProgramId: options.ring }),
  });
  const outputs = [
    output,
    ...dummyInputs.map((_, index) =>
      createProofOutput({
        asset: SOL_MINT,
        amount: 0n,
        blinding: slotBlinding(index + 1),
        ownerTag,
      }),
    ),
  ];
  const proofInputs = new SppProofInputs({
    // The payer must own the input UTXOs. Only its own are provable.
    payer: keypair.shieldedAddress().solanaAddress(),
    inputUtxos: [input, ...dummyInputs],
    outputs,
    externalData: createExternalData({
      txViewingPublicKey: keypair.viewingPublicKey(),
      salt: new Uint8Array(16) as Bytes16,
      outputs: outputs.map((entry) => ({
        utxoHash: entry.hash(outputTreeId),
        ownerTag: { kind: "inline", value: ownerTag },
      })),
      resolvedOwnerTags: outputs.map(() => ownerTag),
      messages: [],
    }),
    blindingSeed: seed,
    outputTreeId,
  });
  const spendProof: SpendProof = {
    state: {
      leaf: input.hash(),
      merkleContext: { treeType: 0, tree: TREE },
      path: Array.from({ length: 32 }, () => bytes(0)),
      leafIndex: 0n,
      root: bytes(3),
      rootSeq: 1n,
      rootIndex: 4,
    },
    nullifier: {
      leaf: input.nullifier(),
      merkleContext: { treeType: 1, tree: TREE },
      path: Array.from({ length: 40 }, () => bytes(0)),
      lowElement: bytes(4),
      lowElementIndex: 0n,
      highElement: bytes(5),
      highElementIndex: 1n,
      root: bytes(6),
      rootSeq: 1n,
      rootIndex: 7,
    },
  };
  const dummyProofs = dummyInputs.map((dummy): NonInclusionProof => ({
    leaf: dummy.nullifier(),
    merkleContext: { treeType: 1, tree: TREE },
    path: Array.from({ length: 40 }, () => bytes(0)),
    lowElement: bytes(4),
    lowElementIndex: 0n,
    highElement: bytes(5),
    highElementIndex: 1n,
    root: bytes(6),
    rootSeq: 1n,
    rootIndex: 7,
  }));
  return { proofInputs, spendProof, dummyProofs, keypair };
}

type ServiceOverrides = Pick<ZolanaClientConfig, "indexerUrl" | "proverUrl">;

async function serviceRequestUrls(
  solanaRpcUrl: string | URL,
  overrides: ServiceOverrides = {},
): Promise<readonly string[]> {
  const urls: string[] = [];
  const fetch = vi.fn(async (input: URL | RequestInfo, init?: RequestInit): Promise<Response> => {
    const requestUrl = input instanceof Request ? input.url : String(input);
    urls.push(requestUrl);
    const path = new URL(requestUrl).pathname;
    if (path.endsWith("/getShieldedTransactionsByNullifiers")) {
      return new Response(
        JSON.stringify({
          id: "test-account",
          jsonrpc: "2.0",
          result: { context: { blockTime: 1, slot: 1 }, transactions: [] },
        }),
        { headers: { "content-type": "application/json" } },
      );
    }
    if (path.endsWith("/prove")) {
      return new Response(JSON.stringify(proofFor(String(init?.body))), {
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`unexpected request: ${requestUrl}`);
  }) as typeof globalThis.fetch;
  const instance = new ZolanaClient({
    solanaRpcUrl,
    proofDataSource: "client",
    ...overrides,
    tree: TREE,
    fetch,
    indexerConfig: {
      poll: { numRetries: 1, delayMs: 0n, maxDelayMs: 0n },
    },
  });

  await instance.getShieldedTransactionsByNullifiers({ nullifiers: [bytes(7)] });
  const fixture = proofFixture();
  // Proving reads the two proof endpoints directly, so those stay off the
  // wire here; only the prover request is under test.
  vi.spyOn(instance, "getMerkleProofs").mockResolvedValue({
    context: { blockTime: 1n, slot: 1n },
    proofs: [fixture.spendProof.state],
  });
  vi.spyOn(instance, "getNonInclusionProofs").mockResolvedValue({
    context: { blockTime: 1n, slot: 1n },
    proofs: [fixture.spendProof.nullifier, ...fixture.dummyProofs],
  });
  await instance.proveTransact(
    fixture.proofInputs,
    LocalKeys.fromKeypair(fixture.keypair, instance.proofService),
  );
  return urls;
}

function proverFetch(): ReturnType<typeof vi.fn<typeof globalThis.fetch>> {
  return vi.fn<typeof globalThis.fetch>((_url, init) =>
    Promise.resolve(
      new Response(JSON.stringify(proofFor(String(init?.body))), {
        headers: { "content-type": "application/json" },
      }),
    ),
  );
}

function client(fetch = vi.fn<typeof globalThis.fetch>()): ZolanaClient {
  return new ZolanaClient({
    solanaRpcUrl: "http://127.0.0.1:8899",
    proofDataSource: "client",
    indexerUrl: "http://127.0.0.1:8784",
    proverUrl: "http://127.0.0.1:3001",
    tree: TREE,
    fetch,
    indexerConfig: {
      poll: { numRetries: 1, delayMs: 0n, maxDelayMs: 0n },
    },
  });
}

describe("ZolanaClient", () => {
  it("uses Solana's adjacent WebSocket port for explicit local RPC ports", () => {
    expect(defaultSolanaRpcSubscriptionsUrl("http://127.0.0.1:8899/")).toBe("ws://127.0.0.1:8900/");
    expect(defaultSolanaRpcSubscriptionsUrl("https://api.devnet.solana.com/")).toBe(
      "wss://api.devnet.solana.com/",
    );
  });

  it("performs no eager network requests", () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    const instance = client(fetch);
    expect(instance.tree).toBe(TREE);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("builds against tree 0 by default and follows an explicit tree id", () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    const byDefault = new ZolanaClient({ solanaRpcUrl: RPC_URL, fetch });
    expect(byDefault.treeId).toBe(0);
    expect(byDefault.tree).toBe(treeAddress(0));

    const explicit = new ZolanaClient({ solanaRpcUrl: RPC_URL, treeId: 3, fetch });
    expect(explicit.treeId).toBe(3);
    expect(explicit.tree).toBe(treeAddress(3));
    expect(fetch).not.toHaveBeenCalled();
  });

  it("rejects a tree address that does not name the tree id", () => {
    // The id is what every commitment hashes under; an address of another tree
    // would prove against one tree and submit to another.
    for (const config of [
      { tree: FOREIGN_TREE },
      { treeId: 1, tree: treeAddress(0) },
    ] satisfies readonly Pick<ZolanaClientConfig, "tree" | "treeId">[]) {
      let error: unknown;
      try {
        new ZolanaClient({ solanaRpcUrl: RPC_URL, ...config });
      } catch (cause) {
        error = cause;
      }
      expect(error).toMatchObject({
        code: "CLIENT_INVALID_CONFIG",
        details: { field: "tree" },
      });
    }
  });

  it.each([
    {
      name: "uses the RPC endpoint for both omitted services",
      overrides: {},
      expected: [
        "https://rpc.example.com/zolana/getShieldedTransactionsByNullifiers",
        "https://rpc.example.com/zolana/prove",
      ],
    },
    {
      name: "keeps an explicit indexer and falls the prover back to RPC",
      overrides: { indexerUrl: INDEXER_URL },
      expected: [
        "https://indexer.example.com/api/getShieldedTransactionsByNullifiers",
        "https://rpc.example.com/zolana/prove",
      ],
    },
    {
      name: "falls the indexer back to RPC and keeps an explicit prover",
      overrides: { proverUrl: PROVER_URL },
      expected: [
        "https://rpc.example.com/zolana/getShieldedTransactionsByNullifiers",
        "https://prover.example.com/api/prove",
      ],
    },
    {
      name: "keeps both explicit service endpoints",
      overrides: { indexerUrl: INDEXER_URL, proverUrl: PROVER_URL },
      expected: [
        "https://indexer.example.com/api/getShieldedTransactionsByNullifiers",
        "https://prover.example.com/api/prove",
      ],
    },
  ] satisfies readonly Readonly<{
    name: string;
    overrides: ServiceOverrides;
    expected: readonly string[];
  }>[])("$name", async ({ overrides, expected }) => {
    await expect(serviceRequestUrls(RPC_URL, overrides)).resolves.toEqual(expected);
  });

  it("treats explicit undefined service URLs as omitted", async () => {
    await expect(
      serviceRequestUrls(RPC_URL, { indexerUrl: undefined, proverUrl: undefined }),
    ).resolves.toEqual([
      "https://rpc.example.com/zolana/getShieldedTransactionsByNullifiers",
      "https://rpc.example.com/zolana/prove",
    ]);
  });

  it("clones a URL object before deriving service request URLs", async () => {
    const rpcUrl = new URL("https://gateway.example.com/base?cluster=devnet");
    const original = rpcUrl.href;

    await expect(serviceRequestUrls(rpcUrl)).resolves.toEqual([
      "https://gateway.example.com/base/getShieldedTransactionsByNullifiers?cluster=devnet",
      "https://gateway.example.com/base/prove?cluster=devnet",
    ]);
    expect(rpcUrl.href).toBe(original);
  });

  it("does not own Solana signing, sending, or confirmation", () => {
    const instance = client();
    expect(instance).not.toHaveProperty("sendTransaction");
    expect(instance).not.toHaveProperty("signAndSendInstructions");
    expect(instance).not.toHaveProperty("submitPrivateTransaction");
  });

  it("resolves confirmTransaction to the slot the transaction landed in", async () => {
    const instance = client();
    const send = vi.fn(async () => ({
      value: [{ slot: 42n, err: null, confirmationStatus: "confirmed" }],
    }));
    Object.defineProperty(instance, "solanaRpc", {
      value: { getSignatureStatuses: () => ({ send }) },
    });

    await expect(instance.confirmTransaction("1".repeat(64) as Signature)).resolves.toBe(42n);
    expect(send).toHaveBeenCalledOnce();
  });

  it("rejects malformed service URLs before any request", () => {
    expect(
      () =>
        new ZolanaClient({
          solanaRpcUrl: "file:///tmp/rpc",
          indexerUrl: "http://127.0.0.1:8784",
          proverUrl: "http://127.0.0.1:3001",
        }),
    ).toThrow(ClientError);
  });

  it.each([
    "http://localhost:8784",
    "http://sdk.localhost:8784",
    "http://127.0.0.2:8784",
    "http://[::1]:8784",
    "https://service.example.com",
  ])("allows secure or loopback service URL %s", (serviceUrl) => {
    expect(
      () =>
        new ZolanaClient({
          solanaRpcUrl: "http://127.0.0.1:8899",
          proofDataSource: "client",
          indexerUrl: serviceUrl,
          proverUrl: serviceUrl,
        }),
    ).not.toThrow();
  });

  it("rejects plaintext non-loopback indexer and prover URLs", () => {
    for (const field of ["indexerUrl", "proverUrl"] as const) {
      let error: unknown;
      try {
        new ZolanaClient({
          solanaRpcUrl: RPC_URL,
          [field]: `http://${field}.example.com`,
        });
      } catch (cause) {
        error = cause;
      }
      expect(error).toMatchObject({
        code: "CLIENT_INVALID_CONFIG",
        details: { field },
      });
    }
  });

  it("allows plaintext non-loopback URLs only when asked explicitly", () => {
    // The escape hatch for a transport that is already private -- an indexer
    // inside a VPC, TLS terminated elsewhere. It has to be opt-in, so running a
    // shielded client over plaintext stays a visible decision.
    expect(
      () =>
        new ZolanaClient({
          solanaRpcUrl: RPC_URL,
          indexerUrl: "http://indexer.internal:8784",
          proverUrl: "http://prover.internal:3001",
          allowInsecureHttp: true,
        }),
    ).not.toThrow();
  });

  it("still rejects credentials and fragments when insecure http is allowed", () => {
    // The opt-in relaxes the scheme and nothing else: a service URL carrying
    // credentials or a fragment is malformed either way.
    for (const indexerUrl of [
      "http://user:pass@indexer.internal:8784",
      "http://indexer.internal:8784#fragment",
    ]) {
      expect(
        () =>
          new ZolanaClient({
            solanaRpcUrl: RPC_URL,
            indexerUrl,
            allowInsecureHttp: true,
          }),
      ).toThrow();
    }
  });

  it("validates an RPC fallback against each service's HTTPS requirement", () => {
    for (const { config, field } of [
      {
        config: { solanaRpcUrl: "http://rpc.example.com" },
        field: "solanaRpcUrl",
      },
      {
        config: {
          solanaRpcUrl: "http://rpc.example.com",
          indexerUrl: INDEXER_URL,
        },
        field: "solanaRpcUrl",
      },
    ] satisfies readonly Readonly<{
      config: ZolanaClientConfig;
      field: "solanaRpcUrl";
    }>[]) {
      let error: unknown;
      try {
        new ZolanaClient(config);
      } catch (cause) {
        error = cause;
      }
      expect(error).toMatchObject({
        code: "CLIENT_INVALID_CONFIG",
        details: { field },
      });
    }
  });

  it("preserves unsupported RPC methods for feature fallbacks", async () => {
    await expect(
      runKitRpc("getProgramAccounts", undefined, async () => {
        throw new SolanaError(SOLANA_ERROR__JSON_RPC__METHOD_NOT_FOUND, {
          __serverMessage: "method not found",
        });
      }),
    ).rejects.toMatchObject({
      code: "CLIENT_UNSUPPORTED_RPC_METHOD",
      details: { method: "getProgramAccounts" },
    });
  });

  it("accepts a nullifier response that reports how far the scan reached", async () => {
    // Strict decoding must still accept the indexer's explicit scan frontier.
    const fetch = vi.fn<typeof globalThis.fetch>(() =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            id: "test-account",
            jsonrpc: "2.0",
            result: {
              context: { blockTime: 1, slot: 1 },
              transactions: [],
              nextCursor: null,
              scannedThrough: "Aw==",
            },
          }),
          { headers: { "content-type": "application/json" } },
        ),
      ),
    );

    const response = await client(fetch).getShieldedTransactionsByNullifiers({
      nullifiers: [bytes(7)],
    });

    expect(response.nextCursor).toBeUndefined();
    expect(response.scannedThrough).toEqual(Uint8Array.of(3));
  });

  it("accepts tag responses that report how far the scan reached", async () => {
    const responseBody = (rows: "transactions" | "matches") =>
      JSON.stringify({
        id: "test-account",
        jsonrpc: "2.0",
        result: {
          context: { blockTime: 1, slot: 1 },
          [rows]: [],
          nextCursor: null,
          scannedThrough: "BA==",
        },
      });
    const transactionFetch = vi.fn<typeof globalThis.fetch>(() =>
      Promise.resolve(
        new Response(responseBody("transactions"), {
          headers: { "content-type": "application/json" },
        }),
      ),
    );
    const encryptedUtxoFetch = vi.fn<typeof globalThis.fetch>(() =>
      Promise.resolve(
        new Response(responseBody("matches"), {
          headers: { "content-type": "application/json" },
        }),
      ),
    );

    const transactions = await client(transactionFetch).getShieldedTransactionsByTags({
      tags: [bytes(7)],
    });
    const encryptedUtxos = await client(encryptedUtxoFetch).getEncryptedUtxosByTags({
      tags: [bytes(7)],
    });

    expect(transactions.scannedThrough).toEqual(Uint8Array.of(4));
    expect(encryptedUtxos.scannedThrough).toEqual(Uint8Array.of(4));
  });

  it("forwards paginated nullifier lookups through the client facade", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(() =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            id: "test-account",
            jsonrpc: "2.0",
            result: {
              context: { blockTime: 1, slot: 1 },
              transactions: [],
              nextCursor: "Ag==",
            },
          }),
          { headers: { "content-type": "application/json" } },
        ),
      ),
    );
    const instance = client(fetch);
    const nullifier = bytes(7);

    const response = await instance.getShieldedTransactionsByNullifiers({
      nullifiers: [nullifier],
      cursor: Uint8Array.of(1),
      limit: 1000,
    });

    expect(response.nextCursor).toEqual(Uint8Array.of(2));
    expect(String(fetch.mock.calls[0]?.[0])).toBe(
      "http://127.0.0.1:8784/getShieldedTransactionsByNullifiers",
    );
    expect(JSON.parse(String(fetch.mock.calls[0]?.[1]?.body))).toMatchObject({
      method: "getShieldedTransactionsByNullifiers",
      params: {
        nullifiers: [getBase58Decoder().decode(nullifier)],
        cursor: "AQ==",
        limit: 1000,
      },
    });
  });

  it("preserves a ring filter for empty-tag scans and refuses an unscoped scan", async () => {
    const requests: unknown[] = [];
    const fetch = vi.fn<typeof globalThis.fetch>(async (_url, init) => {
      requests.push(JSON.parse(String(init?.body)));
      return Response.json({
        id: "test-account",
        jsonrpc: "2.0",
        result: { context: { blockTime: 1, slot: 1 }, transactions: [], scannedThrough: "BA==" },
      });
    });
    const instance = client(fetch);
    await instance.getShieldedTransactionsByTags({
      tags: [],
      ringProgramId: TREE,
      limit: 3,
      cursor: Uint8Array.of(1),
    });
    expect(requests).toEqual([
      expect.objectContaining({
        params: { tags: [], ringProgramId: TREE, limit: 3, cursor: "AQ==" },
      }),
    ]);
    await expect(instance.getShieldedTransactionsByTags({ tags: [] })).rejects.toThrow();
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it("proves caller-assembled transfer inputs on the transfer circuit", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(
      async (_url, init) =>
        new Response(JSON.stringify(proofFor(String(init?.body))), {
          headers: { "content-type": "application/json" },
        }),
    );
    const instance = client(fetch);
    const fixture = proofFixture();
    const { proverInputs } = assemble(fixture.proofInputs, [fixture.spendProof]);

    const keys = LocalKeys.fromKeypair(fixture.keypair, instance.proofService);
    const proof = await keys.prove(proverInputs);

    expect(Object.keys(proof).sort()).toEqual(["a", "b", "c"]);
    expect(String(fetch.mock.calls[0]?.[0])).toBe("http://127.0.0.1:3001/prove");
    expect(JSON.parse(String(fetch.mock.calls[0]?.[1]?.body))).toMatchObject({
      circuitType: "transfer-confidential",
      publicInputHash: `0x${proverInputs.payload.publicInputHash.toString(16)}`,
    });

    await keys.prove({
      circuit: "transferRing",
      payload: { ...proverInputs.payload, ringProgramId: asField(7n) },
    });
    expect(JSON.parse(String(fetch.mock.calls[1]?.[1]?.body))).toMatchObject({
      circuitType: "transfer-ring",
    });
    const [input] = proverInputs.payload.inputs;
    const nullifierKey = fixture.keypair.nullifierKey();
    const secret = nullifierKey.secretBytes();
    try {
      await expect(
        instance.proveTransferInputs({
          ...proverInputs.payload,
          inputs:
            input === undefined
              ? []
              : [
                  {
                    ...input,
                    nullifierSecret: asField(bytesField(secret, "nullifier secret")),
                    statePathElements: [],
                  },
                ],
        }),
      ).rejects.toMatchObject({ code: "CLIENT_PROVER_INPUT" });
    } finally {
      secret.fill(0);
      nullifierKey.destroy();
    }
  });

  it("fetches state and nullifier proofs once and in parallel", async () => {
    // One real spend and one padding input: the padding slot's nullifier rides
    // in the same non-inclusion request as the real one, after it, so every
    // proof opens against one nullifier root.
    const fixture = proofFixture({ dummyInputs: 1 });
    const fetch = proverFetch();
    const instance = client(fetch);
    let resolveState!: (value: GetMerkleProofsResponse) => void;
    let resolveNullifier!: (value: GetNonInclusionProofsResponse) => void;
    const getMerkleProofs = vi
      .spyOn(instance, "getMerkleProofs")
      .mockImplementation(
        () => new Promise<GetMerkleProofsResponse>((resolve) => (resolveState = resolve)),
      );
    const getNonInclusionProofs = vi
      .spyOn(instance, "getNonInclusionProofs")
      .mockImplementation(
        () => new Promise<GetNonInclusionProofsResponse>((resolve) => (resolveNullifier = resolve)),
      );

    const pending = instance.proveTransact(
      fixture.proofInputs,
      LocalKeys.fromKeypair(fixture.keypair, instance.proofService),
    );
    expect(getMerkleProofs).toHaveBeenCalledOnce();
    expect(getNonInclusionProofs).toHaveBeenCalledOnce();
    expect(getMerkleProofs.mock.calls[0]?.slice(0, 2)).toEqual([
      TREE,
      fixture.proofInputs.inputUtxoHashes(),
    ]);
    expect(getNonInclusionProofs.mock.calls[0]?.slice(0, 2)).toEqual([
      TREE,
      [
        ...fixture.proofInputs.inputContexts().map((input) => input.nullifier),
        ...fixture.proofInputs.dummyNullifiers(),
      ],
    ]);
    expect(fetch).not.toHaveBeenCalled();

    resolveState({
      context: { blockTime: 1n, slot: 1n },
      proofs: [fixture.spendProof.state],
    });
    resolveNullifier({
      context: { blockTime: 1n, slot: 1n },
      proofs: [fixture.spendProof.nullifier, ...fixture.dummyProofs],
    });

    await expect(pending).resolves.toMatchObject({
      circuit: { kind: "confidentialEddsa", inputs: 2, outputs: 2 },
    });
    expect(fetch).toHaveBeenCalledOnce();
  });

  it("rejects proof inputs built for another output tree before any request", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>();
    const instance = client(fetch);
    const { proofInputs } = proofFixture({ outputTreeId: 1 });

    await expect(
      instance.proveTransact(
        proofInputs,
        LocalKeys.fromKeypair(proofFixture().keypair, instance.proofService),
      ),
    ).rejects.toMatchObject({
      code: "CLIENT_TREE_ID_MISMATCH",
      details: { expected: 0, actual: 1 },
    });
    expect(fetch).not.toHaveBeenCalled();
  });

  it("writes an open nullifier secret slot as null for a remote key holder", async () => {
    const fixture = proofFixture();
    const assembled = assemble(fixture.proofInputs, [fixture.spendProof]);
    const body = proverRequestBody(assembled.proverInputs);
    const inputs = body["inputs"];
    if (!Array.isArray(inputs)) throw new Error("inputs must be an array");
    const slots = inputs.map((input: unknown) =>
      typeof input === "object" && input !== null && "nullifierSecret" in input
        ? input.nullifierSecret
        : "missing",
    );
    // The wallet's own real input waits for its holder; padding carries zero.
    expect(slots[0]).toBeNull();
    expect(slots.slice(1).every((slot) => slot === "0x0")).toBe(true);
    // The same body, complete, is what the prover client posts.
    const posted = vi.fn<typeof globalThis.fetch>(async (_url, init) => {
      const sent = JSON.parse(String(init?.body)) as { inputs: { nullifierSecret: unknown }[] };
      expect(sent.inputs[0]?.nullifierSecret).toMatch(/^0x[0-9a-f]+$/u);
      expect(sent.inputs[0]?.nullifierSecret).not.toBe("0x0");
      return new Response(JSON.stringify(proofFor(String(init?.body))), {
        headers: { "content-type": "application/json" },
      });
    });
    const instance = client(posted);
    await LocalKeys.fromKeypair(fixture.keypair, instance.proofService).prove(
      assembled.proverInputs,
    );
    expect(posted).toHaveBeenCalledOnce();
  });

  it("refuses to prove an own input whose keys left the nullifier secret out", async () => {
    // A `ProofAuthority` that forwards the inputs untouched is a holder that
    // did not run; the prover request fails before any network call.
    const fetch = vi.fn<typeof globalThis.fetch>(async () => {
      throw new Error("network reached");
    });
    const instance = client(fetch);
    const fixture = proofFixture();
    vi.spyOn(instance, "getMerkleProofs").mockResolvedValue({
      context: { blockTime: 1n, slot: 1n },
      proofs: [fixture.spendProof.state],
    });
    vi.spyOn(instance, "getNonInclusionProofs").mockResolvedValue({
      context: { blockTime: 1n, slot: 1n },
      proofs: [fixture.spendProof.nullifier],
    });
    const forwarding = {
      prove: instance.proofService.prove.bind(instance.proofService),
      proveMerge: instance.proofService.proveMerge.bind(instance.proofService),
    };

    await expect(instance.proveTransact(fixture.proofInputs, forwarding)).rejects.toMatchObject({
      code: "CLIENT_MISSING_NULLIFIER_SECRET",
    });
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe("prover indexer fetching", () => {
  it("decodes a key holder's indexed request before its secret joins", async () => {
    const fixture = proofFixture();
    const prepared = prepareTransfer(fixture.proofInputs);
    const nullifierKey = fixture.keypair.nullifierKey();
    const service = { prove: vi.fn(), proveMerge: vi.fn(), proveIndexed: vi.fn() };
    const holders = [
      LocalKeys.fromKeypair(fixture.keypair, service),
      new NullifierKeyProofAuthority(nullifierKey, service),
    ];
    const bare = [
      LocalKeys.fromKeypair(fixture.keypair, { prove: vi.fn(), proveMerge: vi.fn() }),
      new NullifierKeyProofAuthority(nullifierKey, { prove: vi.fn(), proveMerge: vi.fn() }),
    ];
    nullifierKey.destroy();
    try {
      for (const holder of holders) {
        for (const request of [
          { circuit: "transfer", payload: { inputs: 5 } },
          { circuit: "bogus" },
        ]) {
          await expect(Reflect.apply(holder.proveIndexed, holder, [request])).rejects.toMatchObject(
            {
              code: "CLIENT_INVALID_PROOF_INPUTS",
            },
          );
        }
      }
      expect(service.proveIndexed).not.toHaveBeenCalled();
      for (const holder of bare) {
        await expect(holder.proveIndexed(prepared.inputs)).rejects.toMatchObject({
          code: "CLIENT_INVALID_CONFIG",
          details: { field: "proofs" },
        });
      }
    } finally {
      [...holders, ...bare].forEach((holder) => holder.destroy());
      fixture.keypair.destroy();
    }
  });

  it("refuses a key holder's root at the field modulus as unparsable", async () => {
    const fixture = proofFixture();
    const expected = assemble(fixture.proofInputs, [fixture.spendProof]);
    const modulus = checkedBytes(bigintToBytes(BN254_MODULUS, "root"), 32, "root");
    const tree = {
      tree: TREE,
      id: TREE_ID,
      utxoRoot: fixture.spendProof.state.root,
      nullifierRoot: fixture.spendProof.nullifier.root,
      utxoRootIndex: fixture.spendProof.state.rootIndex,
      nullifierRootIndex: fixture.spendProof.nullifier.rootIndex,
    };
    const hash = expected.publicInputHash;
    const resolutions = [
      { publicInputHash: hash, trees: [tree] },
      { publicInputHash: hash, trees: [{ ...tree, utxoRoot: modulus }] },
      { publicInputHash: hash, trees: [{ ...tree, nullifierRoot: modulus }] },
      { publicInputHash: modulus, trees: [tree] },
    ];
    const proof = parseProof(
      proofFor({ circuitType: "transfer-confidential", nInputs: 1, nOutputs: 1 }),
    );
    const instance = new ZolanaClient({ proofDataSource: "prover", fetch: vi.fn() });
    try {
      for (const [index, resolution] of resolutions.entries()) {
        const keys = {
          prove: vi.fn(),
          proveMerge: vi.fn(),
          proveIndexed: async () => ({ proof, resolution }),
        };
        const proving = instance.proveTransact(fixture.proofInputs, keys);
        if (index === 0) await expect(proving).resolves.toBeDefined();
        else await expect(proving).rejects.toMatchObject({ code: "CLIENT_PROOF_PARSE" });
      }
    } finally {
      fixture.keypair.destroy();
    }
  });

  it.each([false, true])("binds state root omission to cached inputs %s", async (cached) => {
    const fixture = proofFixture({ dummyInputs: 1 });
    try {
      const source = fixture.proofInputs;
      const transaction = new SppProofInputs({
        ...source,
        inputUtxos: source.inputUtxos.map((input) =>
          cached && !input.isDummy() ? input.withCacheSlot(0) : input,
        ),
        cacheAccounts: cached ? { read: FOREIGN_TREE } : {},
      });
      const prepared = prepareTransfer(transaction);
      for (const utxoRootIndex of [0, NO_UTXO_ROOT]) {
        for (const utxoRoot of [bytes(0), bytes(1)]) {
          const resolved = {
            tree: TREE,
            id: TREE_ID,
            utxoRoot,
            utxoRootIndex,
            nullifierRoot: fixture.spendProof.nullifier.root,
            nullifierRootIndex: fixture.spendProof.nullifier.rootIndex,
          };
          const complete = prepared.finish([
            {
              treeId: TREE_ID,
              slot: resolved,
              utxoRootIndex,
              nullifierRootIndex: resolved.nullifierRootIndex,
            },
          ]);
          const resolution = { trees: [resolved], publicInputHash: complete.publicInputHash };
          const validate = () => resolvedTrees(prepared.inputs, resolution);
          if (
            cached
              ? utxoRootIndex === NO_UTXO_ROOT && utxoRoot.every((byte) => byte === 0)
              : utxoRootIndex !== NO_UTXO_ROOT
          )
            expect(validate).not.toThrow();
          else expect(validate).toThrow(expect.objectContaining({ code: "CLIENT_PROOF_PARSE" }));
        }
      }
      const root = cached ? bytes(0) : fixture.spendProof.state.root;
      const rootIndex = cached ? NO_UTXO_ROOT : fixture.spendProof.state.rootIndex;
      const complete = prepared.finish([
        {
          treeId: TREE_ID,
          slot: { id: TREE_ID, utxoRoot: root, nullifierRoot: fixture.spendProof.nullifier.root },
          utxoRootIndex: rootIndex,
          nullifierRootIndex: fixture.spendProof.nullifier.rootIndex,
        },
      ]);
      const fetch = vi.fn<typeof globalThis.fetch>(async () =>
        Response.json({
          ...proofFor({ circuitType: "transfer-confidential", nInputs: 2, nOutputs: 2 }),
          resolution: {
            publicInputHash: `0x${bytesField(complete.publicInputHash, "hash").toString(16)}`,
            trees: [
              {
                tree: TREE,
                id: TREE_ID,
                utxoRoot: `0x${bytesField(root, "root").toString(16)}`,
                utxoRootIndex: rootIndex,
                nullifierRoot: `0x${bytesField(fixture.spendProof.nullifier.root, "root").toString(16)}`,
                nullifierRootIndex: fixture.spendProof.nullifier.rootIndex,
              },
            ],
          },
        }),
      );
      const client = new ZolanaClient({ fetch });
      const keys = LocalKeys.fromKeypair(fixture.keypair, client.proofService);
      try {
        const result = await client.proveTransact(transaction, keys);
        expect(result.treeContexts[0]?.utxoTreeRootIndex).toBe(rootIndex);
        expect(fetch).toHaveBeenCalledOnce();
        expect(String(fetch.mock.calls[0]?.[0])).toMatch(/\/prove\/indexed$/u);
      } finally {
        keys.destroy();
      }
    } finally {
      fixture.keypair.destroy();
    }
  });

  it.each([
    { proofDataSource: "client", recovered: false },
    { proofDataSource: "prover", recovered: false },
    { proofDataSource: "client", recovered: true },
    { proofDataSource: "prover", recovered: true },
  ] as const)(
    "keeps ring authority proving complete with $proofDataSource fetching and recovered=$recovered",
    async ({ proofDataSource, recovered }) => {
      const fixture = proofFixture({ dummyInputs: 1, ring: FOREIGN_TREE });
      const assembled = assemble(fixture.proofInputs, [fixture.spendProof], fixture.dummyProofs, {
        kind: "ringAuthority",
        ring: FOREIGN_TREE,
      });
      const fetch = vi.fn<typeof globalThis.fetch>(async () =>
        Response.json({
          ...proofFor({ circuitType: "transfer-ring-authority", nInputs: 2, nOutputs: 2 }),
          resolution: {
            publicInputHash: `0x${assembled.proverInputs.payload.publicInputHash.toString(16)}`,
            trees: [
              {
                tree: TREE,
                id: TREE_ID,
                utxoRoot: `0x${bytesField(fixture.spendProof.state.root, "root").toString(16)}`,
                nullifierRoot: `0x${bytesField(fixture.spendProof.nullifier.root, "root").toString(16)}`,
                utxoRootIndex: fixture.spendProof.state.rootIndex,
                nullifierRootIndex: fixture.spendProof.nullifier.rootIndex,
              },
            ],
          },
        }),
      );
      const instance = new ZolanaClient({ proofDataSource, fetch });
      const state = vi.spyOn(instance, "getMerkleProofs").mockResolvedValue({
        context: { blockTime: 1n, slot: 1n },
        proofs: [fixture.spendProof.state],
      });
      const nullifier = vi.spyOn(instance, "getNonInclusionProofs").mockResolvedValue({
        context: { blockTime: 1n, slot: 1n },
        proofs: [fixture.spendProof.nullifier, ...fixture.dummyProofs],
      });
      const nullifierKey = fixture.keypair.nullifierKey();
      const keys = recovered
        ? new NullifierKeyProofAuthority(nullifierKey, instance.proofService)
        : LocalKeys.fromKeypair(fixture.keypair, instance.proofService);
      nullifierKey.destroy();
      const indexed = vi.spyOn(keys, "proveIndexed");
      try {
        const result = await instance.proveRingAuthorityTransact(
          fixture.proofInputs,
          FOREIGN_TREE,
          keys,
        );
        expect(result.data.circuit.kind).toBe("ringAuthority");
        expect(state).toHaveBeenCalledTimes(proofDataSource === "client" ? 1 : 0);
        expect(nullifier).toHaveBeenCalledTimes(proofDataSource === "client" ? 1 : 0);
        expect(indexed).toHaveBeenCalledTimes(proofDataSource === "prover" ? 1 : 0);
        expect(fetch).toHaveBeenCalledOnce();
        expect(String(fetch.mock.calls[0]?.[0])).toMatch(
          proofDataSource === "prover" ? /\/prove\/indexed$/u : /\/prove$/u,
        );
        const body: unknown = JSON.parse(String(fetch.mock.calls[0]?.[1]?.body));
        const decoded = wireDecoder(() => new Error("invalid body")).record(body, "body");
        expect(proofDataSource === "prover" ? decoded["prepared"] : body).toMatchObject({
          circuitType: "transfer-ring-authority",
          publishedOutputOwnerPkHashes: [],
        });
      } finally {
        keys.destroy();
        fixture.keypair.destroy();
      }
    },
  );

  it("completes the indexed record slot without fetching client proofs", async () => {
    const fixture = proofFixture({ dummyInputs: 1, ring: FOREIGN_TREE });
    const zeroKey = NullifierKey.fromSecret(new Uint8Array(31) as Bytes31);
    const record = ProofInputUtxo.fromNullifierKey(
      new Utxo({
        owner: ShieldedPublicKey.fromEd25519(bytes(44)),
        asset: SOL_MINT,
        amount: 0n,
        blinding: bytes(2),
        ringProgramId: FOREIGN_TREE,
      }),
      zeroKey,
    );
    zeroKey.destroy();
    const transaction = new SppProofInputs({
      ...fixture.proofInputs,
      inputUtxos: [fixture.proofInputs.inputUtxos[0]!, record],
    });
    const tree = {
      tree: TREE,
      id: TREE_ID,
      utxoRoot: fixture.spendProof.state.root,
      nullifierRoot: fixture.spendProof.nullifier.root,
      utxoRootIndex: fixture.spendProof.state.rootIndex,
      nullifierRootIndex: fixture.spendProof.nullifier.rootIndex,
    };
    const prepared = prepareTransfer(transaction, { kind: "ring", ring: FOREIGN_TREE });
    const complete = prepared.finish([
      {
        treeId: TREE_ID,
        slot: tree,
        utxoRootIndex: tree.utxoRootIndex,
        nullifierRootIndex: tree.nullifierRootIndex,
      },
    ]);
    const hex = (value: Bytes32) => `0x${bytesField(value, "field").toString(16)}`;
    const fetch = vi.fn<typeof globalThis.fetch>(async () =>
      Response.json({
        ...proofFor({ circuitType: "transfer-ring", nInputs: 2, nOutputs: 2 }),
        resolution: {
          publicInputHash: hex(complete.publicInputHash),
          trees: [
            { ...tree, utxoRoot: hex(tree.utxoRoot), nullifierRoot: hex(tree.nullifierRoot) },
          ],
        },
      }),
    );
    const instance = new ZolanaClient({ fetch });
    const state = vi.spyOn(instance, "getMerkleProofs");
    const nullifier = vi.spyOn(instance, "getNonInclusionProofs");
    const keys = LocalKeys.fromKeypair(fixture.keypair, instance.proofService);
    try {
      const result = await instance.proveRingTransact(
        transaction,
        FOREIGN_TREE,
        withRecordSlotSecret(keys, record.nullifier()),
      );
      expect(result.data.circuit.kind).toBe("ringEddsa");
      expect(state).not.toHaveBeenCalled();
      expect(nullifier).not.toHaveBeenCalled();
      expect(fetch).toHaveBeenCalledOnce();
      expect(String(fetch.mock.calls[0]?.[0])).toMatch(/\/prove\/indexed$/u);
      const body: unknown = JSON.parse(String(fetch.mock.calls[0]?.[1]?.body));
      const decoder = wireDecoder(() => new Error("invalid body"));
      const payload = decoder.record(decoder.record(body, "body")["prepared"], "prepared");
      const inputs = decoder.list(payload["inputs"], "inputs");
      expect(decoder.record(inputs[0], "input")["nullifierSecret"]).toMatch(
        /^0x[1-9a-f][0-9a-f]*$/u,
      );
      expect(decoder.record(inputs[1], "record")["nullifierSecret"]).toBe("0x0");
    } finally {
      keys.destroy();
      fixture.keypair.destroy();
    }
  });

  for (const ring of [undefined, FOREIGN_TREE]) {
    it(`matches locally resolved transfer data for ${ring === undefined ? "pool" : "ring"}`, async () => {
      const fixture = proofFixture({ dummyInputs: 1 });
      const expected = assemble(
        fixture.proofInputs,
        [fixture.spendProof],
        fixture.dummyProofs,
        ring === undefined ? { kind: "confidential" } : { kind: "ring", ring },
      );
      const prepared = prepareTransfer(
        fixture.proofInputs,
        ring === undefined ? { kind: "confidential" } : { kind: "ring", ring },
      );
      const proof = proofFor({
        circuitType: ring === undefined ? "transfer-confidential" : "transfer-ring",
        nInputs: 2,
        nOutputs: 2,
      });
      const resultBody = {
        ...proof,
        resolution: {
          publicInputHash: `0x${expected.proverInputs.payload.publicInputHash.toString(16)}`,
          trees: [
            {
              tree: TREE,
              id: TREE_ID,
              utxoRoot: `0x${bytesField(fixture.spendProof.state.root, "root").toString(16)}`,
              nullifierRoot: `0x${bytesField(fixture.spendProof.nullifier.root, "root").toString(16)}`,
              utxoRootIndex: fixture.spendProof.state.rootIndex,
              nullifierRootIndex: fixture.spendProof.nullifier.rootIndex,
            },
          ],
        },
      };
      let calls = 0;
      const fallback = ring !== undefined;
      const fetch = vi.fn<typeof globalThis.fetch>(async () => {
        calls++;
        fixture.proofInputs.externalData.salt.fill(77);
        for (const message of fixture.proofInputs.externalData.messages) message.data.fill(88);

        if (fallback && calls === 1) return new Response(null, { status: 429 });
        if (fallback && calls === 2)
          return new Response(JSON.stringify({ jobId: "indexed-job", status: "queued" }), {
            status: 202,
            headers: { "content-type": "application/json" },
          });
        return new Response(
          JSON.stringify(
            fallback ? { status: "completed", result: { proof: resultBody } } : resultBody,
          ),
          { headers: { "content-type": "application/json" } },
        );
      });
      const instance = new ZolanaClient({
        proofDataSource: "prover",
        proverUrl: "https://prover.test/v1/zolana?api-key=secret",
        fetch,
      });
      const keys = LocalKeys.fromKeypair(fixture.keypair, instance.proofService);
      try {
        const result =
          ring === undefined
            ? await instance.proveTransact(fixture.proofInputs, keys)
            : (await instance.proveRingTransact(fixture.proofInputs, ring, keys)).data;
        expect(result).toEqual(
          expected.withProof(compressProof(parseProof(proof)).toTransactProof()),
        );
        expect(fetch).toHaveBeenCalledTimes(fallback ? 3 : 1);
        if (fallback) {
          expect(String(fetch.mock.calls[1]?.[0])).toBe(
            "https://prover.test/v1/zolana/prove/indexed?api-key=secret",
          );
          expect(new Headers(fetch.mock.calls[1]?.[1]?.headers).get("X-Async")).toBe("true");
          expect(String(fetch.mock.calls[2]?.[0])).toBe(
            "https://prover.test/v1/zolana/prove/status?api-key=secret&jobId=indexed-job",
          );
        }
        expect(String(fetch.mock.calls[0]?.[0])).toBe(
          "https://prover.test/v1/zolana/prove/indexed?api-key=secret",
        );
        const decoder = wireDecoder(() => new Error("bad request"));
        const body: unknown = JSON.parse(String(fetch.mock.calls[0]?.[1]?.body));
        const envelope = decoder.record(body, "request");
        const payload = decoder.record(envelope["prepared"], "prepared");
        expect(payload).not.toHaveProperty("treeSlots");
        expect(payload).not.toHaveProperty("publicInputHash");
        const first = decoder.record(decoder.list(payload["inputs"], "inputs")[0], "input");
        expect(first).not.toHaveProperty("statePathElements");
        expect(typeof first["nullifierSecret"]).toBe("string");
        expect(envelope["publicInputs"]).toEqual(
          prepared.inputs.publicInputs.map((value) => `0x${value.toString(16)}`),
        );
      } finally {
        keys.destroy();
        fixture.keypair.destroy();
      }
    });
  }

  it.each(["hash", "tree", "index", "nullifierIndex", "modulus", "missing"])(
    "rejects a mismatched %s before returning a transaction",
    async (corruption) => {
      const fixture = proofFixture();
      const expected = assemble(fixture.proofInputs, [fixture.spendProof]);
      const resolution = {
        publicInputHash: `0x${expected.proverInputs.payload.publicInputHash.toString(16)}`,
        trees: [
          {
            tree: TREE,
            id: TREE_ID,
            utxoRoot: `0x${bytesField(fixture.spendProof.state.root, "root").toString(16)}`,
            nullifierRoot: `0x${bytesField(fixture.spendProof.nullifier.root, "root").toString(16)}`,
            utxoRootIndex: 0,
            nullifierRootIndex: 0,
          },
        ],
      };
      if (corruption === "hash") resolution.publicInputHash = "0x1";
      if (corruption === "tree")
        resolution.trees[0] = { ...resolution.trees[0]!, tree: FOREIGN_TREE };
      if (corruption === "index")
        resolution.trees[0] = { ...resolution.trees[0]!, utxoRootIndex: 500 };
      if (corruption === "nullifierIndex")
        resolution.trees[0] = { ...resolution.trees[0]!, nullifierRootIndex: 100 };
      if (corruption === "modulus")
        resolution.trees[0] = {
          ...resolution.trees[0]!,
          nullifierRoot: `0x${BN254_MODULUS.toString(16)}`,
        };
      const fetch = vi.fn<typeof globalThis.fetch>(
        async () =>
          new Response(
            JSON.stringify({
              ...proofFor({ circuitType: "transfer-confidential", nInputs: 1, nOutputs: 1 }),
              ...(corruption === "missing" ? {} : { resolution }),
            }),
            { headers: { "content-type": "application/json" } },
          ),
      );
      const instance = new ZolanaClient({ proofDataSource: "prover", fetch });
      const keys = LocalKeys.fromKeypair(fixture.keypair, instance.proofService);
      try {
        await expect(instance.proveTransact(fixture.proofInputs, keys)).rejects.toMatchObject({
          code: "CLIENT_PROOF_PARSE",
        });
        expect(fetch).toHaveBeenCalledTimes(1);
      } finally {
        keys.destroy();
        fixture.keypair.destroy();
      }
    },
  );
});

it("copies resolved roots before client proof data can change", () => {
  const fixture = proofFixture();
  try {
    const assembled = assemble(fixture.proofInputs, [fixture.spendProof]);
    const roots = {
      state: new Uint8Array(assembled.roots.stateRoot),
      nullifier: new Uint8Array(assembled.roots.nullifierRoot),
    };
    fixture.spendProof.state.root.fill(0);
    fixture.spendProof.nullifier.root.fill(0);
    expect(assembled.roots.stateRoot).toEqual(roots.state);
    expect(assembled.roots.nullifierRoot).toEqual(roots.nullifier);
    expect(Object.isFrozen(assembled.proverInputs.payload.treeSlots)).toBe(true);
  } finally {
    fixture.keypair.destroy();
  }
});
