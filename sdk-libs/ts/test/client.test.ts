import {
  SOLANA_ERROR__JSON_RPC__METHOD_NOT_FOUND,
  SolanaError,
  address,
  getBase58Decoder,
} from "@solana/kit";
import { describe, expect, it, vi } from "vitest";

import {
  ClientError,
  ZolanaClient,
  type GetMerkleProofsResponse,
  type GetNonInclusionProofsResponse,
  type SpendProof,
  type ZolanaClientConfig,
} from "../src/client/index.js";
import { defaultSolanaRpcSubscriptionsUrl, runKitRpc } from "../src/client/kit.js";
import type { Bytes16, Bytes32 } from "../src/interface/index.js";
import { ShieldedKeypair } from "../src/keypair/index.js";
import {
  ProofInputUtxo,
  SOL_MINT,
  SppProofInputs,
  Utxo,
  createExternalData,
  createProofOutput,
} from "../src/transaction/index.js";

const TREE = address("3JF3sEqM796hk5WFqA6EtmEwJQ9quALszsfJyvXNQKy3");
const RPC_URL = "https://rpc.example.com/zolana";
const INDEXER_URL = "https://indexer.example.com/api";
const PROVER_URL = "https://prover.example.com/api";
const STANDARD_PROOF = {
  ar: ["0x0", "0x0"],
  bs: [
    ["0x0", "0x0"],
    ["0x0", "0x0"],
  ],
  krs: ["0x0", "0x0"],
};

function bytes(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function proofFixture(): Readonly<{ proofInputs: SppProofInputs; spendProof: SpendProof }> {
  const keypair = ShieldedKeypair.generate();
  const input = new ProofInputUtxo({
    utxo: new Utxo({
      owner: keypair.signingPublicKey(),
      asset: SOL_MINT,
      amount: 7n,
      blinding: bytes(1),
    }),
    nullifierKey: keypair.nullifierKey(),
  });
  const output = createProofOutput({
    ownerAddress: keypair.shieldedAddress(),
    asset: SOL_MINT,
    amount: 7n,
    blinding: bytes(2),
  });
  const ownerTag = bytes(8);
  const proofInputs = new SppProofInputs({
    // The payer must own the input notes: only its own are provable.
    payer: keypair.shieldedAddress().solanaAddress(),
    inputUtxos: [input],
    outputs: [output],
    externalData: createExternalData({
      txViewingPublicKey: keypair.viewingPublicKey(),
      salt: new Uint8Array(16) as Bytes16,
      outputs: [{ utxoHash: output.hash(), ownerTag: { kind: "inline", value: ownerTag } }],
      resolvedOwnerTags: [ownerTag],
      messages: [],
    }),
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
  return { proofInputs, spendProof };
}

type ServiceOverrides = Pick<ZolanaClientConfig, "indexerUrl" | "proverUrl">;

async function serviceRequestUrls(
  solanaRpcUrl: string | URL,
  overrides: ServiceOverrides = {},
): Promise<readonly string[]> {
  const urls: string[] = [];
  const fetch = vi.fn(async (input: URL | RequestInfo): Promise<Response> => {
    const requestUrl = input instanceof Request ? input.url : String(input);
    urls.push(requestUrl);
    const path = new URL(requestUrl).pathname;
    if (path.endsWith("/get_shielded_transactions_by_nullifiers")) {
      return new Response(
        JSON.stringify({
          id: "test-account",
          jsonrpc: "2.0",
          result: { context: { block_time: 1, slot: 1 }, transactions: [] },
        }),
        { headers: { "content-type": "application/json" } },
      );
    }
    if (path.endsWith("/prove")) {
      return new Response(JSON.stringify(STANDARD_PROOF), {
        headers: { "content-type": "application/json" },
      });
    }
    throw new Error(`unexpected request: ${requestUrl}`);
  }) as typeof globalThis.fetch;
  const instance = new ZolanaClient({
    solanaRpcUrl,
    ...overrides,
    tree: TREE,
    fetch,
    indexerConfig: {
      poll: { numRetries: 1, delayMs: 0n, maxDelayMs: 0n },
    },
  });

  await instance.getShieldedTransactionsByNullifiers({ nullifiers: [bytes(7)] });
  const fixture = proofFixture();
  vi.spyOn(instance, "getInputMerkleProofs").mockResolvedValue([fixture.spendProof]);
  await instance.proveTransact(fixture.proofInputs);
  return urls;
}

function client(fetch = vi.fn<typeof globalThis.fetch>()): ZolanaClient {
  return new ZolanaClient({
    solanaRpcUrl: "http://127.0.0.1:8899",
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

  it.each([
    {
      name: "uses the RPC endpoint for both omitted services",
      overrides: {},
      expected: [
        "https://rpc.example.com/zolana/get_shielded_transactions_by_nullifiers",
        "https://rpc.example.com/zolana/prove",
      ],
    },
    {
      name: "keeps an explicit indexer and falls the prover back to RPC",
      overrides: { indexerUrl: INDEXER_URL },
      expected: [
        "https://indexer.example.com/api/get_shielded_transactions_by_nullifiers",
        "https://rpc.example.com/zolana/prove",
      ],
    },
    {
      name: "falls the indexer back to RPC and keeps an explicit prover",
      overrides: { proverUrl: PROVER_URL },
      expected: [
        "https://rpc.example.com/zolana/get_shielded_transactions_by_nullifiers",
        "https://prover.example.com/api/prove",
      ],
    },
    {
      name: "keeps both explicit service endpoints",
      overrides: { indexerUrl: INDEXER_URL, proverUrl: PROVER_URL },
      expected: [
        "https://indexer.example.com/api/get_shielded_transactions_by_nullifiers",
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
      "https://rpc.example.com/zolana/get_shielded_transactions_by_nullifiers",
      "https://rpc.example.com/zolana/prove",
    ]);
  });

  it("clones a URL object before deriving service request URLs", async () => {
    const rpcUrl = new URL("https://gateway.example.com/base?cluster=devnet");
    const original = rpcUrl.href;

    await expect(serviceRequestUrls(rpcUrl)).resolves.toEqual([
      "https://gateway.example.com/base/get_shielded_transactions_by_nullifiers?cluster=devnet",
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

  it("forwards paginated nullifier lookups through the client facade", async () => {
    const fetch = vi.fn<typeof globalThis.fetch>(() =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            id: "test-account",
            jsonrpc: "2.0",
            result: {
              context: { block_time: 1, slot: 1 },
              transactions: [],
              next_cursor: "Ag==",
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
      "http://127.0.0.1:8784/get_shielded_transactions_by_nullifiers",
    );
    expect(JSON.parse(String(fetch.mock.calls[0]?.[1]?.body))).toMatchObject({
      method: "get_shielded_transactions_by_nullifiers",
      params: {
        nullifiers: [getBase58Decoder().decode(nullifier)],
        cursor: "AQ==",
        limit: 1000,
      },
    });
  });

  it("fetches state and nullifier proofs once and in parallel", async () => {
    const instance = client();
    const utxoHash = bytes(1);
    const nullifier = bytes(2);
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

    const pending = instance.getInputMerkleProofs([{ index: 0, utxoHash, nullifier }]);
    expect(getMerkleProofs).toHaveBeenCalledOnce();
    expect(getNonInclusionProofs).toHaveBeenCalledOnce();

    resolveState({
      context: { blockTime: 1n, slot: 1n },
      proofs: [
        {
          leaf: utxoHash,
          merkleContext: { treeType: 1, tree: TREE },
          path: [],
          leafIndex: 0n,
          root: bytes(3),
          rootSeq: 1n,
          rootIndex: 4,
        },
      ],
    });
    resolveNullifier({
      context: { blockTime: 1n, slot: 1n },
      proofs: [
        {
          leaf: nullifier,
          merkleContext: { treeType: 1, tree: TREE },
          path: [],
          lowElement: bytes(4),
          lowElementIndex: 0n,
          highElement: bytes(5),
          highElementIndex: 1n,
          root: bytes(6),
          rootSeq: 1n,
          rootIndex: 7,
        },
      ],
    });

    await expect(pending).resolves.toHaveLength(1);
  });
});
