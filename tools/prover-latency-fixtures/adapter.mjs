import { readFile, access } from "node:fs/promises";
import { resolve, join } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  createZolanaClient,
  ShieldedKeypair,
  SigningKey,
  LocalKeys,
  SOL_MINT,
} from "../../sdk-libs/ts/dist/index.js";
import {
  AssetRegistry,
  ConfidentialTransfer,
  ProofInputUtxo,
  Merge,
  decryptToBalances,
} from "../../sdk-libs/ts/dist/transaction/index.js";

import { proveCustomRingTransfer } from "../../sdk-libs/ts/dist/ring/transfer.js";
import { ringConfigAddress, fetchRingProgramConfig } from "../../sdk-libs/ts/dist/ring/config.js";
import { prepareTransfer } from "../../sdk-libs/ts/dist/client/prover/assembly.js";
import { bigintToBytes } from "../../sdk-libs/ts/dist/client/internal.js";

const root = fileURLToPath(new URL("../..", import.meta.url));
const privateDirectory = resolve(
  process.env.PROVER_FIXTURE_DIR ?? join(root, "target/prover-rtt/private"),
);
const keyDirectory = process.env.PROVER_VERIFY_KEYS ?? join(root, "target/network-benchmark/keys");
const verifier = process.env.PROVER_VERIFY_BIN ?? join(root, "target/prover-rtt-proof-verify");

function verifyProof({ key, publicInput, proof, signal }) {
  return new Promise((accept, reject) => {
    const child = spawn(verifier, ["-key", key, "-public-input", publicInput], {
      stdio: ["pipe", "pipe", "pipe"],
      timeout: 30_000,
      signal,
    });
    let output = "";
    let error = "";
    child.stdout.on("data", (chunk) => {
      output += chunk;
    });
    child.stderr.on("data", (chunk) => {
      error += chunk;
    });
    child.on("error", reject);
    child.stdin.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) reject(new Error(`Local proof verification failed ${error.trim()}`));
      else if (!output.includes('"verified":true'))
        reject(new Error("Verifier did not confirm proof"));
      else accept(true);
    });
    child.stdin.end(JSON.stringify(proof));
  });
}

export async function prepare() {
  const indexer = process.env.INDEXER_URL ?? "https://d2xah7tnhdhcom.cloudfront.net";
  const deployments = {
    baseline: process.env.BASELINE_PROVER_URL ?? "https://d21ni15goiip6l.cloudfront.net",
    candidate: process.env.CANDIDATE_PROVER_URL,
  };
  if (!deployments.candidate) throw new Error("CANDIDATE_PROVER_URL is required");
  await access(verifier);
  let apiKey = process.env.PROVER_API_KEY;
  if (!apiKey) {
    try {
      apiKey = (await readFile(join(root, "target/prover-rtt/deployment/api-key"), "utf8")).trim();
    } catch (error) {
      if (error.code !== "ENOENT") throw error;
    }
  }
  const discovery = await createZolanaClient({
    solanaRpcUrl: process.env.SOLANA_RPC_URL ?? "https://api.devnet.solana.com",
    indexerUrl: indexer,
    proverUrl: deployments.baseline,
    indexerConfig: { poll: { numRetries: 0, delayMs: 0n, maxDelayMs: 0n } },
    fetch: (url, init) => fetch(url, { ...init, signal: AbortSignal.timeout(15_000) }),
  });
  const seed = Uint8Array.from(
    JSON.parse(await readFile(join(privateDirectory, "owner-seed.json"), "utf8")),
  );
  const owner = ShieldedKeypair.fromKeypair(SigningKey.fromEd25519Bytes(seed));
  seed.fill(0);
  const registry = new AssetRegistry();
  const transactions = await discovery.getShieldedTransactionsByTags({
    tags: [owner.shieldedAddress().confidentialViewTag()],
  });
  const balances = await decryptToBalances({
    keypair: owner,
    registry,
    transactions: transactions.transactions,
  });
  const available = balances.balance(SOL_MINT).utxos.slice(0, 2);
  if (available.length !== 2)
    throw new Error("Two confirmed dedicated fixture deposits are required");
  const inputs = available.map((utxo) => ProofInputUtxo.fromKeypair(utxo, owner));
  const recipient = ShieldedKeypair.generate();
  const ringProgramId =
    process.env.PROVER_FIXTURE_RING ?? "3b4wuHVM1zhL6Phs6So2n1ddr8K2wGQtFu7xATxYW9so";
  const ringAddress = await ringConfigAddress(ringProgramId);
  const ringAccount = await discovery.getAccount(ringAddress, {
    signal: AbortSignal.timeout(15_000),
  });
  const ringConfig = await fetchRingProgramConfig(discovery, ringProgramId, {
    signal: AbortSignal.timeout(15_000),
  });
  if (ringConfig.hasPolicy) throw new Error("The fixture ring must use the audit-only circuit");
  let mergeSequence = 0n;
  const mergeExpiry = BigInt(Math.floor(Date.now() / 1000)) + 3600n;
  const fixture = (family, shape, keyFile) => ({
    shape,
    keyFile,
    async prove({ source, url, fetch, signal, span }) {
      const client = await createZolanaClient({
        solanaRpcUrl: "https://api.devnet.solana.com",
        indexerUrl: indexer,
        proverUrl: url,
        proofDataSource: source,
        fetch: (request, init) => {
          const endpoint = new URL(request);
          if (
            url === deployments.candidate &&
            endpoint.origin === new URL(url).origin &&
            endpoint.pathname.startsWith("/prove") &&
            apiKey
          ) {
            const headers = new Headers(init?.headers);
            headers.set("X-API-Key", apiKey);
            return fetch(request, { ...init, headers });
          }
          return fetch(request, init);
        },
        indexerConfig: {
          requireSlot: transactions.context.slot,
          poll: { numRetries: 0, delayMs: 0n, maxDelayMs: 0n },
        },
      });
      const keys = LocalKeys.fromKeypair(owner, client.proofService);
      const context = { signal, timeoutMs: 60_000 };
      try {
        if (family === "merge") {
          const prepared = await span("preparation", () =>
            Merge.fromKeypair(owner, inputs)
              .withExpiry(mergeExpiry + mergeSequence++)
              .prepare(),
          );
          return await client.proveMerge({ prepared, keys }, context);
        }
        if (family === "transfer-ring" || family === "custom-ring-base") {
          const prepared = await span("preparation", () => {
            const transfer = new ConfidentialTransfer(
              owner.shieldedAddress(),
              inputs,
              owner.toSolanaSigner().address,
            )
              .withCompactChange()
              .withShape({ inputs: 2, outputs: 3 });
            transfer.sendToRing(recipient.shieldedAddress(), SOL_MINT, 1n, ringProgramId);
            return transfer.prepare();
          });
          let ringResult;
          const complete = new Error("Requested ring proof is complete");
          const ringClient = new Proxy(client, {
            get(target, property) {
              if (property === "getAccount")
                return async (address) => {
                  if (address !== ringAddress) throw new Error("Unexpected fixture account lookup");
                  return ringAccount;
                };
              if (property === "proveRingTransact")
                return async (...args) => {
                  if (family === "transfer-ring") {
                    ringResult = await target.proveRingTransact(...args);
                    throw complete;
                  }
                  // 2. The audit statement binds the private hash from SDK assembly.
                  const local = prepareTransfer(args[0], ringProgramId);
                  return {
                    data: { privateTxHash: bigintToBytes(local.inputs.payload.privateTxHash) },
                  };
                };
              const value = Reflect.get(target, property, target);
              return typeof value === "function" ? value.bind(target) : value;
            },
          });
          try {
            return await proveCustomRingTransfer(
              {
                client: ringClient,
                ringProgramId,
                prepared,
                keys,
                assets: registry,
                tree: client.tree,
              },
              context,
            );
          } catch (error) {
            if (error !== complete) throw error;
            return ringResult;
          }
        }
        const transfer = await span("preparation", () => {
          const value = new ConfidentialTransfer(
            owner.shieldedAddress(),
            inputs,
            owner.toSolanaSigner().address,
          ).withShape({ inputs: 2, outputs: 3 });
          value.send(recipient.shieldedAddress(), SOL_MINT, 1n);
          return value;
        });
        const prepared = await span("signing", () => transfer.sign(owner, registry));
        return await client.proveTransact(prepared, keys, undefined, context);
      } finally {
        keys.destroy();
      }
    },
    async verify({ wire, signal }) {
      const completed = [...wire].reverse().find((item) => item.response?.ar !== undefined);
      if (!completed) throw new Error("Complete proof response is missing");
      const publicInput =
        completed.request.publicInputHash ?? completed.response.resolution?.publicInputHash;
      if (!publicInput) throw new Error("Expected public input hash is missing");
      return verifyProof({
        key: join(keyDirectory, keyFile),
        publicInput,
        proof: completed.response,
        signal,
      });
    },
  });
  const fixtures = {
    "transfer-confidential": fixture(
      "transfer-confidential",
      "2x3",
      "transfer_confidential_2_3.key",
    ),
    merge: fixture("merge", "8x1", "merge_8_1.key"),
    "transfer-ring": fixture("transfer-ring", "2x3", "transfer_ring_2_3.key"),
    "transfer-ring-authority": {
      shape: "2x2",
      blocked: "The deployed ring has its authority transfer rail disabled",
    },
    "transfer-p256-ring": {
      shape: "2x3",
      blocked: "The TS fixture builder rejects P256 owners, a Rust fixture is required",
    },
    "merge-ring": {
      shape: "8x1",
      blocked: "The TS fixture builder rejects ring merge inputs, a Rust fixture is required",
    },
    "custom-ring-base": {
      ...fixture("custom-ring-base", "audit", "custom_ring_base.key"),
      blockedDeployments: {
        baseline: "The deployed baseline has no custom_ring_base.key release key",
      },
    },
    "custom-ring-policy": { blocked: "The deployed ring has no policy account" },
  };
  for (const value of Object.values(fixtures)) {
    if (!value.blocked) await access(join(keyDirectory, value.keyFile));
  }
  return {
    deployments,
    indexer,
    fixtures,
    metadata: {
      tree: discovery.tree,
      treeId: discovery.treeId,
      ringProgramId,
      ringHasPolicy: ringConfig.hasPolicy,
      fixtureTransactions: transactions.transactions.length,
      measuredTransfersSubmitted: false,
      ringConfigurationPrefetched: true,
      customRingBaseStatement:
        "Individual audit proof, private transaction hash derived by SDK assembly, no SPP proof requested",
      firstUseLabel: "First observed request, server key cache state is unknown",
    },
  };
}
