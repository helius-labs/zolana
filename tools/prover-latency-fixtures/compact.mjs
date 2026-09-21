import { resolve } from "node:path";
import { prepare as prepareFixtures } from "./adapter.mjs";

export async function prepare() {
  const phase = process.env.PROVER_CAMPAIGN_PHASE;
  const directory = process.env.PROVER_CAMPAIGN_DIRECTORY;
  if (!["public", "private"].includes(phase) || !directory) {
    throw new Error("PROVER_CAMPAIGN_PHASE and PROVER_CAMPAIGN_DIRECTORY are required");
  }
  const config = await prepareFixtures({ compactOnly: true });
  return {
    ...config,
    entries: [1, 2].flatMap((repetition) =>
      ["padded", "compact"].map((variant) => ({
        family: "transfer-confidential",
        fixture: variant,
        variant,
        route: phase,
        deployment: "candidate",
        source: "prover",
        repetition,
      })),
    ),
    campaign: {
      directory: resolve(directory),
      phase,
      identity: JSON.stringify({
        input: config.metadata.fixtureInputHash,
        tree: config.metadata.tree,
        amount: config.metadata.sendAmountLamports,
        recipient: config.metadata.recipient,
      }),
    },
    metadata: {
      ...config.metadata,
      indexerRoute: phase,
      clientDiscoveryIndexerUrl: config.indexer,
      clientDiscoveryMeasured: false,
      expectedServerIndexerUrl:
        phase === "public" ? config.indexer : "http://photon-api.zolnet-devnet-c.internal:8784",
      measurement: "One real SOL input, one lamport sent, SDK selects the circuit shape",
    },
  };
}
