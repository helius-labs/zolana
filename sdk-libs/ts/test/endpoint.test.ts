import { describe, expect, it } from "vitest";

import { checkedServiceUrl } from "../src/client/internal.js";
import {
  LOCALNET_PHOTON_ENDPOINT,
  LOCALNET_PROVER_ENDPOINT,
  LOCALNET_SOLANA_ENDPOINT,
  isZolanaGateway,
  resolveClientEndpoints,
} from "../src/endpoint.js";

const HELIUS = "https://devnet.helius-rpc.com?api-key=k";

describe("resolveClientEndpoints", () => {
  it("serves every service from one url", () => {
    const rpc = "https://rpc.example?api-key=k";
    const resolved = resolveClientEndpoints({ solanaRpcUrl: rpc });
    expect([resolved.solana, resolved.photon, resolved.prover]).toEqual([rpc, rpc, rpc]);
    expect([resolved.photonField, resolved.proverField]).toEqual(["solanaRpcUrl", "solanaRpcUrl"]);
  });

  it("serves the indexer and the prover from a Helius RPC host's zolana namespace", () => {
    const resolved = resolveClientEndpoints({ solanaRpcUrl: HELIUS });
    expect(resolved.solana).toBe(HELIUS);
    for (const url of [resolved.photon, resolved.prover]) {
      expect(String(url)).toBe("https://devnet.helius-rpc.com/v1/zolana?api-key=k");
      expect(isZolanaGateway(new URL(url))).toBe(true);
    }
    const custom = resolveClientEndpoints({ solanaRpcUrl: "https://devnet.helius-rpc.com/custom" });
    expect(custom.photon).toBe("https://devnet.helius-rpc.com/custom");
    expect(isZolanaGateway(new URL("https://prover.example/zolana"))).toBe(false);
  });

  it("resolves localnet to accepted service urls", () => {
    const resolved = resolveClientEndpoints({});
    expect([resolved.solana, resolved.photon, resolved.prover]).toEqual([
      LOCALNET_SOLANA_ENDPOINT,
      LOCALNET_PHOTON_ENDPOINT,
      LOCALNET_PROVER_ENDPOINT,
    ]);
    expect(() => checkedServiceUrl(resolved.solana, "solanaRpcUrl")).not.toThrow();
    expect(() => checkedServiceUrl(resolved.photon, resolved.photonField)).not.toThrow();
    expect(() => checkedServiceUrl(resolved.prover, resolved.proverField)).not.toThrow();
  });

  it("prefers service-specific urls over the shared fallback", () => {
    const photon = new URL("https://photon.example/path");
    const resolved = resolveClientEndpoints({
      solanaRpcUrl: HELIUS,
      indexerUrl: photon,
      proverUrl: "https://prover.example",
    });
    expect([resolved.solana, resolved.photon, resolved.prover]).toEqual([
      HELIUS,
      photon,
      "https://prover.example",
    ]);
    expect([resolved.photonField, resolved.proverField]).toEqual(["indexerUrl", "proverUrl"]);
  });

  it("carries a websocket url through", () => {
    const resolved = resolveClientEndpoints({
      solanaRpcUrl: "https://rpc.example",
      solanaRpcSubscriptionsUrl: "wss://ws.example",
    });
    expect(resolved.solanaRpcSubscriptions).toBe("wss://ws.example");
  });
});
