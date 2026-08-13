import { describe, expect, it } from "vitest";

import { checkedServiceUrl } from "../src/client/internal.js";
import {
  LOCALNET_PHOTON_ENDPOINT,
  LOCALNET_PROVER_ENDPOINT,
  LOCALNET_SOLANA_ENDPOINT,
  resolveClientEndpoints,
} from "../src/endpoint.js";

const HELIUS = "https://devnet.helius-rpc.com?api-key=k";

describe("resolveClientEndpoints", () => {
  it("serves every service from one url", () => {
    const resolved = resolveClientEndpoints({ solanaRpcUrl: HELIUS });
    expect([resolved.solana, resolved.photon, resolved.prover]).toEqual([HELIUS, HELIUS, HELIUS]);
    expect([resolved.photonField, resolved.proverField]).toEqual(["solanaRpcUrl", "solanaRpcUrl"]);
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
