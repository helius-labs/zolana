import { describe, expect, it } from "vitest";

import { checkedServiceUrl } from "../src/client/internal.js";
import {
  DEFAULT_TEE_PROVER_ENDPOINT,
  LOCALNET_PHOTON_ENDPOINT,
  LOCALNET_PROVER_ENDPOINT,
  LOCALNET_SOLANA_ENDPOINT,
  isDefaultTeeProver,
  isZolanaGateway,
  resolveClientEndpoints,
} from "../src/endpoint.js";

const HELIUS = "https://devnet.helius-rpc.com?api-key=k";

describe("resolveClientEndpoints", () => {
  it("pins the devnet-e-tee-1 prover endpoint", () => {
    expect(DEFAULT_TEE_PROVER_ENDPOINT).toBe("https://dd73hh473h6ha.cloudfront.net");
    expect(isDefaultTeeProver(new URL("https://d55y5ksdsm1vw.cloudfront.net"))).toBe(false);
  });

  it("serves every service from one url", () => {
    const rpc = "https://rpc.example?api-key=k";
    const resolved = resolveClientEndpoints({ solanaRpcUrl: rpc });
    expect([resolved.solana, resolved.photon, resolved.prover]).toEqual([rpc, rpc, rpc]);
    expect([resolved.photonField, resolved.proverField]).toEqual(["solanaRpcUrl", "solanaRpcUrl"]);
  });

  it("serves the indexer from a Helius RPC host's zolana namespace", () => {
    const resolved = resolveClientEndpoints({ solanaRpcUrl: HELIUS });
    expect(resolved.solana).toBe(HELIUS);
    expect(String(resolved.photon)).toBe("https://devnet.helius-rpc.com/v1/zolana?api-key=k");
    expect(isZolanaGateway(new URL(resolved.photon))).toBe(true);
    const custom = resolveClientEndpoints({ solanaRpcUrl: "https://devnet.helius-rpc.com/custom" });
    expect(custom.photon).toBe("https://devnet.helius-rpc.com/custom");
    expect(isZolanaGateway(new URL("https://prover.example/v1/zolana"))).toBe(false);
  });

  it("sends a Helius devnet RPC URL's proofs to the default TEE prover, without its api key", () => {
    for (const rpc of [HELIUS, "https://beta-devnet.helius-rpc.com/?api-key=k"]) {
      const resolved = resolveClientEndpoints({ solanaRpcUrl: rpc });
      expect(resolved.prover).toBe(DEFAULT_TEE_PROVER_ENDPOINT);
      expect(resolved.proverField).toBe("solanaRpcUrl");
      expect(isDefaultTeeProver(new URL(resolved.prover))).toBe(true);
    }
    const named = resolveClientEndpoints({
      solanaRpcUrl: HELIUS,
      proverUrl: "https://prover.example",
    });
    expect(named.prover).toBe("https://prover.example");
  });

  it("recognizes only the default deployment origin and base path", () => {
    expect(isDefaultTeeProver(new URL(`${DEFAULT_TEE_PROVER_ENDPOINT}/?api-key=k`))).toBe(true);
    for (const url of [
      `${DEFAULT_TEE_PROVER_ENDPOINT}/other`,
      `${DEFAULT_TEE_PROVER_ENDPOINT}:8443`,
      DEFAULT_TEE_PROVER_ENDPOINT.replace("https:", "http:"),
      `${DEFAULT_TEE_PROVER_ENDPOINT}.evil.example`,
    ])
      expect(isDefaultTeeProver(new URL(url))).toBe(false);
  });

  it("keeps a non-devnet Helius RPC URL's proofs on its gateway", () => {
    const resolved = resolveClientEndpoints({
      solanaRpcUrl: "https://mainnet.helius-rpc.com/?api-key=k",
    });
    expect(String(resolved.prover)).toBe("https://mainnet.helius-rpc.com/v1/zolana?api-key=k");
    expect(isZolanaGateway(new URL(resolved.prover))).toBe(true);
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
