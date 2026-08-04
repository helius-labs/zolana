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
  /** The goal: a Helius URL serves the RPC, the indexer, and the prover. */
  it("serves every service from one url", () => {
    const resolved = resolveClientEndpoints({ solanaRpcUrl: HELIUS });
    expect([resolved.solana, resolved.photon, resolved.prover]).toEqual([HELIUS, HELIUS, HELIUS]);
    expect([resolved.photonField, resolved.proverField]).toEqual(["solanaRpcUrl", "solanaRpcUrl"]);
  });

  /** A config that names no url at all reaches the local stack. */
  it("fans localnet out to its separate ports", () => {
    const resolved = resolveClientEndpoints({});
    expect([resolved.solana, resolved.photon, resolved.prover]).toEqual([
      LOCALNET_SOLANA_ENDPOINT,
      LOCALNET_PHOTON_ENDPOINT,
      LOCALNET_PROVER_ENDPOINT,
    ]);
  });

  /**
   * The fanned-out ports have to survive validation, or localnet would resolve
   * to URLs the client then rejects.
   */
  it("resolves localnet to urls the client accepts", () => {
    const resolved = resolveClientEndpoints({});
    expect(() => checkedServiceUrl(resolved.solana, resolved.solanaField)).not.toThrow();
    expect(() => checkedServiceUrl(resolved.photon, resolved.photonField)).not.toThrow();
    expect(() => checkedServiceUrl(resolved.prover, resolved.proverField)).not.toThrow();
  });

  it("keeps the three local ports distinct", () => {
    expect(
      new Set([LOCALNET_SOLANA_ENDPOINT, LOCALNET_PHOTON_ENDPOINT, LOCALNET_PROVER_ENDPOINT]).size,
    ).toBe(3);
  });

  it("prefers a named url over the fallback", () => {
    const resolved = resolveClientEndpoints({
      solanaRpcUrl: HELIUS,
      indexerUrl: "https://photon.example",
    });
    expect(resolved.photon).toBe("https://photon.example");
    expect(resolved.photonField).toBe("indexerUrl");
    expect(resolved.prover).toBe(HELIUS);
  });

  it("routes every service apart", () => {
    const resolved = resolveClientEndpoints({
      solanaRpcUrl: "https://rpc.example",
      indexerUrl: "https://photon.example",
      proverUrl: "https://prover.example",
    });
    expect([resolved.solana, resolved.photon, resolved.prover]).toEqual([
      "https://rpc.example",
      "https://photon.example",
      "https://prover.example",
    ]);
  });

  /** A named url beats a localnet default, so the two cannot disagree. */
  it("lets a named url win over a localnet default port", () => {
    const resolved = resolveClientEndpoints({
      proverUrl: "https://prover.example",
    });
    expect([resolved.solana, resolved.photon, resolved.prover]).toEqual([
      LOCALNET_SOLANA_ENDPOINT,
      LOCALNET_PHOTON_ENDPOINT,
      "https://prover.example",
    ]);
  });

  /** `ZOLANA_PORT_OFFSET` shifts the ports, so a caller names the shifted ones. */
  it("takes shifted local ports when named", () => {
    const resolved = resolveClientEndpoints({
      solanaRpcUrl: "http://127.0.0.1:8999",
      indexerUrl: "http://127.0.0.1:8884",
      proverUrl: "http://127.0.0.1:3101",
    });
    expect([resolved.solana, resolved.photon, resolved.prover]).toEqual([
      "http://127.0.0.1:8999",
      "http://127.0.0.1:8884",
      "http://127.0.0.1:3101",
    ]);
  });

  it("accepts a URL object as well as a string", () => {
    const url = new URL("https://photon.example/path");
    const resolved = resolveClientEndpoints({
      solanaRpcUrl: "https://rpc.example",
      indexerUrl: url,
    });
    expect(resolved.photon).toBe(url);
  });

  it("carries a websocket url through", () => {
    const resolved = resolveClientEndpoints({
      solanaRpcUrl: "https://rpc.example",
      solanaRpcSubscriptionsUrl: "wss://ws.example",
    });
    expect(resolved.solanaRpcSubscriptions).toBe("wss://ws.example");
  });

  /** Nothing here can tell a local URL from an intended one, so it is honored. */
  it("honors a loopback url", () => {
    const resolved = resolveClientEndpoints({ solanaRpcUrl: "http://127.0.0.1:8899" });
    expect([resolved.photon, resolved.prover]).toEqual([
      "http://127.0.0.1:8899",
      "http://127.0.0.1:8899",
    ]);
  });
});
