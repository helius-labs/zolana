// Deploys a fresh ring program from the built binaries, upgrades it in place
// and registers its config. Reads RING_PROGRAM_SO and USER_REGISTRY_PROGRAM_SO.
import { readFile } from "node:fs/promises";

import { address, generateKeyPairSigner } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { createZolanaClient } from "../../src/index.js";
import { ViewingKey } from "../../src/keypair/viewing-key.js";
import {
  createRingConfigInstruction,
  deployRingProgram,
  fetchRingProgramConfig,
  initSppRingConfigInstruction,
  ringProgramBinary,
  verifyRingProgram,
} from "../../src/ring/index.js";
import { airdrop, requiredEnv, sendInstruction } from "./ring-live-helpers.js";

describe("ring program", () => {
  it("deploys, upgrades and registers a ring under the sdk", async () => {
    const client = await createZolanaClient({
      solanaRpcUrl: requiredEnv("ZOLANA_LOCALNET_URL"),
      indexerUrl: requiredEnv("ZOLANA_INDEXER_URL"),
      proverUrl: requiredEnv("ZOLANA_PROVER_URL"),
      tree: address(requiredEnv("ZOLANA_TREE")),
    });
    // The registry binary first, the larger ring binary upgrades over it and extends the account.
    const first = ringProgramBinary(await readFile(requiredEnv("USER_REGISTRY_PROGRAM_SO")));
    const ring = ringProgramBinary(await readFile(requiredEnv("RING_PROGRAM_SO")));
    const operator = await generateKeyPairSigner();
    const program = await generateKeyPairSigner();

    for (const _ of [1, 2, 3]) await airdrop(client, operator.address);
    const deployed = await deployRingProgram({
      client,
      ringProgramId: program.address,
      binary: first,
      payer: operator,
      authority: operator,
      program,
    });
    expect(deployed.kind).toBe("deployed");
    expect(deployed.programData.upgradeAuthority).toBe(operator.address);
    await expect(
      deployRingProgram({
        client,
        ringProgramId: program.address,
        binary: first,
        payer: operator,
        authority: operator,
      }),
    ).resolves.toMatchObject({ kind: "present" });

    expect(ring.bytes.length).toBeGreaterThan(deployed.programData.capacity);
    const upgradePayer = await generateKeyPairSigner();
    for (const _ of [1, 2, 3]) await airdrop(client, upgradePayer.address);
    const upgraded = await deployRingProgram({
      client,
      ringProgramId: program.address,
      binary: ring,
      payer: upgradePayer,
      authority: operator,
    });
    expect(upgraded.kind).toBe("upgraded");
    expect(upgraded.programData.upgradeAuthority).toBe(operator.address);
    expect(upgraded.programData.capacity).toBeGreaterThanOrEqual(ring.bytes.length);
    await verifyRingProgram(client, program.address, ring);

    await sendInstruction(
      client,
      await createRingConfigInstruction({
        ringProgramId: program.address,
        payer: operator,
        authority: operator,
        auditorPublicKey: ViewingKey.generate().publicKey(),
        hasPolicy: false,
      }),
      operator,
    );
    await sendInstruction(
      client,
      await initSppRingConfigInstruction({
        ringProgramId: program.address,
        payer: operator,
        authority: operator,
        hasPolicy: false,
      }),
      operator,
    );
    const config = await fetchRingProgramConfig(client, program.address);
    expect(config.authority).toBe(operator.address);
    expect(config.hasPolicy).toBe(false);
  }, 900_000);
});
