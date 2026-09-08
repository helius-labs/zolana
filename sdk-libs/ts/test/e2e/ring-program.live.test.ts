// Deploys a fresh ring program from the built binaries, upgrades it in place
// and registers its config. Reads RING_PROGRAM_SO and USER_REGISTRY_PROGRAM_SO.
import { readFile } from "node:fs/promises";

import { address, generateKeyPairSigner, type Address } from "@solana/kit";
import { describe, expect, it } from "vitest";

import { createZolanaClient } from "../../src/index.js";
import { ViewingKey } from "../../src/keypair/viewing-key.js";
import {
  createRingConfigInstruction,
  fetchRingProgramConfig,
  initSppRingConfigInstruction,
  planRingProgramDeployment,
  ringProgramBinary,
  verifyRingProgram,
} from "../../src/ring/index.js";
import { currentSlot } from "./live-helpers.js";
import {
  airdrop,
  requiredEnv,
  sendInstruction,
  sendRingProgramDeployment,
} from "./ring-live-helpers.js";

/** Mirrors the ring CLI's `fund_authority`, the reported requirement is what gets funded. */
async function fundUpTo(
  client: Awaited<ReturnType<typeof createZolanaClient>>,
  owner: Address,
  lamports: bigint,
) {
  for (;;) {
    const { value } = await client.solanaRpc.getBalance(owner).send();
    if (value >= lamports) return;
    await airdrop(client, owner);
  }
}

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

    const buffer = await generateKeyPairSigner();
    const planned = await planRingProgramDeployment({
      client,
      ringProgramId: program.address,
      binary: first,
      authority: operator.address,
      payer: operator.address,
      buffer: buffer.address,
    });
    if (planned.kind !== "deploy") throw new Error("expected a deploy");
    await fundUpTo(client, operator.address, planned.requiredLamports);
    await sendRingProgramDeployment(client, planned, {
      payer: operator,
      buffer,
      authority: operator,
      program,
    });
    const deployed = await verifyRingProgram(client, program.address, first);
    expect(deployed.upgradeAuthority).toBe(operator.address);

    await expect(
      planRingProgramDeployment({
        client,
        ringProgramId: program.address,
        binary: first,
        authority: operator.address,
        payer: operator.address,
        buffer: (await generateKeyPairSigner()).address,
      }),
    ).resolves.toMatchObject({ kind: "present" });

    const upgradeBuffer = await generateKeyPairSigner();
    const upgrade = await planRingProgramDeployment({
      client,
      ringProgramId: program.address,
      binary: ring,
      authority: operator.address,
      payer: operator.address,
      buffer: upgradeBuffer.address,
    });
    if (upgrade.kind !== "upgrade") throw new Error("expected an upgrade");
    await fundUpTo(client, operator.address, upgrade.requiredLamports);
    await sendRingProgramDeployment(client, upgrade, {
      payer: operator,
      buffer: upgradeBuffer,
      authority: operator,
    });
    const upgraded = await verifyRingProgram(client, program.address, ring);
    expect(upgraded.capacity).toBeGreaterThanOrEqual(ring.bytes.length);
    // The loader refuses a program in the slot it was deployed in.
    while ((await currentSlot(client)) <= upgraded.lastDeploySlot) {
      await new Promise((resolve) => setTimeout(resolve, 200));
    }

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
