/// <reference types="node" />

import { createHash } from "node:crypto";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";

import type { Address, Bytes31, Bytes32, Signature } from "@zolana/interface";
import { TREE_ACCOUNT_SIZE } from "@zolana/interface";
import { describe, expect, it } from "vitest";

import { createTestWallet, fixtureBytes, startLocalStack, TestKitError } from "../src/index.js";
import {
  createE2eHarness,
  createProtocolConfigInstructions,
  createZoneConfig,
  createStandardAccountInstructions,
  createTestProver,
  createTreeInstructions,
  depositSolInstruction,
  groupInstructions,
  localStackUrls,
  mintToInstruction,
  parseCompiledInstruction,
  programBinaryPath,
  redactDiagnostic,
  sidecarPorts,
  singleOutput,
  splInterfaceAddresses,
  standardAccounts,
  systemCreateAccountInstruction,
  TestIndexer,
  TestRpc,
  tokenAmount,
  verifyStandardAccountsFixture,
  walletDepositData,
  zoneDeposit,
} from "../src/node/index.js";

const address = "11111111111111111111111111111111" as Address;
const signature = "1111111111111111111111111111111111111111111111111111111111111111" as Signature;

function bytes32(value: number): Bytes32 {
  return new Uint8Array(32).fill(value) as Bytes32;
}

function bytes31(value: number): Bytes31 {
  return new Uint8Array(31).fill(value) as Bytes31;
}

describe("public test-kit contract", () => {
  it("loads only manifest-pinned fixtures and verifies their hash", async () => {
    const bytes = await fixtureBytes("test-kit/standard-accounts-v1");
    expect(createHash("sha256").update(bytes).digest("hex")).toBe(
      "3d32fe32c4fe531b3f461aa7357168b1be0f863e76a189ad1db1774ef7544d76",
    );
    const fixture = JSON.parse(new TextDecoder().decode(bytes)) as {
      readonly expected: Readonly<Record<string, string>>;
    };
    expect(fixture.expected["protocolVault"]).toBe(standardAccounts().protocolVault);
    await expect(fixtureBytes("../manifest")).rejects.toMatchObject({
      code: "TEST_KIT_FIXTURE",
      details: { reason: "invalidName" },
    });
    await expect(fixtureBytes("test-kit/not-listed")).rejects.toMatchObject({
      code: "TEST_KIT_FIXTURE",
      details: { reason: "unlisted" },
    });
  });

  it("creates deterministic isolated wallet material from a copied seed", async () => {
    const seed = bytes32(7);
    const first = createTestWallet(seed);
    seed.fill(9);
    const second = createTestWallet(bytes32(7));
    expect(first.wallet.identity.ownerHash()).toEqual(second.wallet.identity.ownerHash());
    expect(first.wallet.identity.ownerHash()).not.toEqual(
      createTestWallet(bytes32(8)).wallet.identity.ownerHash(),
    );
    expect(await first.authority.shieldedAddress()).toEqual(first.wallet.identity);
    expect(first.authority.solanaPublicKey()).toBe(first.wallet.identity.solanaAddress());
  });

  it("returns typed errors with structured safe metadata", () => {
    const error = new TestKitError("TEST_KIT_TIMEOUT", {
      details: { service: "Photon", timeoutMs: 10 },
    });
    expect(error).toBeInstanceOf(Error);
    expect(error).toMatchObject({
      code: "TEST_KIT_TIMEOUT",
      details: { service: "Photon", timeoutMs: 10 },
    });
  });

  it("aborts before starting any local process", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(startLocalStack({ signal: controller.signal })).rejects.toMatchObject({
      code: "TEST_KIT_ABORTED",
    });
  });
});

describe("local stack configuration", () => {
  it("applies one offset to validator, Photon, prover, faucet, and prover metrics", () => {
    withEnvironment(
      {
        ZOLANA_PORT_OFFSET: "100",
        ZOLANA_LOCALNET_URL: undefined,
        ZOLANA_INDEXER_URL: undefined,
        ZOLANA_PROVER_URL: undefined,
      },
      () => {
        const urls = localStackUrls();
        expect(urls.rpcUrl.toString()).toBe("http://127.0.0.1:8999/");
        expect(urls.indexerUrl.toString()).toBe("http://127.0.0.1:8884/");
        expect(urls.proverUrl.toString()).toBe("http://127.0.0.1:3101/");
        expect(urls.external).toEqual({ rpc: false, indexer: false, prover: false });
        // The faucet and the metrics endpoint carry the same offset, so two
        // clones at different offsets never contend for 9900 or 9998.
        expect(sidecarPorts({ rpcPort: 8999, proverPort: 3101 })).toEqual({
          faucet: 10_000,
          proverMetrics: 10_098,
        });
      },
    );
    expect(sidecarPorts({ rpcPort: 8899, proverPort: 3001 })).toEqual({
      faucet: 9900,
      proverMetrics: 9998,
    });
  });

  it("honors explicit service URLs without claiming process ownership", () => {
    withEnvironment(
      {
        ZOLANA_LOCALNET_URL: "http://localhost:19001",
        ZOLANA_INDEXER_URL: "http://localhost:19002",
        ZOLANA_PROVER_URL: "http://localhost:19003",
      },
      () => {
        const urls = localStackUrls({ portOffset: 200 });
        expect(urls.rpcUrl.port).toBe("19001");
        expect(urls.indexerUrl.port).toBe("19002");
        expect(urls.proverUrl.port).toBe("19003");
        expect(urls.external).toEqual({ rpc: true, indexer: true, prover: true });
      },
    );
  });

  it("reuses healthy foreign services and leaves them running after stop", async () => {
    const rpc = await testServer(true);
    const indexer = await testServer(false);
    const prover = await testServer(false);
    const previous = {
      rpc: process.env["ZOLANA_LOCALNET_URL"],
      indexer: process.env["ZOLANA_INDEXER_URL"],
      prover: process.env["ZOLANA_PROVER_URL"],
    };
    process.env["ZOLANA_LOCALNET_URL"] = rpc.url;
    process.env["ZOLANA_INDEXER_URL"] = indexer.url;
    process.env["ZOLANA_PROVER_URL"] = prover.url;
    try {
      const stack = await startLocalStack();
      await stack.stop();
      expect((await fetch(new URL("/readiness", indexer.url))).ok).toBe(true);
      expect((await fetch(new URL("/health", prover.url))).ok).toBe(true);
    } finally {
      restoreEnvironment("ZOLANA_LOCALNET_URL", previous.rpc);
      restoreEnvironment("ZOLANA_INDEXER_URL", previous.indexer);
      restoreEnvironment("ZOLANA_PROVER_URL", previous.prover);
      await Promise.all([rpc.close(), indexer.close(), prover.close()]);
    }
  });

  it("rejects invalid offsets and URL schemes before I/O", () => {
    expect(() => localStackUrls({ portOffset: -1 })).toThrow(
      expect.objectContaining({ code: "TEST_KIT_INVALID_CONFIG" }),
    );
    withEnvironment({ ZOLANA_INDEXER_URL: "file:///secret" }, () => {
      expect(() => localStackUrls()).toThrow(
        expect.objectContaining({
          code: "TEST_KIT_INVALID_CONFIG",
          details: { field: "ZOLANA_INDEXER_URL", protocol: "file:" },
        }),
      );
    });
  });
});

describe("standard protocol material and instruction helpers", () => {
  it("derives all standard smart-account addresses and matches the Rust fixture", async () => {
    const accounts = await verifyStandardAccountsFixture();
    expect(accounts).toEqual(standardAccounts());
    const instructions = createStandardAccountInstructions({
      creator: address,
      signers: {
        protocol: address,
        forester: address,
        merge: address,
        tree: address,
        zone: address,
      },
    });
    expect(instructions).toHaveLength(5);
    expect(instructions.map((instruction) => instruction.data)).not.toContainEqual(
      instructions[0]?.data.map(() => 0),
    );
  });

  it("uses canonical builders and exact system create-account layout", () => {
    const admin = createProtocolConfigInstructions({ authority: address, permissionless: true });
    expect(admin).toHaveLength(1);
    expect(admin[0]?.data[0]).toBe(6);

    const instruction = systemCreateAccountInstruction({
      payer: address,
      account: address,
      lamports: 9n,
      space: 52n,
    });
    expect(instruction.data).toHaveLength(52);
    expect(new DataView(instruction.data.buffer).getBigUint64(4, true)).toBe(9n);
    expect(new DataView(instruction.data.buffer).getBigUint64(12, true)).toBe(52n);
    expect(instruction.accounts).toEqual([
      { address, isSigner: true, isWritable: true },
      { address, isSigner: true, isWritable: true },
    ]);
  });

  it("funds a tree from the rent the rpc reports, as Rust's create_tree does", async () => {
    const rpc = new TestRpc();
    const reads: number[] = [];
    const watched = {
      getMinimumBalanceForRentExemption: (dataLength: number) => {
        reads.push(dataLength);
        return rpc.getMinimumBalanceForRentExemption(dataLength);
      },
    };

    const instructions = await createTreeInstructions(watched, {
      payer: address,
      authority: address,
      tree: address,
      accountSize: TREE_ACCOUNT_SIZE,
    });

    expect(reads).toEqual([TREE_ACCOUNT_SIZE]);
    const create = instructions[0]?.data ?? new Uint8Array();
    const view = new DataView(create.buffer);
    expect(view.getBigUint64(4, true)).toBe(
      await rpc.getMinimumBalanceForRentExemption(TREE_ACCOUNT_SIZE),
    );
    expect(view.getBigUint64(12, true)).toBe(BigInt(TREE_ACCOUNT_SIZE));
    expect(instructions[1]?.data[0]).toBe(5);
  });

  it("refuses a tree rather than underfunding it when the rpc has no rent read", async () => {
    await expect(
      createTreeInstructions(
        {},
        { payer: address, authority: address, tree: address, accountSize: TREE_ACCOUNT_SIZE },
      ),
    ).rejects.toMatchObject({
      code: "TEST_KIT_RPC",
      details: { method: "getMinimumBalanceForRentExemption" },
    });
  });

  it("encodes SPL minting and reads token amounts without truncation", () => {
    const instruction = mintToInstruction({
      mint: address,
      account: address,
      authority: address,
      amount: 0x0102_0304_0506_0708n,
    });
    expect(instruction.data[0]).toBe(7);
    expect(new DataView(instruction.data.buffer).getBigUint64(1, true)).toBe(
      0x0102_0304_0506_0708n,
    );
    const account = new Uint8Array(165);
    new DataView(account.buffer).setBigUint64(64, 42n, true);
    expect(tokenAmount(account)).toBe(42n);
    expect(() => tokenAmount(new Uint8Array(71))).toThrow(
      expect.objectContaining({ code: "TEST_KIT_FIXTURE" }),
    );
  });

  it("derives deterministic wallet deposit fields behaviorally", () => {
    const recipient = createTestWallet(bytes32(3)).wallet.identity;
    const first = walletDepositData({
      amount: 12n,
      recipient,
      blindingSeed: bytes31(4),
      position: 2,
    });
    const second = walletDepositData({
      amount: 12n,
      recipient,
      blindingSeed: bytes31(4),
      position: 2,
    });
    expect(first).toEqual(second);
    expect(first.owner).toEqual(recipient.ownerHash());
    expect(first.viewTag).toEqual(recipient.confidentialViewTag());
    expect(depositSolInstruction({ tree: address, depositor: address, data: first }).data[0]).toBe(
      1,
    );
  });

  it("uses canonical SPL and zone builders and environment-aware program paths", () => {
    const spl = splInterfaceAddresses(address);
    expect(spl.registry).not.toBe(spl.vault);
    const zoneProgram = "CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8" as Address;
    const zone = createZoneConfig({
      payer: address,
      programId: zoneProgram,
      authority: address,
      enabled: true,
    });
    expect(zone.address).toBe("2fMJU7ij5i6pnYHvxHkJHsrVHNcUgWg5hySYBr4qvGDx");
    expect(zone.instruction.accounts[2]?.address).toBe(zone.address);
    expect(zone.instruction.data[0]).toBe(9);
    const instruction = zoneDeposit({
      tree: address,
      depositor: address,
      viewTag: bytes32(1),
      owner: bytes32(2),
      blinding: bytes31(3),
      amount: 4n,
      zoneProgramId: address,
      zoneDataHash: bytes32(5),
      zoneData: Uint8Array.of(6),
    });
    expect(instruction.data[0]).toBe(15);
    withEnvironment({ SHIELDED_POOL_PROGRAM_PATH: "/tmp/pool.so" }, () => {
      expect(
        programBinaryPath("/workspace", {
          environmentVariable: "SHIELDED_POOL_PROGRAM_PATH",
          fileName: "shielded_pool_program.so",
        }),
      ).toBe("/tmp/pool.so");
    });
  });
});

describe("fake service contracts and event indexing", () => {
  it("copies RPC data, preserves proof order, and rejects aborted calls", async () => {
    const rpc = new TestRpc();
    const data = Uint8Array.of(1, 2, 3);
    rpc.setAccount(address, { owner: address, data, lamports: 5n });
    data[0] = 9;
    expect((await rpc.getAccount(address))?.data).toEqual(Uint8Array.of(1, 2, 3));
    const fetched = await rpc.getAccount(address);
    fetched?.data.fill(8);
    expect((await rpc.getAccount(address))?.data).toEqual(Uint8Array.of(1, 2, 3));

    const controller = new AbortController();
    controller.abort();
    await expect(rpc.getBalance(address, { signal: controller.signal })).rejects.toMatchObject({
      code: "TEST_KIT_ABORTED",
    });
    await expect(rpc.getBalance(address, { timeoutMs: 0 })).rejects.toMatchObject({
      code: "TEST_KIT_TIMEOUT",
      details: { timeoutMs: 0 },
    });
  });

  it("indexes contiguous outputs, nullifiers, tags, and signature-bound transactions", () => {
    const indexer = new TestIndexer();
    const output = {
      viewTag: bytes32(1),
      utxoHash: bytes32(2),
      tree: address,
      leafIndex: 0n,
      data: Uint8Array.of(3),
    };
    indexer.record({
      signature,
      outputs: [output],
      nullifiers: [bytes32(4)],
      proofless: false,
    });
    expect(indexer.byViewTag(bytes32(1))).toEqual([output]);
    expect(indexer.isNullifierSpent(bytes32(4))).toBe(true);
    expect(indexer.transaction(signature)?.signature).toBe(signature);
    expect(() => {
      indexer.record({
        signature,
        outputs: [{ ...output, leafIndex: 2n }],
        nullifiers: [],
        proofless: false,
      });
    }).toThrow(expect.objectContaining({ code: "TEST_KIT_FIXTURE" }));
  });

  it("groups outer and inner instructions and rejects malformed indexes", () => {
    const instruction = {
      programAddress: address,
      accounts: [address],
      data: Uint8Array.of(1),
      stackHeight: 1,
    };
    const groups = groupInstructions(
      [instruction],
      new Map([[0, [{ ...instruction, stackHeight: 2 }]]]),
    );
    expect(groups).toHaveLength(1);
    expect(groups[0]?.inner[0]?.stackHeight).toBe(2);
    expect(
      parseCompiledInstruction([address], {
        programIndex: 0,
        accountIndexes: [0],
        data: Uint8Array.of(7),
      }),
    ).toEqual({
      programAddress: address,
      accounts: [address],
      data: Uint8Array.of(7),
    });
    let parseError: unknown;
    try {
      parseCompiledInstruction([address], {
        programIndex: 1,
        accountIndexes: [],
        data: new Uint8Array(),
      });
    } catch (error) {
      parseError = error;
    }
    expect(parseError).toBeInstanceOf(TestKitError);
    if (!(parseError instanceof TestKitError)) throw new Error("expected TestKitError");
    expect(parseError.details).toMatchObject({ reason: "programIndex", index: 1 });
    expect(() => groupInstructions([instruction], new Map([[1, [instruction]]]))).toThrow(
      expect.objectContaining({ code: "TEST_KIT_FIXTURE" }),
    );
    expect(
      singleOutput({
        signature,
        outputs: [
          {
            viewTag: bytes32(1),
            utxoHash: bytes32(2),
            tree: address,
            leafIndex: 0n,
            data: Uint8Array.of(3),
          },
        ],
        nullifiers: [],
        proofless: true,
      }).data,
    ).toEqual(Uint8Array.of(3));
  });

  it("captures exact prover request JSON and serves queued results", async () => {
    const prover = createTestProver();
    prover.enqueue({ proof: "fixture-proof" });
    const response = await prover.fetch("http://127.0.0.1:3001/prove", {
      method: "POST",
      body: '{"circuit":"transfer","input":{"amount":"1"}}',
    });
    expect(await response.json()).toEqual({ proof: "fixture-proof" });
    expect(prover.requests()).toEqual([{ circuit: "transfer", input: { amount: "1" } }]);
    expect(await (await prover.fetch("http://127.0.0.1:3001/health")).json()).toEqual({
      status: "ok",
    });
  });

  it("removes credential-shaped values from process diagnostics", () => {
    const secret = "a".repeat(64);
    const diagnostic = redactDiagnostic(
      `?api_key=top-secret authorization: bearer-token witness=${secret}`,
    );
    expect(diagnostic).not.toContain("top-secret");
    expect(diagnostic).not.toContain("bearer-token");
    expect(diagnostic).not.toContain(secret);
    expect(diagnostic).toContain("[REDACTED]");
  });

  it("constructs the reusable live E2E composition without starting services", () => {
    const stack = {
      rpcUrl: new URL("http://127.0.0.1:8899"),
      indexerUrl: new URL("http://127.0.0.1:8784"),
      proverUrl: new URL("http://127.0.0.1:3001"),
      stop: () => Promise.resolve(),
    };
    const harness = createE2eHarness(stack);
    expect(harness.stack).toBe(stack);
    expect(harness.client.tree).toBeDefined();
  });
});

function withEnvironment(
  values: Readonly<Record<string, string | undefined>>,
  run: () => void,
): void {
  const previous = Object.fromEntries(
    Object.keys(values).map((name) => [name, process.env[name]]),
  ) as Record<string, string | undefined>;
  try {
    for (const [name, value] of Object.entries(values)) {
      if (value === undefined) Reflect.deleteProperty(process.env, name);
      else process.env[name] = value;
    }
    run();
  } finally {
    for (const [name, value] of Object.entries(previous)) {
      if (value === undefined) Reflect.deleteProperty(process.env, name);
      else process.env[name] = value;
    }
  }
}

async function testServer(rpc: boolean): Promise<
  Readonly<{
    url: string;
    close(): Promise<void>;
  }>
> {
  const server = createServer((_request, response) => {
    response.writeHead(200, { "content-type": "application/json" });
    response.end(rpc ? '{"jsonrpc":"2.0","result":"ok","id":1}' : '{"status":"ok"}');
  });
  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", resolve);
  });
  const serverAddress = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${String(serverAddress.port)}`,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) reject(error);
          else resolve();
        });
      }),
  };
}

function restoreEnvironment(name: string, value: string | undefined): void {
  if (value === undefined) Reflect.deleteProperty(process.env, name);
  else process.env[name] = value;
}
