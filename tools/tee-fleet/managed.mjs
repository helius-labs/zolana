// Operator-only qualification of two independently running routers with one private S3 registry.
import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { once } from "node:events";
import { writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";

const execute = promisify(execFile);
const bucket = "zolana-pri285-test-routing-558215002830";
const owner = "558215002830";
const region = "us-east-1";

export async function managedRouter({ deployments, binary, output }) {
  const key = `qualification/${randomBytes(12).toString("hex")}/registry.json`;
  const originApiKey = randomBytes(24).toString("hex");
  const config = {
    schema_version: 1,
    revision: 0,
    expires_at: Math.floor(Date.now() / 1000) + 6 * 3600,
    generations: deployments.map((entry) => ({
      id: entry.id,
      region: entry.region,
      recipient_id: entry.recipientId,
      draining: false,
      disabled: false,
      backends: [{ id: entry.id, origin: entry.origin, api_key_arn: entry.apiKeyARN }],
    })),
  };
  const processes = [];
  const stopped = new Set();
  const outages = [];
  const observations = [];
  const realOutage = process.env.ZOLANA_TEE_REAL_OUTAGE === "1";
  let etag;

  async function service(id, action) {
    const entry = deployments.find((item) => item.id === id);
    assert.ok(
      entry && /^i-[0-9a-f]{17}$/u.test(entry.instanceId) && ["start", "stop"].includes(action),
    );
    const aws = async (...args) => {
      try {
        return JSON.parse(
          (
            await execute("aws", ["--region", entry.region, ...args, "--output", "json"], {
              timeout: 30000,
              maxBuffer: 1 << 20,
            })
          ).stdout,
        );
      } catch (error) {
        if (String(error.stderr).includes("InvocationDoesNotExist")) return { Status: "Pending" };
        throw new Error("isolated enclave service command failed");
      }
    };
    const sent = await aws(
      "ssm",
      "send-command",
      "--instance-ids",
      entry.instanceId,
      "--document-name",
      "AWS-RunShellScript",
      "--timeout-seconds",
      "120",
      "--parameters",
      JSON.stringify({
        commands: [`sudo systemctl ${action} zolana-enclave@0.service`],
        executionTimeout: ["60"],
      }),
    );
    const command = sent.Command.CommandId;
    const deadline = Date.now() + 90000;
    for (;;) {
      const result = await aws(
        "ssm",
        "get-command-invocation",
        "--command-id",
        command,
        "--instance-id",
        entry.instanceId,
        "--query",
        "{Status:Status,ResponseCode:ResponseCode}",
      );
      if (result.Status === "Success") {
        outages.push({ id, action, command, at: new Date().toISOString() });
        return;
      }
      assert.ok(
        ["Pending", "InProgress", "Delayed"].includes(result.Status) && Date.now() < deadline,
        "isolated enclave service action did not succeed",
      );
      await delay(1000);
    }
  }

  async function publish() {
    config.revision++;
    const path = resolve(output, "routing-registry.json");
    await writeFile(path, JSON.stringify(config, null, 2) + "\n");
    try {
      const { stdout } = await execute(
        "aws",
        [
          "--region",
          region,
          "s3api",
          "put-object",
          "--bucket",
          bucket,
          "--key",
          key,
          "--expected-bucket-owner",
          owner,
          "--body",
          path,
          "--content-type",
          "application/json",
          ...(etag === undefined ? ["--if-none-match", "*"] : ["--if-match", etag]),
          "--output",
          "json",
        ],
        { timeout: 30000, maxBuffer: 1 << 20 },
      );
      const result = JSON.parse(stdout);
      assert.equal(typeof result.VersionId, "string");
      assert.equal(typeof result.ETag, "string");
      etag = result.ETag;
    } catch {
      throw new Error("conditional test routing publication failed");
    }
  }

  async function status(process) {
    const response = await fetch(`${process.admin}/status`, { signal: AbortSignal.timeout(5000) });
    assert.equal(response.status, 200);
    const value = await response.json();
    assert.ok(Number.isSafeInteger(value.revision));
    assert.ok(Array.isArray(value.backends));
    return value;
  }

  async function synchronize() {
    for (const id of stopped)
      if (!config.generations.find((entry) => entry.id === id).disabled) {
        await service(id, "start");
        stopped.delete(id);
      }
    await publish();
    const deadline = Date.now() + 45000;
    for (;;) {
      const states = await Promise.all(processes.map(status));
      const converged = states.every(
        (state) =>
          state.registry_fresh &&
          state.revision === config.revision &&
          config.generations.every((generation) => {
            const backend = state.backends.find((item) => item.id === generation.id);
            return (
              backend &&
              backend.draining === generation.draining &&
              backend.disabled === generation.disabled &&
              (generation.disabled || backend.healthy)
            );
          }),
      );
      if (converged || Date.now() >= deadline) {
        observations.push({
          revision: config.revision,
          converged,
          at: new Date().toISOString(),
          states,
        });
        await writeFile(
          resolve(output, "routing-observations.json"),
          JSON.stringify(observations, null, 2) + "\n",
        );
      }
      if (converged) return;
      assert.ok(
        processes.every((process) => process.child.exitCode === null),
        "managed router stopped",
      );
      assert.ok(Date.now() < deadline, "managed routing replicas did not converge");
      await delay(250);
    }
  }

  async function start(index) {
    const child = spawn(
      binary,
      [
        "--registry-bucket",
        bucket,
        "--registry-key",
        key,
        "--registry-owner",
        owner,
        "--registry-region",
        region,
        "--preferred-region",
        deployments[index % deployments.length].region,
        "--listen",
        "127.0.0.1:0",
        "--admin-listen",
        "127.0.0.1:0",
      ],
      {
        env: { ...process.env, ZOLANA_ROUTER_ORIGIN_KEY: originApiKey },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    const processState = { child, url: undefined, admin: undefined };
    processes.push(processState);
    // The command emits only fixed startup/errors. Do not expose inherited AWS diagnostics.
    child.stderr.resume();
    await new Promise((resolveStart, rejectStart) => {
      let pending = "";
      const timeout = setTimeout(() => {
        child.kill();
        rejectStart(new Error("managed router startup timed out"));
      }, 30000);
      child.stdout.on("data", (chunk) => {
        pending += chunk.toString();
        const match =
          /^TEE router listening on (127\.0\.0\.1:\d+); private health on (127\.0\.0\.1:\d+)\n/u.exec(
            pending,
          );
        if (!match) return;
        clearTimeout(timeout);
        processState.url = `http://${match[1]}`;
        processState.admin = `http://${match[2]}`;
        resolveStart();
      });
      child.once("error", () => {
        clearTimeout(timeout);
        rejectStart(new Error("managed router failed to start"));
      });
      child.once("exit", () => {
        clearTimeout(timeout);
        rejectStart(new Error("managed router exited during startup"));
      });
    });
  }

  async function close() {
    let restoreError;
    try {
      for (const id of stopped) {
        await service(id, "start");
        stopped.delete(id);
      }
    } catch (error) {
      restoreError = error;
    }
    await Promise.all(
      processes.map(async ({ child }) => {
        if (child.exitCode !== null || child.signalCode !== null || child.pid === undefined) return;
        const stopped = once(child, "close");
        child.kill("SIGTERM");
        await stopped;
      }),
    );
    if (restoreError) throw restoreError;
  }

  try {
    await publish();
    await Promise.all([start(0), start(1)]);
    await synchronize();
  } catch (error) {
    await close();
    throw error;
  }

  const generation = (id) => {
    const value = config.generations.find((entry) => entry.id === id);
    assert.ok(value, "unknown managed generation");
    return value;
  };
  return {
    origin: processes.map((process) => process.url),
    originApiKey,
    metadata: {
      source: "private versioned S3",
      bucket,
      key,
      replicas: processes.length,
      realOutage,
      outages,
    },
    setAvailable(id, available) {
      generation(id).disabled = !available;
    },
    setDraining(id, draining) {
      generation(id).draining = draining;
    },
    sync: synchronize,
    restore: synchronize,
    async failGeneration(id) {
      if (!realOutage) {
        generation(id).disabled = true;
        for (const entry of config.generations) if (entry.id !== id) entry.disabled = false;
        await synchronize();
        return;
      }
      for (const entry of config.generations) entry.disabled = false;
      await synchronize();
      // A lost SSM acknowledgement can follow a successful stop. Always
      // attempt restoration once the stop may have been dispatched.
      stopped.add(id);
      await service(id, "stop");
      const deadline = Date.now() + 30000;
      for (;;) {
        const states = await Promise.all(processes.map(status));
        if (
          states.every((state) => {
            const backend = state.backends.find((entry) => entry.id === id);
            return (
              state.registry_fresh &&
              state.revision === config.revision &&
              backend?.healthy === false &&
              backend.disabled === false
            );
          })
        ) {
          outages.push({
            id,
            action: "health_observed_down",
            registryRevision: config.revision,
            replicas: states.length,
            at: new Date().toISOString(),
          });
          return;
        }
        assert.ok(Date.now() < deadline, "routing health did not observe the real enclave outage");
        await delay(250);
      }
    },
    async readStats() {
      const states = await Promise.all(processes.map(status));
      const forwarded = Object.fromEntries(deployments.map((entry) => [entry.id, 0]));
      for (const state of states)
        for (const backend of state.backends) {
          assert.ok(
            Object.hasOwn(forwarded, backend.id) && Number.isSafeInteger(backend.forwarded),
          );
          forwarded[backend.id] += backend.forwarded;
        }
      return { forwarded, unavailable: states.reduce((sum, state) => sum + state.unavailable, 0) };
    },
    close,
  };
}
