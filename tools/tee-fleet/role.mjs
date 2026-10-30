// Scoped, temporary runtime identity for the owned PRI-285 qualification only.
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { writeJson } from "./artifacts.mjs";
import { resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { promisify } from "node:util";

const execute = promisify(execFile);
const owner = "558215002830";

// Only identity/permission reads during temporary-role setup use this retry.
// Runtime refreshes, publications, faults and proof requests keep their limits.
export async function retryInitializationRead(read, onRetry) {
  try {
    return await read();
  } catch (error) {
    if (!["ClientTimeout", "InvalidClientTokenId"].includes(error.awsCode)) throw error;
    await onRetry(error);
    await delay(1000);
    return read();
  }
}

async function aws(args, env = process.env) {
  try {
    const { stdout } = await execute("aws", [...args, "--output", "json"], {
      env,
      timeout: 30000,
      maxBuffer: 1 << 20,
    });
    return stdout.trim() ? JSON.parse(stdout) : {};
  } catch (error) {
    const message = String(error.stderr);
    const kind = /AccessDenied|UnauthorizedOperation|Forbidden|\(403\)/u.test(message)
      ? "denied"
      : message.includes("NoSuchEntity")
        ? "missing"
        : "failed";
    const sanitized = new Error(`qualification AWS operation ${kind}`);
    sanitized.kind = kind;
    sanitized.operation = (args[0] === "--region" ? args.slice(2, 4) : args.slice(0, 2)).join(".");
    sanitized.awsCode =
      /An error occurred \(([A-Za-z0-9_]+)\)/u.exec(message)?.[1] ??
      (error.killed
        ? "ClientTimeout"
        : error instanceof SyntaxError
          ? "ResponseEncoding"
          : "UnknownAwsFailure");
    throw sanitized;
  }
}

export async function runtimeRole({ registries, key, deployments, output }) {
  const match = /^qualification\/([0-9a-f]{24})\/registry\.json$/u.exec(key);
  assert.ok(match);
  const name = `zolana-pri285-router-${match[1]}`;
  const caller = await aws(["sts", "get-caller-identity"]);
  assert.equal(caller.Account, owner);
  const assumed = /^arn:aws:sts::558215002830:assumed-role\/([^/]+)\/[^/]+$/u.exec(caller.Arn);
  assert.ok(assumed);
  const operator = await aws(["iam", "get-role", "--role-name", assumed[1]]);
  const principal = operator.Role.Arn;
  assert.ok(principal.startsWith(`arn:aws:iam::${owner}:role/`));
  const objects = registries.map(({ bucket }) => `arn:aws:s3:::${bucket}/${key}`);
  const secrets = deployments.map((entry) => {
    assert.ok(
      entry.apiKeyARN.startsWith(`arn:aws:secretsmanager:${entry.region}:${owner}:secret:ApiKey-`),
    );
    return entry.apiKeyARN;
  });
  const policy = {
    Version: "2012-10-17",
    Statement: [
      { Effect: "Allow", Action: ["s3:GetObject"], Resource: objects },
      { Effect: "Allow", Action: ["secretsmanager:GetSecretValue"], Resource: secrets },
    ],
  };
  const metadata = {
    name,
    arn: `arn:aws:iam::${owner}:role/${name}`,
    principal,
    policy,
    initialization_retries: [],
  };
  const record = () => writeJson(resolve(output, "runtime-role.json"), metadata);
  const initializeRead = (args, environment) =>
    retryInitializationRead(
      () => aws(args, environment),
      async (error) => {
        metadata.initialization_retries.push({
          operation: error.operation,
          code: error.awsCode,
          at: new Date().toISOString(),
        });
        await record();
      },
    );
  await record();
  let created = false;
  async function removePolicy(policyName) {
    try {
      await aws(["iam", "delete-role-policy", "--role-name", name, "--policy-name", policyName]);
    } catch (error) {
      if (error.kind !== "missing") throw error;
    }
  }
  async function close() {
    if (!created) return;
    await removePolicy("RoutingReadOnly");
    await aws(["iam", "delete-role", "--role-name", name]);
    created = false;
    metadata.deleted_at = new Date().toISOString();
    await record();
  }
  try {
    await aws([
      "iam",
      "create-role",
      "--role-name",
      name,
      "--assume-role-policy-document",
      JSON.stringify({
        Version: "2012-10-17",
        Statement: [{ Effect: "Allow", Principal: { AWS: principal }, Action: "sts:AssumeRole" }],
      }),
      "--tags",
      JSON.stringify([{ Key: "Purpose", Value: "pri285-routing-qualification" }]),
      "--max-session-duration",
      "3600",
    ]);
    created = true;
    await aws([
      "iam",
      "put-role-policy",
      "--role-name",
      name,
      "--policy-name",
      "RoutingReadOnly",
      "--policy-document",
      JSON.stringify(policy),
    ]);
    const deadline = Date.now() + 60000;
    let credentials;
    for (;;) {
      try {
        credentials = (
          await aws([
            "sts",
            "assume-role",
            "--role-arn",
            metadata.arn,
            "--role-session-name",
            "pri285-router",
            "--duration-seconds",
            "3600",
          ])
        ).Credentials;
        break;
      } catch (error) {
        if (error.kind !== "denied" || Date.now() >= deadline) throw error;
        await delay(1000);
      }
    }
    // Credentials live only in child-process environments. Reports contain the
    // public role, exact resource policy and expiry, never credential values.
    assert.ok(
      ["AccessKeyId", "SecretAccessKey", "SessionToken"].every(
        (key) => typeof credentials[key] === "string" && credentials[key].length > 0,
      ),
    );
    assert.ok(Date.parse(credentials.Expiration) > Date.now());
    metadata.session_expires = credentials.Expiration;
    await record();
    const environment = {
      ...process.env,
      AWS_ACCESS_KEY_ID: credentials.AccessKeyId,
      AWS_SECRET_ACCESS_KEY: credentials.SecretAccessKey,
      AWS_SESSION_TOKEN: credentials.SessionToken,
    };
    delete environment.AWS_PROFILE;
    delete environment.AWS_DEFAULT_PROFILE;
    const identity = await initializeRead(["sts", "get-caller-identity"], environment);
    assert.equal(identity.Arn, `arn:aws:sts::${owner}:assumed-role/${name}/pri285-router`);
    const actions = [
      "s3:PutObject",
      "s3:ListBucket",
      "secretsmanager:PutSecretValue",
      "kms:Decrypt",
      "kms:Sign",
      "ssm:SendCommand",
      "iam:PassRole",
    ];
    const evaluated = await initializeRead([
      "iam",
      "simulate-principal-policy",
      "--policy-source-arn",
      metadata.arn,
      "--action-names",
      ...actions,
    ]);
    assert.equal(evaluated.EvaluationResults.length, actions.length);
    assert.ok(
      evaluated.EvaluationResults.every((entry) =>
        ["implicitDeny", "explicitDeny"].includes(entry.EvalDecision),
      ),
    );
    metadata.simulated_denials = evaluated.EvaluationResults.map((entry) => ({
      action: entry.EvalActionName,
      decision: entry.EvalDecision,
    }));
    await record();
    return {
      environment,
      metadata,
      close,
    };
  } catch (error) {
    metadata.failure = { operation: error.operation, code: error.awsCode, kind: error.kind };
    await record();
    await close();
    throw error;
  }
}
