import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { address } from "@solana/kit";

const sdk = fileURLToPath(new URL("../", import.meta.url));
const workspace = fileURLToPath(new URL("../../../", import.meta.url));
function loopback(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is required`);
  const url = new URL(value);
  if (
    !["http:", "https:"].includes(url.protocol) ||
    !["127.0.0.1", "localhost", "[::1]"].includes(url.hostname) ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new Error(`${name} must be a credential-free loopback endpoint`);
  }
  return value;
}
const rpc = loopback("ZOLANA_LOCALNET_URL");
const indexer = loopback("ZOLANA_INDEXER_URL");
loopback("ZOLANA_PROVER_URL");
if (!process.env.ZOLANA_TREE) throw new Error("ZOLANA_TREE is required");
address(process.env.ZOLANA_TREE);
const cli = process.env.ZOLANA_CLI_BIN ?? join(workspace, "target/debug/zolana");
const program =
  process.env.RING_PROGRAM_SO ?? join(workspace, "target/deploy/custom_ring_program.so");
if (!existsSync(cli) || !existsSync(program))
  throw new Error("build the local CLI and custom ring program first");
const artifacts = mkdtempSync(join(tmpdir(), "zolana-ts-ring-controls-"));
const environment = {
  ...process.env,
  ZOLANA_CONFIG_DIR: join(artifacts, "config"),
  RING_PROGRAM_SO: program,
};
const run = (...args) => {
  const output = execFileSync(cli, args, {
    cwd: workspace,
    env: environment,
    encoding: "utf8",
    maxBuffer: 2 * 1024 * 1024,
  });
  process.stdout.write(output);
  return output;
};
console.log(`Ring controls artifacts: ${artifacts}`);
const wallet = process.env.ZOLANA_TEST_AUTHORITY_WALLET ?? join(artifacts, "authority.json");
if (process.env.ZOLANA_TEST_AUTHORITY_WALLET === undefined)
  run("wallet", "new", "--outfile", wallet);
else if (!existsSync(wallet)) throw new Error("ZOLANA_TEST_AUTHORITY_WALLET does not exist");
environment.ZOLANA_TEST_AUTHORITY_WALLET = wallet;

for (const [kind, mintVariable, accountVariable] of [
  ["legacy", "ZOLANA_TEST_MINT", "ZOLANA_TEST_TOKEN_ACCOUNT"],
  ["token2022", "ZOLANA_TEST_TOKEN_2022_MINT", "ZOLANA_TEST_TOKEN_2022_ACCOUNT"],
]) {
  const output = run(
    "dev",
    "pool",
    "test-mint",
    "--keypair",
    wallet,
    "--authority-path",
    wallet,
    "--rpc-url",
    rpc,
    "--indexer-url",
    indexer,
    "--airdrop-lamports",
    "1000000000",
    "--amount",
    "1000000000000",
    "--token-program",
    kind,
  );
  const matches = [
    ...output.matchAll(
      /^ok test_mint mint=(\S+) asset_id=(\d+) token_account=(\S+) owner=\S+ amount=\d+$/gm,
    ),
  ];
  if (matches.length !== 1) throw new Error(`could not read ${kind} mint bootstrap result`);
  const [, mint, assetId, account] = matches[0];
  if (BigInt(assetId) < 2n || BigInt(assetId) > 0xffff_ffff_ffff_ffffn)
    throw new Error("invalid test asset id");
  environment[mintVariable] = address(mint);
  environment[accountVariable] = address(account);
}
const vitest = join(
  dirname(fileURLToPath(import.meta.resolve("vitest/package.json"))),
  "vitest.mjs",
);
const result = spawnSync(
  process.execPath,
  [vitest, "run", "--no-file-parallelism", "test/e2e/ring-controls.live.test.ts"],
  { cwd: sdk, env: environment, stdio: "inherit" },
);
if (result.error) throw result.error;
process.exitCode = result.status ?? 1;
