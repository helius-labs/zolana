import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readdir, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { gzipSync } from "node:zlib";

const packageRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const repositoryRoot = path.resolve(packageRoot, "../..");
const crateRoot = path.join(repositoryRoot, "sdk-libs/hasher-wasm");
const assetPath = path.join(packageRoot, "src/hasher/poseidon.wasm");
const lockPath = path.join(packageRoot, "poseidon-wasm.lock.json");
const targetDirectory = path.join(repositoryRoot, "target/hasher-wasm");
const compiledPath = path.join(
  targetDirectory,
  "wasm32-unknown-unknown/release/zolana_hasher_wasm.wasm",
);

const sourceFiles = [
  ".cargo/config.toml",
  "Cargo.toml",
  "rust-toolchain.toml",
  "program-libs/hasher/Cargo.toml",
  "sdk-libs/hasher-wasm/Cargo.lock",
  "sdk-libs/hasher-wasm/Cargo.toml",
  "sdk-libs/ts/scripts/poseidon-wasm.mjs",
];
const sourceDirectories = ["program-libs/hasher/src", "sdk-libs/hasher-wasm/src"];

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

async function sourceHash() {
  const files = [...sourceFiles];
  for (const directory of sourceDirectories) {
    const entries = await readdir(path.join(repositoryRoot, directory), {
      recursive: true,
    });
    files.push(
      ...entries
        .filter((entry) => entry.endsWith(".rs"))
        .map((entry) => path.posix.join(directory, entry.split(path.sep).join("/"))),
    );
  }
  files.sort();
  const hash = createHash("sha256");
  for (const file of files) {
    hash
      .update(file)
      .update("\0")
      .update(await readFile(path.join(repositoryRoot, file)));
  }
  return hash.digest("hex");
}

function compile() {
  const cargoHome = process.env.CARGO_HOME ?? path.join(os.homedir(), ".cargo");
  const environment = { ...process.env };
  delete environment.RUSTFLAGS;
  environment.CARGO_ENCODED_RUSTFLAGS = [
    `--remap-path-prefix=${repositoryRoot}=/zolana`,
    `--remap-path-prefix=${cargoHome}=/cargo`,
  ].join("\u001f");
  execFileSync(
    "cargo",
    [
      "build",
      "--locked",
      "--release",
      "--target",
      "wasm32-unknown-unknown",
      "--target-dir",
      targetDirectory,
    ],
    { cwd: crateRoot, env: environment, stdio: "inherit" },
  );
}

async function metadata(bytes) {
  return {
    sourceSha256: await sourceHash(),
    wasmSha256: sha256(bytes),
    wasmBytes: bytes.length,
  };
}

const mode = process.argv[2] ?? "--check";
if (mode === "--build" || mode === "--verify") compile();
const bytes =
  mode === "--build" || mode === "--verify"
    ? await readFile(compiledPath)
    : await readFile(assetPath);
const actual = await metadata(bytes);

if (mode === "--build") {
  await writeFile(assetPath, bytes);
  await writeFile(lockPath, `${JSON.stringify(actual, undefined, 2)}\n`);
} else {
  const expected = JSON.parse(await readFile(lockPath, "utf8"));
  if (
    actual.sourceSha256 !== expected.sourceSha256 ||
    actual.wasmSha256 !== expected.wasmSha256 ||
    actual.wasmBytes !== expected.wasmBytes
  ) {
    if (mode === "--verify" && process.env.CI) {
      const committed = await readFile(assetPath);
      const xor = Buffer.alloc(Math.max(bytes.length, committed.length));
      for (let index = 0; index < xor.length; index++) {
        xor[index] = (bytes[index] ?? 0) ^ (committed[index] ?? 0);
      }
      const encoded = gzipSync(xor, { level: 9 }).toString("base64");
      const chunks = encoded.match(/.{1,30000}/g) ?? [];
      console.error(`POSEIDON_WASM_ACTUAL=${JSON.stringify(actual)}`);
      console.error(`POSEIDON_WASM_XOR_BYTES=${xor.length}`);
      console.error(`POSEIDON_WASM_XOR_CHUNK_COUNT=${chunks.length}`);
      for (const [index, chunk] of chunks.entries()) {
        console.error(`POSEIDON_WASM_XOR_CHUNK_${index}=${chunk}`);
      }
    }
    throw new Error(
      mode === "--verify"
        ? "the compiled Poseidon WASM differs from the committed asset"
        : "Poseidon WASM inputs or bytes changed; run npm run build:wasm",
    );
  }
}

console.log(`${actual.wasmBytes} bytes, sha256 ${actual.wasmSha256}`);
