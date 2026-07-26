import { copyFile, mkdir } from "node:fs/promises";

const wasmSource = new URL("../src/hasher/poseidon.wasm", import.meta.url);
const wasmDirectory = new URL("../dist/hasher/", import.meta.url);
const licenseSource = new URL("../../../LICENSE", import.meta.url);
const distDirectory = new URL("../dist/", import.meta.url);

await mkdir(wasmDirectory, { recursive: true });
await Promise.all([
  copyFile(wasmSource, new URL("poseidon.wasm", wasmDirectory)),
  copyFile(licenseSource, new URL("LICENSE", distDirectory)),
]);
