import init, * as xark from "./pkg/wasm_test_program.js";
import { createPool, parallelSupported } from "./pkg/xark/pool.mjs";
import { fetchBytes, failure } from "./util.js";
const ready = (async () => {
await init();
const runtimeOptions = await (await fetch("./pkg/runtime-options.json")).json();
const requested = runtimeOptions.threads
  ? Number(new URL(self.location.href).searchParams.get("threads") || Math.max(1, navigator.hardwareConcurrency - 2))
  : 1;
if (parallelSupported() && requested > 1) {
  try { pool = await Promise.race([createPool({ threads: requested, wasm: new URL("./pkg/wasm_test_program.js", import.meta.url).href }), new Promise((_, reject) => setTimeout(() => reject(new Error("pool initialization timed out")), 20000))]); }
  catch { pool = undefined; }
}
})();
let pool;
let loaded;
const artifacts = new Map();
async function data(program) {
  if (!artifacts.has(program)) artifacts.set(program, Promise.all(["circuit.xbc", "pk.bin", "vk.bin"].map(name => fetchBytes(`/keys/${program}/${name}`))).then(async ([circuit, key, vk]) => {
    const schema = await (await fetch(`/keys/${program}/schema.json`)).text();
    return { circuit, key, vk, schema,
      sources: await (await fetch(`/keys/${program}/sources.json`)).text(),
      codec: new xark.Schema(schema),
    };
  }));
  return artifacts.get(program);
}
async function preload(program, format) {
  const value = await data(program);
  const fixture = await (await fetch(`/fixtures/${program}.json`)).json();
  for (const [name, bytes] of [["circuit.xbc", value.circuit], ["pk.bin", value.key], ["vk.bin", value.vk]]) {
    const actual = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)), b => b.toString(16).padStart(2, "0")).join("");
    if (actual !== fixture.hashes[name]) throw Object.assign(new Error(`${name} checksum mismatch`), { name: "KeyChecksumMismatch" });
  }
  if (loaded !== `${program}:${format}`) { xark.preloadStreaming(value.circuit, value.key, { residentKey: format === "resident", sources: value.sources }); loaded = `${program}:${format}`; }
  return value;
}
function options(format) { return format === "resident" ? {} : { pool }; }
function entropy() { if (typeof crypto?.getRandomValues !== "function") throw Object.assign(new Error("WebCrypto randomness is unavailable"), { name: "SecureRandomUnavailable" }); }
function plainProof(bundle) {
  try {
    return { proof: bundle.proof.slice(), publicInputs: bundle.publicInputs.slice(), numPublicInputs: bundle.numPublicInputs };
  } finally { bundle.free(); }
}
const api = {
  info: () => ({ crossOriginIsolated: self.crossOriginIsolated, threads: pool?.threads ?? 1, stats: pool?.stats }),
  async prove(program, format, _url, inputs) { const value = await preload(program, format); entropy(); return plainProof(xark.proveStreamingPreloaded(value.codec.encodeInputs(JSON.stringify(inputs)), options(format))); },
  async verify(program, proof) { return xark.verify((await data(program)).vk, new Uint8Array(proof.proof), new Uint8Array(proof.publicInputs)); },
  async proveWithClient(program, inputs) {
    const { Circuit } = await import("./pkg/xark/client.mjs");
    const artifacts = await data(program);
    const circuit = new Circuit({ name: program, schema: artifacts.schema, decodePublic: value => value, client: false });
    const prover = await circuit.prover({ circuit: artifacts.circuit, provingKey: artifacts.key, sources: artifacts.sources }, { wasm: xark });
    const proof = prover.prove(inputs);
    const verifier = await circuit.verifier(artifacts.vk, { wasm: xark });
    return verifier.verify(proof);
  },
  async timeKeyLoad(program, format) { const value = await data(program); loaded = undefined; const start = performance.now(); xark.preloadStreaming(value.circuit, value.key, { residentKey: format === "resident", sources: value.sources }); loaded = `${program}:${format}`; return performance.now() - start; },
  async timeProof(program, format, url, inputs) { const value = await preload(program, format); entropy(); const encoded = value.codec.encodeInputs(JSON.stringify(inputs)); const start = performance.now(); const bundle = xark.proveStreamingPreloaded(encoded, options(format)); bundle.free(); return performance.now() - start; },
  async mutateKey(program, inputs) { const value = await data(program); const key = value.key.slice(); key[key.length - 1] ^= 1;
    const digest = bytes => crypto.subtle.digest("SHA-256", bytes).then(value => Array.from(new Uint8Array(value), b => b.toString(16).padStart(2, "0")).join(""));
    const expected = (await (await fetch(`/fixtures/${program}.json`)).json()).hashes["pk.bin"];
    if (await digest(key) !== expected) throw Object.assign(new Error("pk.bin checksum mismatch"), { name: "KeyChecksumMismatch" });
    return plainProof(xark.proveStreaming(value.circuit, key, value.codec.encodeInputs(JSON.stringify(inputs)), options("streaming"))); },
  async randomness(program, inputs, mode) {
    const value = await preload(program, "streaming");
    const encoded = value.codec.encodeInputs(JSON.stringify(inputs));
    if (mode === "seed") return plainProof(xark.proveStreamingPreloaded(encoded, { seed: 5 }));
    const original = crypto.getRandomValues;
    try {
      Object.defineProperty(crypto, "getRandomValues", { configurable: true, value: mode === "zero" ? array => { array.fill(0); return array; } : undefined });
      entropy();
      return plainProof(xark.proveStreamingPreloaded(encoded, {}));
    } finally { Object.defineProperty(crypto, "getRandomValues", { configurable: true, value: original }); }
  },
};
self.onmessage = async ({ data: request }) => { try { await ready; self.postMessage({ id: request.id, result: await api[request.method](...request.args) }); } catch (error) { self.postMessage({ id: request.id, ...failure(error) }); } };
