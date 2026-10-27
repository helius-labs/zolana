import init, * as xark from "/xark/dist/web/xark_wasm.js";
import { createPool, parallelSupported } from "/xark/js/pool.mjs";
import { fetchBytes, failure } from "./util.js";
const ready = (async () => {
await init();
const requested = Number(new URL(self.location.href).searchParams.get("threads") || Math.max(1, navigator.hardwareConcurrency - 2));
if (parallelSupported() && requested > 1) {
  try { pool = await Promise.race([createPool({ threads: requested }), new Promise((_, reject) => setTimeout(() => reject(new Error("pool initialization timed out")), 20000))]); }
  catch { pool = undefined; }
}
})();
let pool;
let loaded;
const artifacts = new Map();
async function data(program) {
  if (!artifacts.has(program)) artifacts.set(program, Promise.all(["circuit.xbc", "pk.bin", "vk.bin"].map(name => fetchBytes(`/keys/${program}/${name}`))).then(async ([circuit, key, vk]) => ({ circuit, key, vk, sources: await (await fetch(`/keys/${program}/sources.json`)).text() })));
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
const api = {
  info: () => ({ crossOriginIsolated: self.crossOriginIsolated, threads: pool?.threads ?? 1 }),
  async prove(program, format, _url, inputs) { await preload(program, format); entropy(); return xark.proveStreamingPreloaded(inputs, options(format)); },
  async verify(program, proof) { return xark.verify((await data(program)).vk, new Uint8Array(proof.proof), new Uint8Array(proof.publicInputs)); },
  async timeKeyLoad(program, format) { const value = await data(program); loaded = undefined; const start = performance.now(); xark.preloadStreaming(value.circuit, value.key, { residentKey: format === "resident", sources: value.sources }); loaded = `${program}:${format}`; return performance.now() - start; },
  async timeProof(program, format, url, inputs) { await preload(program, format); entropy(); const start = performance.now(); xark.proveStreamingPreloaded(inputs, options(format)); return performance.now() - start; },
  async mutateKey(program, inputs) { const value = await data(program); const key = value.key.slice(); key[key.length - 1] ^= 1;
    const digest = bytes => crypto.subtle.digest("SHA-256", bytes).then(value => Array.from(new Uint8Array(value), b => b.toString(16).padStart(2, "0")).join(""));
    const expected = (await (await fetch(`/fixtures/${program}.json`)).json()).hashes["pk.bin"];
    if (await digest(key) !== expected) throw Object.assign(new Error("pk.bin checksum mismatch"), { name: "KeyChecksumMismatch" });
    return xark.proveStreaming(value.circuit, key, inputs, options("streaming")); },
  async randomness(program, inputs, mode) {
    await preload(program, "streaming");
    if (mode === "seed") return xark.proveStreamingPreloaded(inputs, { seed: 5 });
    const original = crypto.getRandomValues;
    try {
      Object.defineProperty(crypto, "getRandomValues", { configurable: true, value: mode === "zero" ? array => { array.fill(0); return array; } : undefined });
      entropy();
      return xark.proveStreamingPreloaded(inputs, {});
    } finally { Object.defineProperty(crypto, "getRandomValues", { configurable: true, value: original }); }
  },
};
self.onmessage = async ({ data: request }) => { try { await ready; self.postMessage({ id: request.id, result: await api[request.method](...request.args) }); } catch (error) { self.postMessage({ id: request.id, ...failure(error) }); } };
