import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  // The SDK and the Poseidon hasher both use top-level await, so the output
  // target has to permit it. Vite 8 transforms through rolldown/oxc, which reads
  // this single target rather than the esbuild options earlier versions used.
  build: { target: "esnext" },
  worker: { format: "es" },
  server: {
    headers: {
      // Not required by the Go wasm prover -- js/wasm is single-threaded and
      // needs no SharedArrayBuffer -- but set so the page stays cross-origin
      // isolated if a threaded prover is dropped in later.
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Embedder-Policy": "require-corp",
    },
  },
  // Proving keys are served from public/keys in local development so the browser
  // fetches them same-origin, with no CORS configuration on the key host.
  publicDir: "public",
});
