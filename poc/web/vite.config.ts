import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

const isolationHeaders = {
  "Cross-Origin-Opener-Policy": "same-origin",
  "Cross-Origin-Embedder-Policy": "require-corp",
};

export default defineConfig({
  plugins: [react()],
  // The SDK and the Poseidon hasher both use top-level await, so the output
  // target has to permit it. Vite 8 transforms through rolldown/oxc, which reads
  // this single target rather than the esbuild options earlier versions used.
  build: { target: "esnext" },
  worker: { format: "es" },
  server: {
    host: "127.0.0.1",
    port: 5178,
    strictPort: true,
    // Must match the /devnet/ paths deploy/nginx.conf proxies.
    proxy: {
      "/devnet/indexer": {
        target: "http://zolnet-devnet-1779374825.eu-north-1.elb.amazonaws.com",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/devnet\/indexer/u, ""),
      },
      "/devnet/prover": {
        target: "http://zolnet-devnet-1779374825.eu-north-1.elb.amazonaws.com:3001",
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/devnet\/prover/u, ""),
      },
    },
    // Required for Mopro's shared-memory Rayon arithmetic workers.
    headers: isolationHeaders,
  },
  preview: { host: "127.0.0.1", headers: isolationHeaders },
  // Proving keys are served from public/keys in local development so the browser
  // fetches them same-origin, with no CORS configuration on the key host.
  publicDir: "public",
});
