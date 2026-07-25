import { defineConfig } from "vitest/config";

/**
 * Deliberately separate from the root config, whose `include` covers
 * `sdk-libs/ts/**` and feeds `npm run check`. The oracle needs the Rust
 * toolchain and a WebAssembly build, and it is reconnaissance rather than a
 * gate, so nothing in the default pipeline runs it.
 */
export default defineConfig({
  test: {
    include: ["tools/wasm-oracle/suite/**/*.test.ts"],
    testTimeout: 600_000,
    hookTimeout: 600_000,
    pool: "forks",
  },
});
