import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { build } from "esbuild";
const root = new URL("../../", import.meta.url);
const dist = new URL("sdk-libs/ts/dist/", root);

export async function sdkBundle(authority, platform, outfile) {
  await build({
    stdin: {
      contents: `
      export { tufTeePolicy } from ${JSON.stringify(new URL("client/prover/tee/tuf-browser.js", dist).pathname)};
      export { ZolanaClient } from ${JSON.stringify(new URL("client/index.js", dist).pathname)};
      export { ProverClient } from ${JSON.stringify(new URL("client/prover/client.js", dist).pathname)};
      export { teeFleetPolicyFromJson } from ${JSON.stringify(new URL("client/prover/tee/fleet.js", dist).pathname)};
      export { TeeSession } from ${JSON.stringify(new URL("client/prover/tee/session.js", dist).pathname)};
      export { composeSignal } from ${JSON.stringify(new URL("client/internal.js", dist).pathname)};
    `,
      resolveDir: root.pathname,
    },
    bundle: true,
    platform,
    format: "esm",
    outfile,
    ...(platform === "node"
      ? {
          banner: {
            js: 'import { createRequire } from "node:module"; const require = createRequire(import.meta.url);',
          },
        }
      : {}),
    plugins: [
      {
        name: "test-only-nitro-root",
        setup(context) {
          context.onLoad({ filter: /\/tee\/nitro\.js$/ }, async ({ path }) => {
            const source = await readFile(path, "utf8");
            const needle = "anchors: Object.freeze([AWS_NITRO_ROOT_G1])";
            assert.equal(
              source.split(needle).length,
              2,
              "test anchor patch must match exactly once",
            );
            return {
              contents: source.replace(
                needle,
                `anchors: Object.freeze([new Uint8Array(${JSON.stringify([...authority.root])})])`,
              ),
              loader: "js",
            };
          });
        },
      },
    ],
  });
}
