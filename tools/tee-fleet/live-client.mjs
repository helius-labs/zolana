import { createZolanaClient } from "@heliuslabs/zolana";
import { tufTeePolicy } from "@heliuslabs/zolana/tee/node";
import { bytesToHex } from "@noble/hashes/utils.js";
import { readBoundedBody } from "../../sdk-libs/ts/dist/services/transport.js";
import {
  transferFixtureInputs,
  transferFixturePublicInputHash,
} from "../../sdk-libs/ts/test/helpers/transfer-fixture.ts";

export async function client({ policy, proverUrl }) {
  const source = tufTeePolicy(policy);
  const observed = { encrypted: 0, attestations: 0 };
  let evidence;
  const fetch = async (input, init) => {
    const url = new URL(input instanceof Request ? input.url : String(input));
    if (url.origin !== new URL(proverUrl).origin)
      throw new Error("unexpected fixture client endpoint");
    const attesting = url.pathname.endsWith("/tee/v1/attestation");
    if (attesting) observed.attestations++;
    else {
      const headers = new Headers(init?.headers);
      if (
        headers.get("Zolana-Tee") !== "v1" ||
        !/^[0-9a-f]{64}$/u.test(headers.get("Zolana-Tee-Key-Id") ?? "")
      )
        throw new Error("unencrypted fixture request");
      observed.encrypted++;
    }
    const response = await globalThis.fetch(input, init);
    if (!attesting || !response.ok) return response;
    const bytes = await readBoundedBody(response, 1 << 20);
    evidence = {
      captured_at: Math.floor(Date.now() / 1000),
      nonce: url.searchParams.get("nonce"),
      attestation: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)),
    };
    return new Response(bytes.slice(), { status: response.status, headers: response.headers });
  };
  const value = await createZolanaClient({
    solanaRpcUrl: "http://127.0.0.1:8899",
    indexerUrl: undefined,
    proverUrl,
    proverTee: source,
    fetch,
  });
  return {
    observed,
    evidence: () => evidence,
    async policy() {
      const policy = await source.resolve({ timeoutMs: 30_000 });
      return {
        revision: policy.revision,
        expiresAt: policy.expiresAt,
        deployments: policy.deployments.map((entry) => entry.id),
      };
    },
    async attest() {
      const prover = await value.attestProver({ timeoutMs: 120_000 });
      return { platform: prover.platform, key: bytesToHex(prover.hpkePublicKey) };
    },
    async prove() {
      await value.checkProverProvingKeys({ timeoutMs: 120_000 });
      const proof = await value.proofService.prove(transferFixtureInputs(), { timeoutMs: 180_000 });
      return {
        a: bytesToHex(proof.a),
        b: bytesToHex(proof.b),
        c: bytesToHex(proof.c),
        publicInputHash: transferFixturePublicInputHash(),
      };
    },
  };
}
