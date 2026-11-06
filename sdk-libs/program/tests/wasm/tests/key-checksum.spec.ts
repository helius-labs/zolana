import { test, expect } from "./harness";
import { fixture } from "./fixtures";
test("a changed proving key is refused before parsing", async ({ harness }) => {
  const data = fixture("escrow");
  const result = await harness.page.evaluate(async data => {
    const input = (await window.zkProgram.transaction("escrow", data.inputs, data.sender, data.payer)).transaction.proofInputs;
    return window.zkProgram.attempt("mutateKey", "escrow", input);
  }, data);
  expect(result.error?.name).toBe("KeyChecksumMismatch");
});

test("application build pins match the complete proving keys", async ({ harness }) => {
  const checked = await harness.page.evaluate(async () => {
    const pins = await (await fetch("/pkg/proving-keys.json")).json();
    return Promise.all(["escrow", "withdraw"].map(async program => {
      const key = await (await fetch(`/keys/${program}/pk.bin`)).arrayBuffer();
      const actual = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", key)));
      return { expected: pins[program].provingKeySha256, actual, setupFlag: typeof pins[program].insecureTestSetup };
    }));
  });
  for (const { expected, actual, setupFlag } of checked) {
    expect(expected).toEqual(actual);
    expect(setupFlag).toBe("boolean");
  }
});

test("the reusable checksum export rejects missing and malformed pins", async ({ harness }) => {
  const results = await harness.page.evaluate(async () => {
    const wasm = await import("/pkg/wasm_test_program.js");
    const key = new Uint8Array(await (await fetch("/keys/escrow/pk.bin")).arrayBuffer());
    return [undefined, new Uint8Array(), new Uint8Array(31), new Uint8Array(33)].map(expected => {
      try { wasm.checkProvingKey(key, expected); return "accepted"; }
      catch (error) { return (error as Error).name; }
    });
  });
  expect(results).toEqual(Array(4).fill("InvalidProvingKeyHash"));
});

for (const [name, method, args] of [
  ["streaming preload", "prove", ["escrow", "streaming", "", {}]],
  ["resident preload", "prove", ["escrow", "resident", "", {}]],
  ["high-level client", "proveWithClient", ["escrow", {}]],
  ["timed key loading", "timeKeyLoad", ["escrow", "resident", ""]],
] as const) {
  test(`${name} checks a same-length key substitution before loading`, async ({ browser }) => {
    const page = await browser.newPage();
    try {
      await page.route("**/keys/escrow/pk.bin", async route => {
        const response = await route.fetch();
        const bytes = Buffer.from(await response.body());
        bytes[bytes.length - 1] ^= 1;
        await route.fulfill({ response, body: bytes });
      });
      await page.goto("/?threads=2");
      await page.waitForFunction(() => "zkProgram" in window);
      const result = await page.evaluate(({ method, args }) => window.zkProgram.attempt(method, ...args), { method, args });
      expect(result.error?.name).toBe("KeyChecksumMismatch");
    } finally { await page.close(); }
  });
}

for (const invalid of ["missing", "short", "out-of-range"] as const) {
  test(`the loader rejects a ${invalid} build pin`, async ({ browser }) => {
    const page = await browser.newPage();
    try {
      await page.route("**/pkg/proving-keys.json", async route => {
        const response = await route.fetch();
        const pins = await response.json();
        if (invalid === "missing") delete pins.escrow;
        else pins.escrow.provingKeySha256 = invalid === "short" ? Array(31).fill(0) : Array(32).fill(256);
        await route.fulfill({ response, json: pins });
      });
      await page.goto("/?threads=2");
      await page.waitForFunction(() => "zkProgram" in window);
      const result = await page.evaluate(() => window.zkProgram.attempt("timeKeyLoad", "escrow", "streaming", ""));
      expect(result.error?.name).toBe("InvalidProvingKeyHash");
    } finally { await page.close(); }
  });
}
