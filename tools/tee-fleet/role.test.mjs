import assert from "node:assert/strict";
import test from "node:test";
import { retryInitializationRead } from "./role.mjs";

test("temporary-role identity and permission initialization retries a transient read only once", async () => {
  for (const awsCode of ["ClientTimeout", "InvalidClientTokenId"]) {
    let calls = 0;
    const recorded = [];
    const transient = Object.assign(new Error("test read failure"), { awsCode });
    const value = await retryInitializationRead(() => {
      if (++calls === 1) throw transient;
      return "verified";
    }, async (error) => recorded.push(error.awsCode));
    assert.equal(value, "verified");
    assert.equal(calls, 2);
    assert.deepEqual(recorded, [awsCode]);
  }
  let calls = 0;
  const failure = Object.assign(new Error("persistent failure"), { awsCode: "InvalidClientTokenId" });
  await assert.rejects(retryInitializationRead(() => {
    calls++;
    throw failure;
  }, async () => {}), (error) => error === failure);
  assert.equal(calls, 2);
});

test("initialization never retries access denials or other unexpected failures", async () => {
  for (const awsCode of ["AccessDenied", "MalformedPolicyDocument", "UnknownAwsFailure"]) {
    let calls = 0;
    const failure = Object.assign(new Error("permanent failure"), { awsCode });
    await assert.rejects(retryInitializationRead(() => {
      calls++;
      throw failure;
    }, async () => assert.fail("must not retry")), (error) => error === failure);
    assert.equal(calls, 1);
  }
});
