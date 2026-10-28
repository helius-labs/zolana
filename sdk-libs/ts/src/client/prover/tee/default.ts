/** Mirrors `sdk-libs/prover-tee/src/policy.json`, kept equal by a test. */
export const DEFAULT_TEE_POLICY_FILE: Readonly<{ deployment: unknown }> = Object.freeze({
  deployment: {
    platform: "aws-nitro",
    measurements: [
      {
        pcr0: "30a5ca7cdaa68adc9802c57c7ef590cc4ea3cee981898de55c2aa2082d7980a7ca42c3daf6a0988aff5e6daaacd949ad",
        pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
        pcr2: "f389a946e669e3bef011d91189a542619a4dc9fe8578f9af66bc54f8f9347e1cf979a50a8c1f56e7a595bd935bf29cab",
      },
    ],
    gpu: "optional",
    max_age_secs: 600,
    hpke_public_key: "cf2254cff568f3401272b0b5fc965917938498e0ae4a41391b04f6924a93e033",
  },
});
