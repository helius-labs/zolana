/** Mirrors `sdk-libs/prover-tee/src/mainnet-policy.json`, kept equal by a test. */
export const MAINNET_TEE_POLICY_FILE: Readonly<{ deployment: unknown }> = Object.freeze({
  deployment: {
    platform: "aws-nitro",
    measurements: [
      {
        pcr0: "89cde9fcf78ed0fe2e80c25554ad38b4022a3372e5f8bf4b1ab6b4b69e721699a5d022d7370bbc8854c2c4f46d630097",
        pcr1: "4b4d5b3661b3efc12920900c80e126e4ce783c522de6c02a2a5bf7af3a2b9327b86776f188e4be1c1c404a129dbda493",
        pcr2: "8265ae7a12c74695e4484aa5f085f730df8c5a4741fb2a334ef88f306f47d39ae0137a9bec2e8a495ce7c6db3841e1ee",
      },
    ],
    gpu: "optional",
    max_age_secs: 600,
    hpke_public_key: "ee8289b5afa1d2e885809a91f4b28b645807dcfd5c9457ddf6a031b3ecb45878",
  },
});
