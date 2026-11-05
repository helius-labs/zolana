use spr_gnark_ffi_prover::setup_cli::append_proving_key_sha256;

/// The appended constant must match the committed modules' `u8`-suffixed
/// form, or a regeneration rewrites every verifying-key file.
#[test]
fn appends_the_file_hash_in_the_committed_format() {
    let dir = std::env::temp_dir().join(format!("spr-pk-sha256-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let proving_key = dir.join("pk.bin");
    let rust_vk = dir.join("vk.rs");
    std::fs::write(&proving_key, b"abc").unwrap();
    std::fs::write(&rust_vk, "// generated\n").unwrap();

    append_proving_key_sha256(&rust_vk, &proving_key).unwrap();

    // SHA-256("abc")
    let expected = "// generated\n\n\
        /// SHA-256 of the proving key file, pinned by zolana's clients.\n\
        #[rustfmt::skip]\n\
        pub const VERIFYINGKEY_PROVING_KEY_SHA256: [u8; 32] = [186u8, 120u8, 22u8, 191u8, 143u8, 1u8, 207u8, 234u8, 65u8, 65u8, 64u8, 222u8, 93u8, 174u8, 34u8, 35u8, 176u8, 3u8, 97u8, 163u8, 150u8, 23u8, 122u8, 156u8, 180u8, 16u8, 255u8, 97u8, 242u8, 0u8, 21u8, 173u8];\n";
    assert_eq!(std::fs::read_to_string(&rust_vk).unwrap(), expected);
    std::fs::remove_dir_all(&dir).unwrap();
}
