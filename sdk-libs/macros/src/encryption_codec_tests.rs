use super::generate;

fn error(input: syn::DeriveInput) -> String {
    generate(&input).unwrap_err().to_string()
}

#[test]
fn the_default_codec_refuses_skipped_fields() {
    assert_eq!(
        error(syn::parse_quote! {
            struct SkippedState {
                #[borsh(skip)]
                value: u64,
            }
        }),
        "the default encryption codec cannot skip state fields; use #[utxo_state(custom_codec)] and reconstruct omitted values in EncryptionCodec"
    );
}

#[test]
fn a_custom_codec_may_skip_fields_and_generates_no_codec() {
    let input = syn::parse_quote! {
        #[utxo_state(custom_codec)]
        struct CompactState {
            value: u64,
            #[borsh(skip)]
            doubled: u64,
        }
    };
    assert!(generate(&input).unwrap().is_empty());
}

#[test]
fn malformed_state_options_are_refused() {
    let cases: [(syn::DeriveInput, &str); 5] = [
        (
            syn::parse_quote! { #[utxo_state(unknown)] struct S { value: u64 } },
            "expected `custom_codec`",
        ),
        (
            syn::parse_quote! { #[utxo_state(custom_codec, custom_codec)] struct S { value: u64 } },
            "`custom_codec` is given more than once",
        ),
        (
            syn::parse_quote! { #[utxo_state(custom_codec = true)] struct S { value: u64 } },
            "expected `,`",
        ),
        (
            syn::parse_quote! { struct S { #[utxo_state(custom_codec)] value: u64 } },
            "#[utxo_state(custom_codec)] belongs on the state struct",
        ),
        (
            syn::parse_quote! { #[utxo_state()] struct S { value: u64 } },
            "expected `custom_codec`",
        ),
    ];
    for (input, expected) in cases {
        assert_eq!(error(input), expected);
    }
}

#[test]
fn the_default_codec_uses_borsh_and_bounds_generic_states() {
    let input = syn::parse_quote! {
        struct GenericState<const N: usize> { values: [u64; N] }
    };
    let generated: syn::ItemImpl = syn::parse2(generate(&input).unwrap()).unwrap();
    let source = quote::ToTokens::to_token_stream(&generated).to_string();
    for expected in [
        "borsh :: to_vec",
        "BorshDeserialize > :: try_from_slice",
        "GenericState < N > : :: spr_program :: __private :: borsh :: BorshSerialize",
    ] {
        assert!(source.contains(expected), "{expected} in {source}");
    }
}
