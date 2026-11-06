use super::{program, public, state};
use crate::syntax::one_module_down;

fn twelve_fields(name: &str) -> syn::DeriveInput {
    let ident = syn::Ident::new(name, proc_macro2::Span::call_site());
    let fields = (b'a'..=b'l').map(|letter| {
        syn::Ident::new(
            &char::from(letter).to_string(),
            proc_macro2::Span::call_site(),
        )
    });
    syn::parse_quote! { struct #ident { #(#fields: u64,)* } }
}

#[test]
fn public_inputs_and_states_fit_one_poseidon_hash() {
    assert_eq!(
        (
            public(&twelve_fields("TooManyPublicInputs"))
                .unwrap_err()
                .to_string(),
            state(&twelve_fields("TooManyStateFields"))
                .unwrap_err()
                .to_string(),
        ),
        (
            "public fields and the transaction commitment fit in twelve Poseidon inputs".into(),
            "state fields and the discriminator fit in twelve Poseidon inputs".into(),
        )
    );
}

#[test]
fn a_program_has_exactly_private_and_public_inputs() {
    let inputs: [syn::DeriveInput; 3] = [
        syn::parse_quote! { struct Program { private: PrivateInputs } },
        syn::parse_quote! { struct Program { private: PrivateInputs, public: PublicInputs, extra: u64 } },
        syn::parse_quote! { struct Program { private: PrivateInputs, other: PublicInputs } },
    ];
    for input in inputs {
        assert_eq!(
            program(&input).unwrap_err().to_string(),
            "a program has exactly private and public inputs"
        );
    }
}

#[test]
fn programs_states_and_public_inputs_are_named_field_structs() {
    let tuple: syn::DeriveInput = syn::parse_quote! { struct Amount(u64); };
    let choice: syn::DeriveInput = syn::parse_quote! { enum Choice { A } };
    assert_eq!(
        [
            public(&tuple).unwrap_err().to_string(),
            state(&choice).unwrap_err().to_string(),
        ],
        [
            "program inputs and states use named fields",
            "expected a struct",
        ]
    );
}

#[test]
fn client_paths_are_rejected() {
    let input = syn::parse_quote! {
        #[zk_program(client = "crate::First", client = "crate::Second")]
        struct Program { private: PrivateInputs, public: PublicInputs }
    };
    assert_eq!(
        program(&input).unwrap_err().to_string(),
        "client conversions are derived from the input structs"
    );
}

#[test]
fn export_attributes_require_a_rust_type_path() {
    let input = syn::parse_quote! {
        #[zk_program(path = "crate::Request; arbitrary()")]
        struct Program { private: PrivateInputs, public: PublicInputs }
    };
    assert!(program(&input).is_err());
}

#[test]
fn generic_states_do_not_export_unbound_wasm_functions() {
    let input = syn::parse_quote! {
        struct GenericState<const N: usize> { bytes: [u8; N] }
    };
    let expanded: syn::File = syn::parse2(state(&input).unwrap()).unwrap();
    assert!(!expanded.items.iter().any(|item| matches!(item,
        syn::Item::Macro(item) if item.mac.path.segments.last().is_some_and(|segment| segment.ident == "__zk_wasm"))));
}

#[test]
fn field_types_are_rewritten_for_a_module_one_level_down() {
    use quote::ToTokens;
    let owner: syn::Ident = syn::parse_quote!(State);
    let cases: [(syn::Type, syn::Type); 7] = [
        (
            syn::parse_quote!(super::Amount),
            syn::parse_quote!(super::super::Amount),
        ),
        (
            syn::parse_quote!(self::Amount),
            syn::parse_quote!(super::Amount),
        ),
        (syn::parse_quote!(Self), syn::parse_quote!(super::State)),
        (
            syn::parse_quote!(Option<[super::Amount; self::N]>),
            syn::parse_quote!(Option<[super::super::Amount; super::N]>),
        ),
        (
            syn::parse_quote!(<super::Terms as ::spr_program::ClientInputs>::Client),
            syn::parse_quote!(<super::super::Terms as ::spr_program::ClientInputs>::Client),
        ),
        (
            syn::parse_quote!(crate::Amount),
            syn::parse_quote!(crate::Amount),
        ),
        (
            syn::parse_quote!(::other::Amount),
            syn::parse_quote!(::other::Amount),
        ),
    ];
    for (written, expected) in cases {
        assert_eq!(
            one_module_down(&written, &owner)
                .to_token_stream()
                .to_string(),
            expected.to_token_stream().to_string(),
            "{}",
            written.to_token_stream()
        );
    }
}
