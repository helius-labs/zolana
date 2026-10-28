use super::{program, state};

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
