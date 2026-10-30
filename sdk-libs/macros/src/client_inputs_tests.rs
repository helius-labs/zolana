use super::expand;
use quote::{ToTokens, quote};

#[test]
fn protocol_inputs_use_native_records_and_checked_capacity() {
    let input = syn::parse_quote! {
        pub struct Private {
            context: TxContext,
            tokens: ArrayVec<Utxo, CAPACITY>,
            account: ShieldedAddress,
            scalar: Field,
        }
    };
    let output = expand(&input).unwrap();
    let file: syn::File = syn::parse2(output.clone()).unwrap();
    assert_eq!(file.items.len(), 1);
    let source = output.to_string();
    for expression in [
        quote!(TransactionOptions),
        quote!(WalletUtxo),
        quote!(NativeShieldedAddress),
        quote!(records.utxos::<CAPACITY>),
        quote!(records.address),
        quote!(from_decimal),
    ] {
        assert!(source.contains(&expression.to_string()), "{expression}");
    }
    let syn::Item::Macro(gate) = &file.items[0] else {
        panic!("client feature gate");
    };
    let body: syn::File = syn::parse2(gate.mac.tokens.clone()).unwrap();
    let syn::Item::Struct(client) = &body.items[0] else {
        panic!("client view");
    };
    assert_eq!(
        client
            .fields
            .iter()
            .map(|field| field.ident.as_ref().unwrap().to_string())
            .collect::<Vec<_>>(),
        ["context", "tokens", "account", "scalar"]
    );
}

#[test]
fn empty_inputs_have_a_default_empty_client() {
    let input = syn::parse_quote! { pub struct Public {} };
    let output = expand(&input).unwrap().to_string();
    assert!(output.contains(&quote!(derive(Default)).to_string()));
    assert!(
        output.contains(
            &quote!(
                struct PublicClient {}
            )
            .to_string()
        )
    );
}

#[test]
fn custom_types_recurse_and_keep_strict_wasm_decoding() {
    let input = syn::parse_quote! { pub struct Private { terms: crate::Terms } };
    let output = expand(&input).unwrap().to_string();
    for expression in [
        quote!(<crate::Terms as ::spr_program::ClientInputs>::Client),
        quote!(
            <crate::Terms as ::spr_program::ClientInputs>::from_client(client.terms, records)?
        ),
        quote!(tsify(type = "TermsClient")),
        quote!(serde(
            deserialize_with = "::spr_program::wasm::deserialize_client_input"
        )),
    ] {
        assert!(output.contains(&expression.to_string()), "{expression}");
    }
}

#[test]
fn unknown_or_conflicting_conversion_modes_and_generics_are_rejected() {
    for input in [
        syn::parse_quote!(
            struct Bad {
                #[client(nested, nested)]
                field: Field,
            }
        ),
        syn::parse_quote!(
            struct Bad {
                #[client(unknown)]
                field: u64,
            }
        ),
        syn::parse_quote!(
            struct Bad<T> {
                field: T,
            }
        ),
    ] {
        assert!(expand(&input).is_err(), "{}", input.to_token_stream());
    }
}
