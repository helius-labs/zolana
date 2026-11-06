use super::{classify, client_name, expand, Kind};
use proc_macro2::TokenStream;
use quote::{quote, ToTokens};
use syn::{DeriveInput, Type};

/// The items inside the generated `__zk_client!` gate, pretty-printed.
fn gated_items(output: TokenStream) -> String {
    let file: syn::File = syn::parse2(output).unwrap();
    let [syn::Item::Macro(gate)] = file.items.as_slice() else {
        panic!("one client feature gate");
    };
    assert!(gate
        .mac
        .path
        .segments
        .last()
        .is_some_and(|segment| segment.ident == "__zk_client"));
    prettyplease::unparse(&syn::parse2(gate.mac.tokens.clone()).unwrap())
}

fn pretty(tokens: TokenStream) -> String {
    prettyplease::unparse(&syn::parse2(tokens).unwrap())
}

#[test]
fn every_kind_of_field_expands_to_its_client_type_and_conversion() {
    let input = syn::parse_quote! {
        pub struct Private {
            context: TxContext,
            tokens: ArrayVec<Utxo, CAPACITY>,
            deposit: Utxo,
            account: ShieldedAddress,
            mint: Asset,
            scalar: Field,
            creator: UtxoOwner,
            amounts: ArrayVec<u64, 2>,
            bytes: [u8; 32],
            terms: crate::Terms,
        }
    };
    let expected = quote! {
        pub use __zk_inputs_private::PrivateClient;
        #[doc(hidden)]
        mod __zk_inputs_private {
            #[allow(unused_imports)]
            use super::*;
            #[cfg(feature = "wasm")]
            use ::spr_program::__private::{serde, tsify, wasm_bindgen};
            #[cfg_attr(feature = "wasm", derive(serde::Deserialize, tsify::Tsify),
                serde(crate = "::spr_program::__private::serde", rename_all = "camelCase", deny_unknown_fields),
                tsify(large_number_types_as_bigints))]
        pub struct PrivateClient {
            #[cfg_attr(feature = "wasm", tsify(type = "TransactionOptions"))]
            pub context: ::spr_program::TransactionOptions,
            #[cfg_attr(feature = "wasm", tsify(type = "WalletUtxo[]"))]
            pub tokens: ::spr_program::__private::Vec<::spr_program::__private::WalletUtxo>,
            #[cfg_attr(feature = "wasm", tsify(type = "WalletUtxo"))]
            pub deposit: ::spr_program::__private::WalletUtxo,
            #[cfg_attr(feature = "wasm", tsify(type = "Uint8Array"))]
            pub account: ::spr_program::__private::NativeShieldedAddress,
            #[cfg_attr(feature = "wasm", tsify(type = "Mint"))]
            pub mint: ::spr_program::__private::Mint,
            #[cfg_attr(feature = "wasm", tsify(type = "string"))]
            #[cfg_attr(feature = "wasm", serde(deserialize_with = "::spr_program::wasm::deserialize_field"))]
            pub scalar: ::spr_program::Field,
            pub creator: ::spr_program::UtxoOwner,
            pub amounts: ::spr_program::__private::Vec<u64>,
            pub bytes: [u8; 32],
            #[cfg_attr(feature = "wasm", tsify(type = "TermsClient"))]
            #[cfg_attr(feature = "wasm", serde(deserialize_with = "::spr_program::wasm::deserialize_client_input"))]
            pub terms: <crate::Terms as ::spr_program::ClientInputs>::Client,
        }
        }
        impl ::spr_program::ClientInputs for Private {
            type Client = PrivateClient;
            fn from_client(client: Self::Client, records: &mut ::spr_program::InputRecords)
                -> Result<Self, ::spr_program::ClientError>
            {
                let _ = (&client, &records);
                Ok(Self {
                    context: client.context.into_context()?,
                    tokens: records.utxos::<CAPACITY>(&client.tokens)?,
                    deposit: records.utxo(&client.deposit)?,
                    account: records.address(&client.account)?,
                    mint: records.asset(client.mint)?,
                    scalar: client.scalar,
                    creator: client.creator,
                    amounts: ::spr_program::InputRecords::bounded::<_, 2>(client.amounts)?,
                    bytes: client.bytes,
                    terms: <crate::Terms as ::spr_program::ClientInputs>::from_client(client.terms, records)?,
                })
            }
        }
    };
    assert_eq!(gated_items(expand(&input).unwrap()), pretty(expected),);
}

#[test]
fn identity_inputs_convert_back_and_empty_inputs_default() {
    let input = syn::parse_quote! { pub struct Public { identity: Field, amount: u64 } };
    let expected = quote! {
        pub use __zk_inputs_public::PublicClient;
        #[doc(hidden)]
        mod __zk_inputs_public {
            #[allow(unused_imports)]
            use super::*;
            #[cfg(feature = "wasm")]
            use ::spr_program::__private::{serde, tsify, wasm_bindgen};
            #[cfg_attr(feature = "wasm", derive(serde::Deserialize, tsify::Tsify),
                serde(crate = "::spr_program::__private::serde", rename_all = "camelCase", deny_unknown_fields),
                tsify(large_number_types_as_bigints))]
        pub struct PublicClient {
            #[cfg_attr(feature = "wasm", tsify(type = "string"))]
            #[cfg_attr(feature = "wasm", serde(deserialize_with = "::spr_program::wasm::deserialize_field"))]
            pub identity: ::spr_program::Field,
            pub amount: u64,
        }
        }
        impl ::core::convert::From<Public> for PublicClient {
            fn from(native: Public) -> Self {
                let _ = &native;
                Self { identity: native.identity, amount: native.amount }
            }
        }
        impl ::spr_program::ClientInputs for Public {
            type Client = PublicClient;
            fn from_client(client: Self::Client, records: &mut ::spr_program::InputRecords)
                -> Result<Self, ::spr_program::ClientError>
            {
                let _ = (&client, &records);
                Ok(Self { identity: client.identity, amount: client.amount })
            }
        }
    };
    assert_eq!(gated_items(expand(&input).unwrap()), pretty(expected));

    let empty = gated_items(expand(&syn::parse_quote! { pub struct Public {} }).unwrap());
    assert!(empty.contains("#[derive(Default)]\n"), "{empty}");
}

fn kind(ty: &Type) -> &'static str {
    match classify(ty) {
        Ok(Kind::Context) => "context",
        Ok(Kind::Utxo) => "utxo",
        Ok(Kind::Address) => "address",
        Ok(Kind::Asset) => "asset",
        Ok(Kind::Field) => "field",
        Ok(Kind::Owner(_)) => "owner",
        Ok(Kind::Utxos { .. }) => "utxos",
        Ok(Kind::Bounded { .. }) => "bounded",
        Ok(Kind::Plain) => "plain",
        Ok(Kind::Nested(_)) => "nested",
        Err(_) => "refused",
    }
}

/// `ty` as a `macro_rules!` `$ty` substitution delivers it: in an invisible group.
fn grouped(ty: Type) -> Type {
    Type::Group(syn::TypeGroup {
        group_token: Default::default(),
        elem: Box::new(ty),
    })
}

#[test]
fn types_are_classified_and_anything_that_could_skip_a_conversion_is_refused() {
    let cases: [(Type, &str); 32] = [
        (syn::parse_quote!(TxContext), "context"),
        (syn::parse_quote!(spr_program::TxContext), "context"),
        (syn::parse_quote!(Utxo), "utxo"),
        (syn::parse_quote!((Utxo)), "utxo"),
        (grouped(syn::parse_quote!(Utxo)), "utxo"),
        (syn::parse_quote!(ShieldedAddress), "address"),
        (syn::parse_quote!(Asset), "asset"),
        (syn::parse_quote!(Field), "field"),
        (syn::parse_quote!(UtxoOwner), "owner"),
        (syn::parse_quote!(spr_program::SigningPubkey), "owner"),
        (syn::parse_quote!(ArrayVec<Utxo, N>), "utxos"),
        (syn::parse_quote!(ArrayVec<(Utxo), 2>), "utxos"),
        (syn::parse_quote!(ArrayVec<[u8; 32], 2>), "bounded"),
        (syn::parse_quote!(u64), "plain"),
        (syn::parse_quote!([[u8; 32]; 2]), "plain"),
        (syn::parse_quote!((u64, bool)), "plain"),
        (syn::parse_quote!(crate::Terms), "nested"),
        // A collection or wrapper would pass its items through unconverted.
        (syn::parse_quote!([Utxo; 2]), "refused"),
        (syn::parse_quote!([[Utxo; 2]; 2]), "refused"),
        (syn::parse_quote!((Utxo, u64)), "refused"),
        (syn::parse_quote!([Field; 2]), "refused"),
        (syn::parse_quote!([UtxoOwner; 2]), "refused"),
        (syn::parse_quote!([Terms; 2]), "refused"),
        (syn::parse_quote!(ArrayVec<Field, 2>), "refused"),
        (syn::parse_quote!(ArrayVec<Terms, 2>), "refused"),
        (syn::parse_quote!(Option<Utxo>), "refused"),
        (syn::parse_quote!(Wrapper<u64>), "refused"),
        (syn::parse_quote!(ArrayVec<Utxo>), "refused"),
        (syn::parse_quote!(ArrayVec), "refused"),
        (
            Type::Path(syn::TypePath {
                qself: None,
                path: syn::PathSegment {
                    ident: syn::parse_quote!(Callback),
                    arguments: syn::PathArguments::Parenthesized(syn::parse_quote!((u8))),
                }
                .into(),
            }),
            "refused",
        ),
        (syn::parse_quote!(<T as Trait>::Utxo), "refused"),
        (syn::parse_quote!(&'static str), "refused"),
    ];
    for (ty, expected) in cases {
        assert_eq!(kind(&ty), expected, "{}", ty.to_token_stream());
    }
}

#[test]
fn nested_client_names_refuse_generic_arguments() {
    assert_eq!(
        client_name(&syn::parse_quote!(crate::Terms)).unwrap(),
        "TermsClient"
    );
    assert!(client_name(&syn::parse_quote!(Wrapper<A>)).is_err());
}

#[test]
fn every_invalid_field_is_reported_at_once() {
    let input: DeriveInput = syn::parse_quote! {
        struct Bad {
            first: [Utxo; 2],
            fine: u64,
            #[client(nested)]
            second: u64,
            third: Option<Utxo>,
        }
    };
    let Err(errors) = expand(&input) else {
        panic!("invalid fields must be refused");
    };
    let messages = errors
        .into_iter()
        .map(|error| error.to_string())
        .collect::<Vec<_>>();
    let [first, second, third] = messages.as_slice() else {
        panic!("one error per invalid field: {messages:?}");
    };
    assert!(
        first.contains("ArrayVec<Utxo, N> is the one collection"),
        "{first}"
    );
    assert!(second.contains("remove the client attribute"), "{second}");
    assert!(third.contains("unsupported client input type"), "{third}");
}
