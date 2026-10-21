use proc_macro2::TokenStream;
use quote::quote;
use syn::{punctuated::Punctuated, DeriveInput, Meta, Result, Token};

pub(crate) fn generate(input: &DeriveInput) -> Result<TokenStream> {
    let mut custom = false;
    for attr in input
        .attrs
        .iter()
        .filter(|a| a.path().is_ident("utxo_state"))
    {
        let mut found = false;
        attr.parse_nested_meta(|meta| {
            if !meta.path.is_ident("custom_codec") {
                return Err(meta.error("expected `custom_codec`"));
            }
            if custom {
                return Err(meta.error("`custom_codec` is given more than once"));
            }
            custom = true;
            found = true;
            Ok(())
        })?;
        if !found {
            return Err(syn::Error::new_spanned(attr, "expected `custom_codec`"));
        }
    }
    if let syn::Data::Struct(data) = &input.data {
        for field in &data.fields {
            for attr in &field.attrs {
                if attr.path().is_ident("utxo_state") {
                    return Err(syn::Error::new_spanned(
                        attr,
                        "#[utxo_state(custom_codec)] belongs on the state struct",
                    ));
                }
                if !custom && attr.path().is_ident("borsh") {
                    let options =
                        attr.parse_args_with(Punctuated::<Meta, Token![,]>::parse_terminated)?;
                    if options.iter().any(|option| option.path().is_ident("skip")) {
                        return Err(syn::Error::new_spanned(
                            attr,
                            "the default encryption codec cannot skip state fields; use #[utxo_state(custom_codec)] and reconstruct omitted values in EncryptionCodec",
                        ));
                    }
                }
            }
        }
    }
    if custom {
        return Ok(TokenStream::new());
    }

    let ident = &input.ident;
    let (_, ty_generics, _) = input.generics.split_for_impl();
    let mut generics = input.generics.clone();
    generics
        .make_where_clause()
        .predicates
        .push(syn::parse_quote!(
            #ident #ty_generics: ::zolana_program::__private::borsh::BorshSerialize
                + ::zolana_program::__private::borsh::BorshDeserialize
        ));
    let (impl_generics, _, where_clause) = generics.split_for_impl();
    Ok(quote! {
        impl #impl_generics ::zolana_program::EncryptionCodec for #ident #ty_generics #where_clause {
            fn serialize_for_encryption(&self) -> ::std::io::Result<::std::vec::Vec<u8>> {
                ::zolana_program::__private::borsh::to_vec(self)
            }

            fn deserialize_after_decryption(bytes: &[u8]) -> ::std::io::Result<Self> {
                <Self as ::zolana_program::__private::borsh::BorshDeserialize>::try_from_slice(bytes)
            }
        }
    })
}
