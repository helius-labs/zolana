use proc_macro2::TokenStream;
use quote::quote;
use syn::{Data, DeriveInput, Fields, Result};

pub(crate) fn expand(input: &DeriveInput) -> Result<TokenStream> {
    let Data::Enum(data) = &input.data else {
        return Err(syn::Error::new_spanned(input, "ErrorName requires an enum"));
    };
    let ident = &input.ident;
    let enum_name = ident.to_string();
    let prefix = enum_name.strip_suffix("Kind").unwrap_or(&enum_name);
    let mut arms = Vec::new();
    for variant in &data.variants {
        let name = &variant.ident;
        let cfg = variant
            .attrs
            .iter()
            .filter(|attr| attr.path().is_ident("cfg"));
        let mut transparent = false;
        for attr in variant
            .attrs
            .iter()
            .filter(|attr| attr.path().is_ident("error_name"))
        {
            attr.parse_nested_meta(|meta| {
                if meta.path.is_ident("transparent") {
                    transparent = true;
                    Ok(())
                } else {
                    Err(meta.error("expected transparent"))
                }
            })?;
        }
        let arm = if transparent {
            if !matches!(&variant.fields, Fields::Unnamed(fields) if fields.unnamed.len() == 1) {
                return Err(syn::Error::new_spanned(
                    variant,
                    "transparent requires one tuple field",
                ));
            }
            quote!(Self::#name(error) => error.name())
        } else {
            let pattern = match &variant.fields {
                Fields::Unit => quote!(Self::#name),
                Fields::Unnamed(_) => quote!(Self::#name(..)),
                Fields::Named(_) => quote!(Self::#name { .. }),
            };
            let label = format!("{prefix}.{name}");
            quote!(#pattern => #label)
        };
        arms.push(quote!(#(#cfg)* #arm,));
    }
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();
    Ok(quote! {
        impl #impl_generics #ident #ty_generics #where_clause {
            fn name(&self) -> &'static str {
                match self { #(#arms)* }
            }
        }
    })
}
