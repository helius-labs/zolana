use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse2, parse_quote, Attribute, Error, ImplItem, Item, ItemImpl, Result};

use crate::paths;

mod lint;
mod rename;

pub(crate) fn expand(attr: TokenStream, item: TokenStream) -> TokenStream {
    expand_item(attr, item).unwrap_or_else(|error| error.to_compile_error())
}

fn expand_item(attr: TokenStream, item: TokenStream) -> Result<TokenStream> {
    if !attr.is_empty() {
        return Err(Error::new_spanned(attr, "`#[circuit]` takes no arguments"));
    }
    let (item, violations) = match parse2::<Item>(item)? {
        Item::Impl(item_impl) => {
            let violations = lint::check_impl(&item_impl);
            (Item::Impl(prepare_impl(item_impl)?), violations)
        }
        Item::Fn(mut item_fn) => {
            let violations = lint::check_fn(&item_fn);
            add_lint_levels(&mut item_fn.attrs);
            (Item::Fn(item_fn), violations)
        }
        other => {
            return Err(Error::new_spanned(
                other,
                "`#[circuit]` goes on an impl block or a function",
            ))
        }
    };
    let errors = violations.iter().map(Error::to_compile_error);
    Ok(quote!(#item #(#errors)*))
}

fn prepare_impl(mut item: ItemImpl) -> Result<ItemImpl> {
    rename::to_twin(&mut item.self_ty)?;
    if is_circuit_impl(&item) && !has_marker(&item) {
        let marker = paths::circuit_marker();
        item.items
            .insert(0, parse_quote!(const MARKER: #marker = #marker;));
    }
    add_lint_levels(&mut item.attrs);
    Ok(item)
}

fn is_circuit_impl(item: &ItemImpl) -> bool {
    item.trait_
        .as_ref()
        .and_then(|(_, path, _)| path.segments.last())
        .is_some_and(|segment| segment.ident == "Circuit")
}

fn has_marker(item: &ItemImpl) -> bool {
    item.items
        .iter()
        .any(|item| matches!(item, ImplItem::Const(constant) if constant.ident == "MARKER"))
}

fn add_lint_levels(attrs: &mut Vec<Attribute>) {
    attrs.push(parse_quote!(#[deny(unused_must_use, unused_variables, unused_assignments)]));
    attrs.push(parse_quote!(#[forbid(unsafe_code)]));
}
