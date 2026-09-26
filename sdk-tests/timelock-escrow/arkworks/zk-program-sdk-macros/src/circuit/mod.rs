use proc_macro2::TokenStream;
use quote::ToTokens;
use syn::{parse2, parse_quote, Attribute, Error, ImplItem, Item, ItemImpl, ItemMod, Result};

use crate::paths;

mod rename;

pub(crate) fn expand(attr: TokenStream, item: TokenStream) -> TokenStream {
    expand_item(attr, item).unwrap_or_else(|error| error.to_compile_error())
}

fn expand_item(attr: TokenStream, item: TokenStream) -> Result<TokenStream> {
    if !attr.is_empty() {
        return Err(Error::new_spanned(attr, "`#[circuit]` takes no arguments"));
    }
    let item = match parse2::<Item>(item)? {
        Item::Impl(mut item_impl) => {
            prepare_impl(&mut item_impl)?;
            add_lint_levels(&mut item_impl.attrs);
            Item::Impl(item_impl)
        }
        Item::Fn(mut item_fn) => {
            add_lint_levels(&mut item_fn.attrs);
            Item::Fn(item_fn)
        }
        Item::Mod(mut item_mod) => {
            prepare_mod(&mut item_mod)?;
            add_lint_levels(&mut item_mod.attrs);
            Item::Mod(item_mod)
        }
        other => {
            return Err(Error::new_spanned(
                other,
                "`#[circuit]` goes on an impl block, a function or an inline module",
            ))
        }
    };
    Ok(item.into_token_stream())
}

fn prepare_impl(item: &mut ItemImpl) -> Result<()> {
    rename::to_twin(&mut item.self_ty)?;
    if is_circuit_impl(item) && !has_marker(item) {
        let marker = paths::circuit_marker();
        item.items
            .insert(0, parse_quote!(const MARKER: #marker = #marker;));
    }
    Ok(())
}

fn prepare_mod(item: &mut ItemMod) -> Result<()> {
    let Some((_, items)) = item.content.as_mut() else {
        return Err(Error::new_spanned(
            &*item,
            "`#[circuit]` goes on an inline module: `mod name { .. }`",
        ));
    };
    let mut errors = items
        .iter_mut()
        .filter_map(|item| prepare_module_item(item).err());
    match errors.next() {
        None => Ok(()),
        Some(mut first) => {
            errors.for_each(|error| first.combine(error));
            Err(first)
        }
    }
}

fn prepare_module_item(item: &mut Item) -> Result<()> {
    if let Some(attr) = item_attrs(item).and_then(circuit_attribute) {
        return Err(Error::new_spanned(
            attr,
            "this item is inside a `#[circuit]` module, which already applies the attribute",
        ));
    }
    match item {
        Item::Impl(item_impl) => prepare_impl(item_impl),
        Item::Mod(item_mod) => prepare_mod(item_mod),
        _ => Ok(()),
    }
}

fn item_attrs(item: &Item) -> Option<&[Attribute]> {
    match item {
        Item::Const(item) => Some(&item.attrs),
        Item::Enum(item) => Some(&item.attrs),
        Item::ExternCrate(item) => Some(&item.attrs),
        Item::Fn(item) => Some(&item.attrs),
        Item::ForeignMod(item) => Some(&item.attrs),
        Item::Impl(item) => Some(&item.attrs),
        Item::Macro(item) => Some(&item.attrs),
        Item::Mod(item) => Some(&item.attrs),
        Item::Static(item) => Some(&item.attrs),
        Item::Struct(item) => Some(&item.attrs),
        Item::Trait(item) => Some(&item.attrs),
        Item::TraitAlias(item) => Some(&item.attrs),
        Item::Type(item) => Some(&item.attrs),
        Item::Union(item) => Some(&item.attrs),
        Item::Use(item) => Some(&item.attrs),
        _ => None,
    }
}

fn circuit_attribute(attrs: &[Attribute]) -> Option<&Attribute> {
    attrs.iter().find(|attr| {
        attr.path()
            .segments
            .last()
            .is_some_and(|segment| segment.ident == "circuit")
    })
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
    attrs.push(parse_quote!(#[deny(clippy::let_underscore_must_use, clippy::disallowed_types)]));
}
