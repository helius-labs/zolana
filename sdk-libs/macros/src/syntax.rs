//! Syntax helpers the derives share.

use syn::{PathSegment, Type};

/// Strips the invisible groups a `macro_rules!` `$ty` substitution adds, and
/// parentheses.
pub fn ungroup(mut ty: &Type) -> &Type {
    loop {
        ty = match ty {
            Type::Group(group) => &group.elem,
            Type::Paren(paren) => &paren.elem,
            _ => return ty,
        };
    }
}

/// The last segment of a path type that names no `<T as Trait>` projection
/// and has no generic arguments before its last segment.
pub fn last_segment(ty: &Type) -> Option<&PathSegment> {
    let Type::Path(path) = ungroup(ty) else {
        return None;
    };
    if path.qself.is_some() {
        return None;
    }
    let mut segments = path.path.segments.iter().rev();
    let last = segments.next()?;
    segments
        .all(|segment| segment.arguments.is_none())
        .then_some(last)
}

pub fn snake_case(name: &str) -> String {
    let mut out = String::new();
    for (i, c) in name.chars().enumerate() {
        if c.is_uppercase() && i != 0 {
            out.push('_');
        }
        out.extend(c.to_lowercase());
    }
    out
}

/// `ty`, written in the module of the type `owner`, as it must be written in a
/// module nested one level below: a leading `self` becomes `super`, a leading
/// `super` gains another, and `Self` names `owner`. Generated code places
/// copies of user field types in such a module.
pub fn one_module_down(ty: &Type, owner: &syn::Ident) -> Type {
    struct Deeper<'a>(&'a syn::Ident);
    impl syn::visit_mut::VisitMut for Deeper<'_> {
        fn visit_path_mut(&mut self, path: &mut syn::Path) {
            let first = path
                .segments
                .first()
                .map(|segment| segment.ident.to_string());
            if path.leading_colon.is_none() {
                let owner = self.0;
                let prefix: Option<syn::Path> = match first.as_deref() {
                    Some("self") => Some(syn::parse_quote!(super)),
                    Some("super") => Some(syn::parse_quote!(super::super)),
                    Some("Self") => Some(syn::parse_quote!(super::#owner)),
                    _ => None,
                };
                if let Some(prefix) = prefix {
                    let rest = path.segments.iter().skip(1).cloned();
                    path.segments = prefix.segments.into_iter().chain(rest).collect();
                }
            }
            syn::visit_mut::visit_path_mut(self, path);
        }
    }
    let mut ty = ty.clone();
    syn::visit_mut::VisitMut::visit_type_mut(&mut Deeper(owner), &mut ty);
    ty
}
