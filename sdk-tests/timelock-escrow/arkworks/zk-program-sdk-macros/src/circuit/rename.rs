use quote::format_ident;
use syn::{Error, Result, Type};

pub(crate) fn to_twin(self_ty: &mut Type) -> Result<()> {
    let Type::Path(type_path) = self_ty else {
        return Err(Error::new_spanned(
            &*self_ty,
            "`#[circuit]` needs the client type's name as the self type",
        ));
    };
    if type_path.qself.is_some() {
        return Err(Error::new_spanned(
            &*type_path,
            "`#[circuit]` needs the client type's name as the self type, not a projection",
        ));
    }
    let Some(segment) = type_path.path.segments.last_mut() else {
        return Err(Error::new_spanned(
            &type_path.path,
            "`#[circuit]` needs the client type's name as the self type",
        ));
    };
    segment.ident = format_ident!("{}Circuit", segment.ident, span = segment.ident.span());
    Ok(())
}
