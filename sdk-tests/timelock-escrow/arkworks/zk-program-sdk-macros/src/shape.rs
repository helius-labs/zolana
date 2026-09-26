use quote::format_ident;
use syn::{Data, DeriveInput, Error, Fields, Ident, Result, Type, Visibility};

pub(crate) const MAX_HASHED_FIELDS: usize = 11;

pub(crate) struct Field<'a> {
    pub(crate) ident: &'a Ident,
    pub(crate) ty: &'a Type,
    pub(crate) vis: &'a Visibility,
}

pub(crate) enum Shape<'a> {
    Named(Vec<Field<'a>>),
    Unit,
}

impl<'a> Shape<'a> {
    pub(crate) fn of(input: &'a DeriveInput) -> Result<Self> {
        match &input.data {
            Data::Struct(data) => match &data.fields {
                Fields::Named(fields) => fields
                    .named
                    .iter()
                    .map(|field| {
                        let ident = field.ident.as_ref().ok_or_else(|| {
                            Error::new_spanned(field, "a named field has no name")
                        })?;
                        Ok(Field {
                            ident,
                            ty: &field.ty,
                            vis: &field.vis,
                        })
                    })
                    .collect::<Result<Vec<_>>>()
                    .map(Shape::Named),
                Fields::Unit => Ok(Shape::Unit),
                Fields::Unnamed(fields) => Err(Error::new_spanned(
                    fields,
                    "circuit derives support structs with named fields and unit structs, not tuple structs",
                )),
            },
            Data::Enum(data) => Err(Error::new_spanned(
                data.enum_token,
                "circuit derives support structs, not enums",
            )),
            Data::Union(data) => Err(Error::new_spanned(
                data.union_token,
                "circuit derives support structs, not unions",
            )),
        }
    }

    pub(crate) fn fields(&self) -> &[Field<'a>] {
        match self {
            Shape::Named(fields) => fields,
            Shape::Unit => &[],
        }
    }

    pub(crate) fn check_hashed_field_count(&self, input: &DeriveInput, what: &str) -> Result<()> {
        let count = self.fields().len();
        if count > MAX_HASHED_FIELDS {
            return Err(Error::new_spanned(
                &input.ident,
                format!(
                    "{what} hash at most {MAX_HASHED_FIELDS} fields, {count} given: Poseidon takes 12 inputs and one is reserved; nest a struct to hash more"
                ),
            ));
        }
        Ok(())
    }
}

pub(crate) fn twin_ident(ident: &Ident) -> Ident {
    format_ident!("{}Circuit", ident)
}
