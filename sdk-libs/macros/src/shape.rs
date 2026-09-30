use quote::format_ident;
use syn::{
    Attribute, Data, DeriveInput, Error, Expr, Fields, GenericArgument, Ident, PathArguments,
    Result, Type, Visibility,
};

pub(crate) const MAX_HASHED_FIELDS: usize = 11;

const MAX_LEN: &str = "max_len";
const MIN_LEN: &str = "min_len";

pub(crate) struct Field<'a> {
    pub(crate) ident: &'a Ident,
    pub(crate) ty: &'a Type,
    pub(crate) vis: &'a Visibility,
    pub(crate) bounds: Option<Bounds<'a>>,
}

pub(crate) struct Bounds<'a> {
    pub(crate) item: &'a Type,
    pub(crate) min: Option<Expr>,
    pub(crate) max: Expr,
}

impl<'a> Field<'a> {
    fn of(field: &'a syn::Field) -> Result<Self> {
        let ident = field
            .ident
            .as_ref()
            .ok_or_else(|| Error::new_spanned(field, "a named field has no name"))?;
        let max = length(&field.attrs, MAX_LEN)?;
        let min = length(&field.attrs, MIN_LEN)?;
        let bounds = match (vec_item(&field.ty), max) {
            (Some(item), Some(max)) => Some(Bounds { item, min, max }),
            (Some(_), None) => {
                return Err(Error::new_spanned(
                    &field.ty,
                    "a Vec field needs #[max_len(N)]: a circuit takes a fixed number of items",
                ))
            }
            (None, Some(_)) => {
                return Err(Error::new_spanned(
                    &field.ty,
                    "#[max_len] and #[min_len] bound a Vec field",
                ))
            }
            (None, None) if min.is_some() => {
                return Err(Error::new_spanned(
                    &field.ty,
                    "#[max_len] and #[min_len] bound a Vec field",
                ))
            }
            (None, None) => None,
        };
        Ok(Self {
            ident,
            ty: &field.ty,
            vis: &field.vis,
            bounds,
        })
    }
}

fn length(attrs: &[Attribute], name: &str) -> Result<Option<Expr>> {
    let mut found = attrs.iter().filter(|attr| attr.path().is_ident(name));
    let Some(attr) = found.next() else {
        return Ok(None);
    };
    if let Some(duplicate) = found.next() {
        return Err(Error::new_spanned(
            duplicate,
            format!("#[{name}] is given more than once"),
        ));
    }
    attr.parse_args().map(Some)
}

fn vec_item(ty: &Type) -> Option<&Type> {
    let Type::Path(path) = ty else {
        return None;
    };
    if path.qself.is_some() {
        return None;
    }
    let segment = path.path.segments.last()?;
    if segment.ident != "Vec" {
        return None;
    }
    let PathArguments::AngleBracketed(arguments) = &segment.arguments else {
        return None;
    };
    let mut arguments = arguments.args.iter();
    match (arguments.next(), arguments.next()) {
        (Some(GenericArgument::Type(item)), None) => Some(item),
        _ => None,
    }
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
                    .map(Field::of)
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

    pub(crate) fn is_program(&self) -> bool {
        is_program_fields(self.fields().iter().map(|field| field.ident))
    }

    pub(crate) fn fields(&self) -> &[Field<'a>] {
        match self {
            Shape::Named(fields) => fields,
            Shape::Unit => &[],
        }
    }

    pub(crate) fn check_no_bounds(&self, what: &str) -> Result<()> {
        match self.fields().iter().find(|field| field.bounds.is_some()) {
            Some(field) => Err(Error::new_spanned(
                field.ty,
                format!("{what} have a fixed layout: a Vec field is a proof input of a program"),
            )),
            None => Ok(()),
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

pub(crate) fn is_program_fields<'a>(names: impl IntoIterator<Item = &'a Ident>) -> bool {
    let mut names: Vec<String> = names.into_iter().map(Ident::to_string).collect();
    names.sort();
    names == ["private", "public"]
}

pub(crate) fn snake_case(name: &str) -> String {
    let mut snake = String::with_capacity(name.len() + 4);
    for (index, character) in name.char_indices() {
        if character.is_uppercase() {
            if index > 0 {
                snake.push('_');
            }
            snake.extend(character.to_lowercase());
        } else {
            snake.push(character);
        }
    }
    snake
}

pub(crate) fn twin_ident(ident: &Ident) -> Ident {
    format_ident!("{}Circuit", ident)
}
