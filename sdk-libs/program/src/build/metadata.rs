use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PublicFieldKind {
    Integer { bits: usize },
    Bool,
    Hash,
    Bytes { len: usize },
    Array { len: usize, item: Box<PublicFieldKind> },
}

pub trait PublicField { fn kind() -> PublicFieldKind; }
pub trait PublicInputLayout { fn layout() -> Vec<(&'static str, PublicFieldKind)>; }

macro_rules! integer {
    ($($t:ty => $bits:literal),*) => {$(impl PublicField for $t {
        fn kind() -> PublicFieldKind { PublicFieldKind::Integer { bits: $bits } }
    })*};
}
integer!(u8 => 8, u16 => 16, u32 => 32, u64 => 64, u128 => 128);
impl PublicField for bool { fn kind() -> PublicFieldKind { PublicFieldKind::Bool } }
impl PublicField for crate::Field { fn kind() -> PublicFieldKind { PublicFieldKind::Hash } }
impl PublicField for crate::UtxoOwner { fn kind() -> PublicFieldKind { PublicFieldKind::Hash } }
impl PublicField for crate::ShieldedAddress { fn kind() -> PublicFieldKind { PublicFieldKind::Hash } }
impl<T: PublicField, const N: usize> PublicField for [T; N] {
    fn kind() -> PublicFieldKind {
        let item = T::kind();
        if matches!(item, PublicFieldKind::Integer { bits: 8 }) { PublicFieldKind::Hash }
        else { PublicFieldKind::Array { len: N, item: Box::new(item) } }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProgramMetadata {
    pub name: String,
    pub rust_type: String,
    pub fields: Vec<(String, PublicFieldKind)>,
}

pub fn export_program(name: &str, rust_type: &str, layout: Vec<(&str, PublicFieldKind)>) {
    let Some(directory) = std::env::var_os("ZOLANA_PROGRAM_EXPORT_DIR") else { return; };
    let metadata = ProgramMetadata { name: name.into(), rust_type: rust_type.into(),
        fields: layout.into_iter().map(|(name, kind)| (name.to_string(), kind)).collect() };
    let output = Path::new(&directory).join(format!("{name}.json"));
    std::fs::write(output, serde_json::to_vec_pretty(&metadata).expect("serialize program metadata"))
        .expect("write program metadata");
}
