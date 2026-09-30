use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
};

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote};
use syn::{punctuated::Punctuated, Error, Fields, Ident, Item, ItemStruct, Result, Token, Type};

use crate::shape::{is_program_fields, snake_case};

const DERIVES: [&str; 3] = ["ProofInput", "PublicInputs", "CircuitType"];
const INTEGERS: [&str; 5] = ["u8", "u16", "u32", "u64", "u128"];
const STAMP: &str = "zk-programs.stamp";

struct Program {
    module: Ident,
    fields: Vec<PublicField>,
}

struct PublicField {
    ident: Ident,
    ty: FieldType,
}

enum FieldType {
    Integer(Ident),
    Bool,
    Hash,
}

pub(crate) fn expand(input: TokenStream) -> Result<TokenStream> {
    if !input.is_empty() {
        return Err(Error::new_spanned(
            input,
            "`include_zk_programs!` takes no arguments",
        ));
    }
    let crate_dir = PathBuf::from(env("CARGO_MANIFEST_DIR")?);
    let package = env("CARGO_PKG_NAME")?;
    let mut structs = BTreeMap::new();
    collect_structs(&crate_dir.join("src"), &mut structs);
    let programs = programs(&structs)?;
    let zk_dir = zk_dir(&crate_dir, &package)?;

    let tracking = stamp(&zk_dir).map(|stamp| {
        let stamp = stamp.to_string_lossy().into_owned();
        quote!(
            const _: &[u8] = ::core::include_bytes!(#stamp);
        )
    });
    let modules = programs.iter().map(|program| module(program, &zk_dir));

    Ok(quote! {
        const _: ::core::option::Option<&str> = ::core::option_env!("ZOLANA_ZK_DIR");
        #tracking

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum VerifyError {
            MissingVerifyingKey,
            PublicInputs,
            Proof,
        }

        pub struct Groth16Proof<'a> {
            pub a: &'a [u8; 32],
            pub b: &'a [u8; 64],
            pub c: &'a [u8; 32],
        }

        fn field_bytes(value: u128) -> [u8; 32] {
            let mut bytes = [0u8; 32];
            for (target, source) in bytes.iter_mut().rev().zip(value.to_le_bytes()) {
                *target = source;
            }
            bytes
        }

        #[inline(never)]
        fn verify_groth16(
            proof: &Groth16Proof,
            public_hash: [u8; 32],
            verifying_key: &::groth16_solana::groth16::Groth16Verifyingkey,
        ) -> ::core::result::Result<(), VerifyError> {
            if verifying_key.vk_commitment.is_some() {
                return ::core::result::Result::Err(VerifyError::Proof);
            }
            let a = ::groth16_solana::decompression::decompress_g1(proof.a)
                .map_err(|_| VerifyError::Proof)?;
            let b = ::groth16_solana::decompression::decompress_g2(proof.b)
                .map_err(|_| VerifyError::Proof)?;
            let c = ::groth16_solana::decompression::decompress_g1(proof.c)
                .map_err(|_| VerifyError::Proof)?;
            let public_inputs = [public_hash];
            ::groth16_solana::groth16::Groth16Verifier::new(
                &a,
                &b,
                &c,
                &public_inputs,
                verifying_key,
            )
            .map_err(|_| VerifyError::Proof)?
            .verify()
            .map_err(|_| VerifyError::Proof)
        }

        #(#modules)*
    })
}

fn module(program: &Program, zk_dir: &Path) -> TokenStream {
    let module = &program.module;
    let verifying_key = zk_dir.join(format!("{module}.vk.rs"));
    let key = if verifying_key.is_file() {
        let path = verifying_key.to_string_lossy().into_owned();
        quote! {
            ::core::include!(#path);
            pub const VERIFYINGKEY_AVAILABLE: bool = true;
        }
    } else {
        let missing = format!(
            "no verifying key for `{module}` at {}: run `zolana build-zk-program` first",
            verifying_key.display()
        );
        quote! {
            #[cfg(target_os = "solana")]
            ::core::compile_error!(#missing);
            pub const VERIFYINGKEY: ::groth16_solana::groth16::Groth16Verifyingkey<'static> =
                ::groth16_solana::groth16::Groth16Verifyingkey {
                    nr_pubinputs: 1,
                    vk_alpha_g1: [0; 64],
                    vk_beta_g2: [0; 128],
                    vk_gamma_g2: [0; 128],
                    vk_delta_g2: [0; 128],
                    vk_ic: &[[0; 64]; 2],
                    vk_commitment: ::core::option::Option::None,
                };
            pub const VERIFYINGKEY_AVAILABLE: bool = false;
        }
    };

    let definitions = program.fields.iter().map(|field| {
        let ident = &field.ident;
        match &field.ty {
            FieldType::Integer(ty) => quote!(pub #ident: #ty),
            FieldType::Bool => quote!(pub #ident: bool),
            FieldType::Hash => quote!(pub #ident: [u8; 32]),
        }
    });
    let bindings = program.fields.iter().map(|field| {
        let ident = &field.ident;
        match &field.ty {
            FieldType::Integer(_) | FieldType::Bool => {
                quote!(let #ident = super::field_bytes(u128::from(self.#ident));)
            }
            FieldType::Hash => quote!(let #ident = self.#ident;),
        }
    });
    let inputs = program.fields.iter().map(|field| {
        let ident = &field.ident;
        quote!(#ident.as_slice())
    });

    quote! {
        pub mod #module {
            #key

            pub struct PublicInputs {
                #(#definitions,)*
            }

            impl PublicInputs {
                pub fn hash(
                    &self,
                    private_tx_hash: &[u8; 32],
                ) -> ::core::result::Result<[u8; 32], super::VerifyError> {
                    use ::zolana_hasher::Hasher;
                    #(#bindings)*
                    ::zolana_hasher::Poseidon::hashv(&[#(#inputs,)* private_tx_hash.as_slice()])
                        .map_err(|_| super::VerifyError::PublicInputs)
                }
            }

            pub fn verify(
                proof: &super::Groth16Proof,
                public_inputs: &PublicInputs,
                private_tx_hash: &[u8; 32],
            ) -> ::core::result::Result<(), super::VerifyError> {
                if !VERIFYINGKEY_AVAILABLE {
                    return ::core::result::Result::Err(super::VerifyError::MissingVerifyingKey);
                }
                super::verify_groth16(proof, public_inputs.hash(private_tx_hash)?, &VERIFYINGKEY)
            }
        }
    }
}

fn programs(structs: &BTreeMap<String, ItemStruct>) -> Result<Vec<Program>> {
    let mut programs = Vec::new();
    for item in structs.values() {
        let Fields::Named(fields) = &item.fields else {
            continue;
        };
        let names = fields.named.iter().filter_map(|field| field.ident.as_ref());
        if !item.generics.params.is_empty()
            || !derives_proof_input(item)
            || !is_program_fields(names)
        {
            continue;
        }
        let public = fields
            .named
            .iter()
            .find(|field| field.ident.as_ref().is_some_and(|ident| ident == "public"))
            .and_then(|field| last_ident(&field.ty))
            .ok_or_else(|| {
                Error::new(
                    Span::call_site(),
                    format!(
                        "the `public` field of `{}` is not a named struct",
                        item.ident
                    ),
                )
            })?;
        let fields = if public == "NoPublicInputs" {
            Vec::new()
        } else {
            public_fields(structs.get(&public.to_string()).ok_or_else(|| {
                Error::new(
                    Span::call_site(),
                    format!(
                        "the public inputs `{public}` of `{}` are not a struct in this crate's src",
                        item.ident
                    ),
                )
            })?)
        };
        programs.push(Program {
            module: format_ident!("{}", snake_case(&item.ident.to_string())),
            fields,
        });
    }
    Ok(programs)
}

fn public_fields(item: &ItemStruct) -> Vec<PublicField> {
    let Fields::Named(fields) = &item.fields else {
        return Vec::new();
    };
    fields
        .named
        .iter()
        .filter_map(|field| {
            let ident = field.ident.clone()?;
            let ty = match &field.ty {
                Type::Path(path) if path.qself.is_none() && path.path.is_ident("bool") => {
                    FieldType::Bool
                }
                Type::Path(path)
                    if path.qself.is_none()
                        && INTEGERS.iter().any(|integer| path.path.is_ident(integer)) =>
                {
                    FieldType::Integer(path.path.get_ident()?.clone())
                }
                _ => FieldType::Hash,
            };
            Some(PublicField { ident, ty })
        })
        .collect()
}

fn derives_proof_input(item: &ItemStruct) -> bool {
    item.attrs
        .iter()
        .filter(|attr| attr.path().is_ident("derive"))
        .filter_map(|attr| {
            attr.parse_args_with(Punctuated::<syn::Path, Token![,]>::parse_terminated)
                .ok()
        })
        .flatten()
        .any(|path| {
            path.segments
                .last()
                .is_some_and(|segment| DERIVES.iter().any(|derive| segment.ident == derive))
        })
}

fn last_ident(ty: &Type) -> Option<&Ident> {
    match ty {
        Type::Path(path) => path.path.segments.last().map(|segment| &segment.ident),
        _ => None,
    }
}

fn collect_structs(dir: &Path, structs: &mut BTreeMap<String, ItemStruct>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut paths: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
    paths.sort();
    for path in paths {
        if path.is_dir() {
            collect_structs(&path, structs);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            let Ok(source) = std::fs::read_to_string(&path) else {
                continue;
            };
            if let Ok(file) = syn::parse_file(&source) {
                collect_items(file.items, structs);
            }
        }
    }
}

fn collect_items(items: Vec<Item>, structs: &mut BTreeMap<String, ItemStruct>) {
    for item in items {
        match item {
            Item::Struct(item) => {
                structs.insert(item.ident.to_string(), item);
            }
            Item::Mod(module) => {
                if let Some((_, items)) = module.content {
                    collect_items(items, structs);
                }
            }
            _ => {}
        }
    }
}

fn zk_dir(crate_dir: &Path, package: &str) -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("ZOLANA_ZK_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--manifest-path",
        ])
        .arg(crate_dir.join("Cargo.toml"))
        .output()
        .map_err(|error| located(format!("running cargo metadata: {error}")))?;
    if !output.status.success() {
        return Err(located(format!(
            "cargo metadata failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let metadata: serde_json::Value = serde_json::from_slice(&output.stdout)
        .map_err(|error| located(format!("reading cargo metadata: {error}")))?;
    let target = metadata
        .get("target_directory")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| located("cargo metadata has no target directory".to_string()))?;
    Ok(Path::new(target).join("zk").join(package))
}

fn stamp(zk_dir: &Path) -> Option<PathBuf> {
    let stamp = zk_dir.join(STAMP);
    if !stamp.is_file() {
        std::fs::create_dir_all(zk_dir).ok()?;
        std::fs::write(&stamp, []).ok()?;
    }
    Some(stamp)
}

fn env(name: &str) -> Result<String> {
    std::env::var(name).map_err(|_| located(format!("{name} is not set; build with cargo")))
}

fn located(message: String) -> Error {
    Error::new(Span::call_site(), message)
}
