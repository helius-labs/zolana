//! Emits the TypeScript SDK tables that mirror Rust definitions.
//!
//! The names live only in Rust source, so the tags, error codes, and account
//! discriminators are read from the source files rather than from the linked
//! crates. The shape table carries no names and comes from the linked constant.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use syn::{Expr, ExprLit, Fields, Item, Lit};

const REGEN_COMMAND: &str = "cargo xtask ts-interface-consts";
const DEFAULT_OUT_DIR: &str = "sdk-libs/ts/src/interface/generated";

const TAG_SOURCE: &str = "program-libs/event/src/tag.rs";
const ERROR_SOURCE: &str = "program-libs/interface/src/error.rs";
const DISCRIMINATOR_SOURCE: &str = "program-libs/interface/src/state/discriminator.rs";
const SHAPE_SOURCE: &str = "program-libs/interface/src/shape.rs";
const TREE_SOURCE: &str = "program-libs/interface/src/state/tree.rs";
const STATE_SOURCE: &str = "program-libs/interface/src/state";

pub struct Options {
    out_dir: PathBuf,
    check: bool,
}

impl Options {
    pub fn parse(args: Vec<String>) -> Self {
        let mut out_dir = PathBuf::from(DEFAULT_OUT_DIR);
        let mut check = false;

        let mut args = args.into_iter();
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--out-dir" => {
                    out_dir = args
                        .next()
                        .map(PathBuf::from)
                        .unwrap_or_else(|| usage_and_exit("--out-dir missing value"));
                }
                "--check" => check = true,
                "--help" | "-h" => {
                    print_help();
                    std::process::exit(0);
                }
                other => usage_and_exit(&format!("unexpected arg {other:?}")),
            }
        }

        Self { out_dir, check }
    }
}

pub fn run(options: Options) -> Result<()> {
    let files = [
        ("instruction-tags.ts", instruction_tags()?),
        ("error-codes.ts", error_codes()?),
        ("state-discriminators.ts", state_discriminators()?),
        ("shapes.ts", shapes()),
        ("tree-layout.ts", tree_layout()),
        ("account-sizes.ts", account_sizes()),
    ];

    if options.check {
        check(&options.out_dir, &files)
    } else {
        write(&options.out_dir, &files)
    }
}

fn check(out_dir: &Path, files: &[(&str, String)]) -> Result<()> {
    let stale = files
        .iter()
        .filter(|(name, expected)| {
            fs::read_to_string(out_dir.join(name)).ok().as_deref() != Some(expected.as_str())
        })
        .map(|(name, _)| *name)
        .collect::<Vec<_>>();

    if !stale.is_empty() {
        bail!(
            "{} no longer matches the Rust definitions. Run `{REGEN_COMMAND}`.",
            stale.join(", ")
        );
    }
    println!("{} matches the Rust definitions", out_dir.display());
    Ok(())
}

fn write(out_dir: &Path, files: &[(&str, String)]) -> Result<()> {
    fs::create_dir_all(out_dir)
        .with_context(|| format!("failed to create {}", out_dir.display()))?;
    for (name, contents) in files {
        let path = out_dir.join(name);
        fs::write(&path, contents)
            .with_context(|| format!("failed to write {}", path.display()))?;
        println!("wrote {}", path.display());
    }
    Ok(())
}

/// First-byte dispatch tags. `NEXT_FREE_TAG` bounds the table, so a tag added
/// below it lands here without touching this generator.
fn instruction_tags() -> Result<String> {
    let consts = parse_u8_consts(Path::new(TAG_SOURCE))?;
    let next_free = consts
        .iter()
        .find(|item| item.name == "NEXT_FREE_TAG")
        .ok_or_else(|| anyhow!("{TAG_SOURCE} defines no NEXT_FREE_TAG"))?
        .value;

    let mut tags = consts
        .iter()
        .filter(|item| item.value < next_free)
        .collect::<Vec<_>>();
    tags.sort_by_key(|item| item.value);

    for (index, tag) in tags.iter().enumerate() {
        if u64::try_from(index) != Ok(tag.value) {
            bail!(
                "{TAG_SOURCE} tag {} = {} breaks the run of dispatched bytes below NEXT_FREE_TAG",
                tag.name,
                tag.value
            );
        }
    }

    let mut out = header(TAG_SOURCE);
    out.push_str("/** First byte of shielded-pool instruction data. */\n");
    out.push_str("export const InstructionTag = Object.freeze({\n");
    for tag in tags {
        out.push_str(&format!("  {}: {},\n", camel_case(&tag.name), tag.value));
    }
    out.push_str("} as const);\n");
    out.push_str(
        "export type InstructionTag = (typeof InstructionTag)[keyof typeof InstructionTag];\n",
    );
    Ok(out)
}

fn error_codes() -> Result<String> {
    let variants = parse_enum_discriminants(Path::new(ERROR_SOURCE), "ShieldedPoolError")?;

    let mut out = header(ERROR_SOURCE);
    out.push_str("/** On-chain `ProgramError::Custom` codes of the shielded pool. */\n");
    out.push_str("export const ShieldedPoolError = Object.freeze({\n");
    for variant in variants {
        out.push_str(&format!("  {}: {},\n", variant.name, variant.value));
    }
    out.push_str("} as const);\n");
    Ok(out)
}

/// Account discriminators. The table already says `Discriminator`, so a name
/// that repeats the word loses the repetition.
fn state_discriminators() -> Result<String> {
    let consts = parse_u8_consts(Path::new(DISCRIMINATOR_SOURCE))?;

    let mut out = header(DISCRIMINATOR_SOURCE);
    out.push_str("/** First byte of a shielded-pool account's data. */\n");
    out.push_str("export const StateDiscriminator = Object.freeze({\n");
    for item in consts {
        let name = item
            .name
            .strip_suffix("_DISCRIMINATOR")
            .unwrap_or(&item.name);
        out.push_str(&format!("  {}: {},\n", camel_case(name), item.value));
    }
    out.push_str("} as const);\n");
    Ok(out)
}

fn shapes() -> String {
    use zolana_interface::shape::SPP_SUPPORTED_SHAPES;

    let mut out = header(SHAPE_SOURCE);
    out.push_str("/** Transact shapes the SPP prover holds keys for. */\n");
    out.push_str("export const SPP_SUPPORTED_SHAPES = Object.freeze([\n");
    for shape in SPP_SUPPORTED_SHAPES {
        out.push_str(&format!(
            "  Object.freeze({{ inputs: {}, outputs: {} }}),\n",
            shape.n_inputs(),
            shape.n_outputs()
        ));
    }
    out.push_str("]);\n");
    out
}

/// Byte length each account decoder must demand. A `#[repr(C)]` size shifts
/// whenever a field is added, and the decoders read it as a literal.
fn account_sizes() -> String {
    use zolana_interface::state::{ProtocolConfig, RingConfig, SplAssetCounter, SplAssetRegistry};

    let sizes = [
        ("protocolConfig", ProtocolConfig::SIZE),
        ("ringConfig", RingConfig::SIZE),
        ("splAssetCounter", SplAssetCounter::SIZE),
        ("splAssetRegistry", SplAssetRegistry::SIZE),
    ];

    let mut out = header(STATE_SOURCE);
    out.push_str("/** Byte length of a shielded-pool account's data. */\n");
    out.push_str("export const AccountSize = Object.freeze({\n");
    for (name, size) in sizes {
        out.push_str(&format!("  {name}: {size},\n"));
    }
    out.push_str("} as const);\n");
    out
}

/// Byte lengths and offsets of the tree account. They come out of the Rust type
/// layout, so no reader can check them against a constant in the source.
fn tree_layout() -> String {
    use zolana_interface::state::{state_root_offset, tree_account_size};

    let mut out = header(TREE_SOURCE);
    out.push_str("/** Byte length of a shielded-pool tree account. */\n");
    out.push_str(&format!(
        "export const TREE_ACCOUNT_SIZE = {};\n\n",
        digit_groups(tree_account_size())
    ));
    out.push_str("/** Byte offset of the utxo tree's current root in that account. */\n");
    out.push_str(&format!(
        "export const STATE_ROOT_OFFSET = {};\n",
        digit_groups(state_root_offset())
    ));
    out
}

/// Underscore-separated thousands, the form the SDK writes long numbers in.
fn digit_groups(value: usize) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push('_');
        }
        out.push(digit);
    }
    out
}

fn header(source: &str) -> String {
    format!(
        "// This file is generated by `{REGEN_COMMAND}` from {source}.\n\
         // Do not edit by hand.\n\n"
    )
}

/// A `pub const NAME: u8 = N;` item, or an enum variant with an explicit
/// discriminant, in declaration order.
struct RustConst {
    name: String,
    value: u64,
}

fn parse_u8_consts(path: &Path) -> Result<Vec<RustConst>> {
    parse_file(path)?
        .items
        .into_iter()
        .filter_map(|item| match item {
            Item::Const(item) => Some(item),
            _ => None,
        })
        .map(|item| {
            let name = item.ident.to_string();
            let value = int_literal(&item.expr).ok_or_else(|| {
                anyhow!("{} const {name} is not an integer literal", path.display())
            })?;
            Ok(RustConst { name, value })
        })
        .collect()
}

fn parse_enum_discriminants(path: &Path, wanted: &str) -> Result<Vec<RustConst>> {
    let item = parse_file(path)?
        .items
        .into_iter()
        .find_map(|item| match item {
            Item::Enum(item) if item.ident == wanted => Some(item),
            _ => None,
        })
        .ok_or_else(|| anyhow!("{} defines no enum {wanted}", path.display()))?;

    item.variants
        .into_iter()
        .map(|variant| {
            let name = variant.ident.to_string();
            if !matches!(variant.fields, Fields::Unit) {
                bail!("{wanted}::{name} carries data and has no wire code");
            }
            let value = variant
                .discriminant
                .as_ref()
                .and_then(|(_, expr)| int_literal(expr))
                .ok_or_else(|| anyhow!("{wanted}::{name} has no explicit code"))?;
            Ok(RustConst { name, value })
        })
        .collect()
}

fn parse_file(path: &Path) -> Result<syn::File> {
    let source =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;
    syn::parse_file(&source).with_context(|| format!("failed to parse {}", path.display()))
}

fn int_literal(expr: &Expr) -> Option<u64> {
    match expr {
        Expr::Lit(ExprLit {
            lit: Lit::Int(literal),
            ..
        }) => literal.base10_parse().ok(),
        _ => None,
    }
}

fn camel_case(screaming_snake: &str) -> String {
    screaming_snake
        .split('_')
        .filter(|word| !word.is_empty())
        .enumerate()
        .map(|(index, word)| {
            let lower = word.to_ascii_lowercase();
            if index == 0 {
                return lower;
            }
            let mut chars = lower.chars();
            match chars.next() {
                Some(first) => first.to_ascii_uppercase().to_string() + chars.as_str(),
                None => lower,
            }
        })
        .collect()
}

fn usage_and_exit(message: &str) -> ! {
    eprintln!("error: {message}");
    print_help();
    std::process::exit(2);
}

fn print_help() {
    println!("xtask ts-interface-consts [--out-dir <dir>] [--check]");
    println!();
    println!("Emits the TypeScript interface tables derived from the Rust definitions.");
    println!("--check fails when the committed TypeScript differs from the emitted one.");
    println!();
    println!("Defaults:");
    println!("  --out-dir {DEFAULT_OUT_DIR}");
}
