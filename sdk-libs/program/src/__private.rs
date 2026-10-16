// The zk DSL's private items exist only with its serde (also behind tsify and
// wasm) or setup features, which these forward to.
#[cfg(any(feature = "serde", feature = "setup"))]
pub use zolana_zk_dsl::__private::*;

#[cfg(feature = "setup")]
pub use crate::verifier_codegen::render_verifier;

/// The hook of a ZK program: its verifier hashes the public fields with the
/// private transaction hash into the one public input.
#[cfg(feature = "r1cs-export")]
pub fn write_program_r1cs<P: crate::ZkProgram>(
    name: &str,
    layout: &[(&'static str, crate::PublicFieldKind)],
) {
    zolana_zk_dsl::r1cs_hook::write_r1cs::<P>(name, &render_verifier(name, layout));
}

// The cfg is evaluated in this crate, not in the consuming program.
macro_rules! feature_macro {
    ($name:ident, $feature:literal, $d:tt, { $($definition:tt)* }) => {
        #[cfg(feature = $feature)]
        #[doc(hidden)]
        #[macro_export]
        macro_rules! $name { $($definition)* }

        #[cfg(not(feature = $feature))]
        #[doc(hidden)]
        #[macro_export]
        macro_rules! $name { ($d($d item:tt)*) => {}; }
    };
}

feature_macro!(__zk_program_r1cs, "r1cs-export", $, {
    ($($item:tt)*) => { $($item)* };
});
feature_macro!(__zk_program_wasm, "wasm", $, {
    ($($item:tt)*) => { $($item)* };
});
// zolana-zk-dsl defines the same gates on its own features for standalone
// circuits. A ZK program's derives resolve to these, gated on this crate's
// features, which also enable the matching wallet type serde impls.
feature_macro!(__proof_input_serde, "serde", $, {
    ($($item:tt)*) => { $($item)* };
});
feature_macro!(__proof_input_tsify, "tsify", $, {
    ($($item:tt)*) => { $($item)* };
});
