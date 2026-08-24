//! The ring source ships the workspace lockfile, a generated ring resolves
//! the versions zolana builds with.

use std::fs;

#[test]
fn ring_lockfile_matches_the_workspace() {
    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
    let workspace = fs::read_to_string(format!("{root}/Cargo.lock")).expect("workspace lock");
    let ring = fs::read_to_string(format!("{root}/custom-rings/Cargo.lock"))
        .expect("ring lock copy");
    assert!(
        workspace == ring,
        "run `cp Cargo.lock custom-rings/Cargo.lock`"
    );
}
