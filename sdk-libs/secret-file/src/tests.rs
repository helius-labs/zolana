use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

const SECRET: &str = "0101010101010101010101010101010101010101010101010101010101010101";

fn temp_dir(label: &str) -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let dir = std::env::temp_dir().join(format!(
        "zolana-secret-file-{label}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("temp dir");
    dir
}

#[test]
fn hex_must_be_exactly_64_lowercase_digits() {
    assert_eq!(*read_hex32(SECRET).expect("hex"), [1; 32]);
    for text in ["abcd", &"zz".repeat(32), &"AA".repeat(32), &"a".repeat(65)] {
        assert!(matches!(read_hex32(text), Err(SecretFileError::Hex)));
    }
}

#[test]
fn a_pair_round_trips_and_is_never_overwritten() {
    let dir = temp_dir("pair");
    let secret = dir.join("nested/auditor.key");
    let public = dir.join("nested/auditor.key.pub");
    create_pair((&secret, SECRET.as_bytes()), (&public, b"02ab")).expect("pair");
    assert_eq!(
        read_private(&secret, Access::OwnerOnly, 64)
            .expect("secret")
            .as_str(),
        SECRET
    );
    assert_eq!(fs::read_to_string(&public).expect("public"), "02ab");
    assert!(matches!(
        create_pair((&secret, b"other"), (&dir.join("other.pub"), b"other")),
        Err(SecretFileError::Write { .. })
    ));
    assert!(matches!(
        create_new(&public, b"other", Visibility::Public),
        Err(SecretFileError::Write { .. })
    ));
    assert_eq!(fs::read_to_string(&public).expect("public"), "02ab");
    fs::remove_dir_all(dir).expect("cleanup");
}

#[cfg(unix)]
#[test]
fn files_get_their_exact_mode() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("mode");
    let mode = |path: &Path| fs::metadata(path).expect("metadata").permissions().mode() & 0o777;
    let secret = dir.join("root.key");
    let public = dir.join("root.pub");
    create_new(&secret, SECRET.as_bytes(), Visibility::Secret).expect("secret");
    create_new(&public, b"public", Visibility::Public).expect("public");
    assert_eq!(mode(&secret), 0o600);
    assert_eq!(mode(&public), 0o644);
    fs::remove_dir_all(dir).expect("cleanup");
}

#[cfg(unix)]
#[test]
fn a_shared_file_is_refused_unless_allowed() {
    use std::os::unix::fs::PermissionsExt;
    let dir = temp_dir("shared");
    let secret = dir.join("auditor.key");
    create_new(&secret, SECRET.as_bytes(), Visibility::Secret).expect("secret");
    fs::set_permissions(&secret, fs::Permissions::from_mode(0o644)).expect("chmod");
    assert!(matches!(
        read_private(&secret, Access::OwnerOnly, 64),
        Err(SecretFileError::Shared { mode: 0o644, .. })
    ));
    assert!(read_private(&secret, Access::Shared, 64).is_ok());
    fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn a_file_longer_than_the_limit_is_refused() {
    let dir = temp_dir("oversized");
    let secret = dir.join("root.key");
    fs::write(&secret, "a".repeat(65)).expect("write");
    assert!(matches!(
        read_private(&secret, Access::Shared, 64),
        Err(SecretFileError::TooLong { max: 64, .. })
    ));
    fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn a_directory_is_not_a_key_file() {
    let dir = temp_dir("directory");
    assert!(matches!(
        read_private(&dir, Access::Shared, 64),
        Err(SecretFileError::NotRegular { .. } | SecretFileError::Read { .. })
    ));
    fs::remove_dir_all(dir).expect("cleanup");
}

#[cfg(unix)]
#[test]
fn a_symlink_is_never_read() {
    let dir = temp_dir("symlink");
    let target = dir.join("target.key");
    let link = dir.join("link.key");
    create_new(&target, SECRET.as_bytes(), Visibility::Secret).expect("secret");
    std::os::unix::fs::symlink(&target, &link).expect("symlink");
    assert!(matches!(
        read_private(&link, Access::OwnerOnly, 64),
        Err(SecretFileError::Read { .. })
    ));
    fs::remove_dir_all(dir).expect("cleanup");
}

#[cfg(unix)]
#[test]
fn a_symlinked_public_path_leaves_no_secret() {
    let dir = temp_dir("public-symlink");
    let secret = dir.join("auditor.key");
    let public = dir.join("auditor.key.pub");
    let target = dir.join("target");
    fs::write(&target, "unchanged").expect("target");
    std::os::unix::fs::symlink(&target, &public).expect("symlink");
    assert!(matches!(
        create_pair((&secret, SECRET.as_bytes()), (&public, b"02ab")),
        Err(SecretFileError::Write { .. })
    ));
    assert!(!secret.exists());
    assert_eq!(fs::read_to_string(target).expect("target"), "unchanged");
    fs::remove_dir_all(dir).expect("cleanup");
}
