pub mod circom;
pub mod field;
pub mod iden3;
pub mod normalize;
pub mod snarkjs;

use std::{
    fs::File,
    path::{Path, PathBuf},
};

pub fn artifacts() -> PathBuf {
    Path::new(env!("CARGO_TARGET_TMPDIR")).join("zk-program-sdk-unit")
}

pub fn locked(dir: &Path) -> File {
    std::fs::create_dir_all(dir).expect("artifact directory");
    let lock = File::create(dir.join(".lock")).expect("lock file");
    lock.lock().expect("artifact lock");
    lock
}

pub fn path(path: &Path) -> &str {
    path.to_str().expect("utf-8 path")
}

pub struct WorkDir(PathBuf);

impl WorkDir {
    pub fn new(name: &str) -> Self {
        let dir = artifacts()
            .join("work")
            .join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("work directory");
        Self(dir)
    }

    pub fn join(&self, file: &str) -> PathBuf {
        self.0.join(file)
    }

    pub fn write(&self, file: &str, bytes: &[u8]) -> PathBuf {
        let path = self.join(file);
        std::fs::write(&path, bytes).expect("work file");
        path
    }
}

impl Drop for WorkDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
