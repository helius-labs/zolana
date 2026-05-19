use thiserror::Error;

#[derive(Error, Debug)]
pub enum ForesterError {
    #[error("forester is currently a skeleton (no foresting logic compiled in)")]
    SkeletonOnly,

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
