//! The Xark dependency that generated entry crates pin. Shared with the CLI
//! test fixtures so they build against exactly the sources the CLI accepts.

pub(crate) const CRATES_IO: &str = "registry+https://github.com/rust-lang/crates.io-index";

/// Converts the cargo source id and version of the resolved Xark package into
/// the TOML fields of a dependency on exactly that package: its crates.io
/// version, or the Git revision of a source `git+<url>?rev=<rev>`, optionally
/// followed by `#<commit>`.
pub(crate) fn pinned_dependency(source: &str, version: &str) -> Result<String, String> {
    let quote = |value: &str| serde_json::to_string(value).map_err(|e| e.to_string());
    if source == CRATES_IO {
        return Ok(format!("version = {}", quote(&format!("={version}"))?));
    }
    let source = source
        .strip_prefix("git+")
        .ok_or("Xark must come from crates.io or a pinned Git revision")?;
    let source = source.split_once('#').map_or(source, |(source, _)| source);
    let (repository, revision) = source
        .split_once('?')
        .and_then(|(repository, query)| Some((repository, query.strip_prefix("rev=")?)))
        .filter(|(repository, revision)| {
            !repository.is_empty() && !revision.is_empty() && !revision.contains(['&', '='])
        })
        .ok_or("a Git Xark must be pinned with a revision (`rev = ...`)")?;
    Ok(format!(
        "git = {}, rev = {}",
        quote(repository)?,
        quote(revision)?
    ))
}
