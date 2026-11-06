//! The Xark dependency that generated entry crates pin. Shared with the CLI
//! test fixtures so they build against exactly the sources the CLI accepts.

/// Converts a cargo source id (`git+<url>?rev=<rev>`, optionally followed by
/// `#<commit>`) into the TOML fields of a pinned Git dependency.
pub(crate) fn pinned_git_dependency(source: &str) -> Result<String, String> {
    let source = source
        .strip_prefix("git+")
        .ok_or("Xark must use a pinned Git dependency")?;
    let source = source.split_once('#').map_or(source, |(source, _)| source);
    let (repository, revision) = source
        .split_once('?')
        .and_then(|(repository, query)| Some((repository, query.strip_prefix("rev=")?)))
        .filter(|(repository, revision)| {
            !repository.is_empty() && !revision.is_empty() && !revision.contains(['&', '='])
        })
        .ok_or("Xark must be pinned with a Git revision (`rev = ...`)")?;
    let quote = |value: &str| serde_json::to_string(value).map_err(|e| e.to_string());
    Ok(format!(
        "git = {}, rev = {}",
        quote(repository)?,
        quote(revision)?
    ))
}
