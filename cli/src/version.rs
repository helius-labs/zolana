//! `spr version`: the CLI version, which follows the published SPR crates, and
//! the localnet release whose artifacts `release-artifacts.lock` pins.

use anyhow::Result;

use crate::release::Release;

pub(crate) fn run_version() -> Result<()> {
    println!("{}", version_line(Release::load()?.tag()));
    Ok(())
}

fn version_line(localnet_tag: &str) -> String {
    format!(
        "ok version cli={} localnet={localnet_tag}",
        env!("CARGO_PKG_VERSION")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_line_reports_cli_and_localnet_release() {
        assert_eq!(
            version_line("v0.6.0-alpha"),
            format!(
                "ok version cli={} localnet=v0.6.0-alpha",
                env!("CARGO_PKG_VERSION")
            )
        );
    }

    /// The CLI is not published, so nothing else reminds a release to bump it.
    #[test]
    fn cli_version_follows_the_published_crates() {
        let manifest = include_str!("../../sdk-libs/client/Cargo.toml");
        let client_version = manifest
            .lines()
            .find_map(|line| line.strip_prefix("version = \"")?.strip_suffix('"'));
        assert_eq!(
            client_version,
            Some(env!("CARGO_PKG_VERSION")),
            "bump cli/Cargo.toml to the spr-client version"
        );
    }
}
