//! Attestation-only qualification: signed static policy, no wallet or proof submission.

use std::{env, error::Error, fs, io, path::PathBuf};

use spr_client::prover::{
    tee::{tuf_tee_policy, TufTeePolicyOptions},
    ProverClient,
};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args().collect();
    if args.len() != 6 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "usage: tee_policy_attest <reviewed-root.json> <network> <metadata-url> <targets-url> <absolute-cache-directory>; set ZOLANA_PROVER_URL").into());
    }
    let prover_url = env::var("ZOLANA_PROVER_URL").map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "set ZOLANA_PROVER_URL to the prover endpoint",
        )
    })?;
    let source = tuf_tee_policy(TufTeePolicyOptions {
        root_json: fs::read_to_string(&args[1])?,
        network: args[2].clone(),
        metadata_url: args[3].parse()?,
        targets_url: args[4].parse()?,
        cache_directory: PathBuf::from(&args[5]),
        refresh_interval: None,
    })?;
    let prover = ProverClient::new(prover_url).with_tee_source(source);
    let attested = prover.attest()?;
    println!(
        "Verified fresh {:?} attestation with a signed fleet policy",
        attested.platform
    );
    Ok(())
}
