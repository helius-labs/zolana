//! Qualify a signed-policy prover with the committed synthetic 2x2 transfer.
//! No wallet, chain access or transaction submission. `--verify` checks proof
//! exports from the Node/browser qualification against the same on-chain VK.
//! `--pause-after-attestation` waits for `continue` on stdin to exercise
//! recipient failover before the first encrypted request.

use std::{env, error::Error, fs, io, io::Write, path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};
use spr_client::{
    prover::{
        known_proving_keys,
        tee::{recipient_id, tuf_tee_policy, TufTeePolicyOptions},
        verify_proof_statement, Delivery, ExpectedProvingKey, Proof, ProveRequest, ProverClient,
    },
    ClientError, Prover,
};
use spr_interface::{verifying_keys::CircuitId, N_PUBLIC_SLOTS};
use zeroize::Zeroizing;

const INPUTS: &str =
    include_str!("../../../prover/server/prover/request/testdata/transfer-2x2.json");
const KEY: &str = "transfer_confidential_2_2.key";

struct Fixture;

impl ProveRequest for Fixture {
    fn body(&self) -> Result<Zeroizing<String>, ClientError> {
        Ok(Zeroizing::new(INPUTS.to_owned()))
    }

    fn proving_key(&self) -> Result<ExpectedProvingKey, ClientError> {
        let (_, sha256) = known_proving_keys()
            .find(|(name, _)| *name == KEY)
            .ok_or_else(|| ClientError::Prover("fixture proving key is not pinned".into()))?;
        Ok(ExpectedProvingKey {
            name: KEY.into(),
            sha256,
        })
    }

    fn delivery(&self) -> Delivery {
        Delivery::InResponse
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicProof {
    a: String,
    b: String,
    c: String,
    public_input_hash: String,
}

fn bytes<const N: usize>(value: &str) -> Result<[u8; N], Box<dyn Error>> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    if raw.len() != N * 2
        || !raw
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(
            io::Error::new(io::ErrorKind::InvalidInput, "non-canonical proof bytes").into(),
        );
    }
    let mut result = [0; N];
    hex::decode_to_slice(raw, &mut result)?;
    Ok(result)
}

fn verify(proof: &Proof, hash: [u8; 32]) -> Result<(), Box<dyn Error>> {
    let key = CircuitId::ConfidentialSigner(2, 2, N_PUBLIC_SLOTS as u8)
        .verifying_key()
        .ok_or_else(|| io::Error::other("fixture verifying key is missing"))?;
    verify_proof_statement(proof, hash, key)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args: Vec<_> = env::args().skip(1).collect();
    let pause = args
        .first()
        .is_some_and(|arg| arg == "--pause-after-attestation");
    if pause {
        args.remove(0);
    }
    if args.first().is_some_and(|arg| arg == "--verify") && args.len() == 2 {
        let exported: PublicProof = serde_json::from_slice(&fs::read(&args[1])?)?;
        let proof = Proof {
            a: bytes(&exported.a)?,
            b: bytes(&exported.b)?,
            c: bytes(&exported.c)?,
            commitment: None,
        };
        verify(&proof, bytes(&exported.public_input_hash)?)?;
        println!("Verified exported 2x2 proof against the committed on-chain verifying key");
        return Ok(());
    }
    if args.len() != 5 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "usage: tee_policy_prove <reviewed-root.json> <network> <metadata-url> <targets-url> <absolute-cache-directory>; set ZOLANA_PROVER_URL; or --verify <public-proof.json>").into());
    }
    let source = tuf_tee_policy(TufTeePolicyOptions {
        root_json: fs::read_to_string(&args[0])?,
        network: args[1].clone(),
        metadata_url: args[2].parse()?,
        targets_url: args[3].parse()?,
        cache_directory: PathBuf::from(&args[4]),
        refresh_interval: None,
    })?;
    let prover = ProverClient::new(env::var("ZOLANA_PROVER_URL")?)
        .with_tee_source(source)
        .with_proof_timeout(Duration::from_secs(180));
    let attested = prover.attest()?;
    if pause {
        // Let the qualification harness remove the attested generation before
        // the first encrypted request. No fault-control HTTP route is exposed.
        println!(
            "{{\"phase\":\"attested\",\"recipientId\":\"{}\"}}",
            recipient_id(&attested.hpke_public_key)
        );
        io::stdout().flush()?;
        let mut command = String::new();
        io::stdin().read_line(&mut command)?;
        if command.trim() != "continue" {
            return Err(io::Error::other("qualification barrier was not released").into());
        }
    }
    let catalog = prover.check_proving_keys()?;
    let proof = prover.prove(&Fixture)?;
    #[derive(Deserialize)]
    struct Statement {
        #[serde(rename = "publicInputHash")]
        hash: String,
    }
    let statement: Statement = serde_json::from_str(INPUTS)?;
    verify(&proof, bytes(&statement.hash)?)?;
    if let Ok(path) = env::var("ZOLANA_TEE_PROOF_OUTPUT") {
        fs::write(
            path,
            serde_json::to_vec_pretty(&PublicProof {
                a: hex::encode(proof.a),
                b: hex::encode(proof.b),
                c: hex::encode(proof.c),
                public_input_hash: statement.hash,
            })?,
        )?;
    }
    println!(
        "Verified fresh {:?} attestation, encrypted catalog ({} keys), and encrypted 2x2 proof",
        attested.platform,
        catalog.keys.len()
    );
    Ok(())
}
