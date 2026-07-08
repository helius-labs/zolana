use std::process::Command;

/// Boot a fresh `solana-test-validator` with Photon (and no bundled prover) via
/// the `zolana` CLI, loading the given SBF programs and the Squads smart-account
/// program-config fixture. Mirrors the per-crate `restart_localnet` helpers the
/// swap, spp and zone test crates each used to copy.
///
/// The caller resolves the CLI path, ports, ledger/account directories and the
/// `(program_id, program_so)` list so this stays program-agnostic.
pub struct LocalnetValidator {
    pub cli_bin: String,
    pub working_dir: String,
    pub rpc_port: String,
    pub photon_port: String,
    pub ledger: String,
    pub account_dir: String,
    pub programs: Vec<(String, String)>,
}

impl LocalnetValidator {
    pub fn start(&self) {
        crate::smart_account::write_program_config_fixture(&self.account_dir);

        let mut args: Vec<String> = vec![
            "test-validator".into(),
            "--no-use-surfpool".into(),
            "--with-photon".into(),
            "--skip-prover".into(),
            "--rpc-port".into(),
            self.rpc_port.clone(),
            "--photon-port".into(),
            self.photon_port.clone(),
            "--ledger".into(),
            self.ledger.clone(),
        ];
        for (program_id, program_so) in &self.programs {
            args.push("--sbf-program".into());
            args.push(program_id.clone());
            args.push(program_so.clone());
        }
        args.push("--account-dir".into());
        args.push(self.account_dir.clone());

        let status = Command::new(&self.cli_bin)
            .current_dir(&self.working_dir)
            .args(&args)
            .status()
            .expect("run zolana test-validator");
        assert!(status.success(), "zolana test-validator start failed");
    }
}
