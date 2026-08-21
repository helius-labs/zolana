// Every answer is a template variable, a `-d name=value` answer is kept. FEATURES is the one place a feature is declared.

const PIPELINE = [
    "cargo generate template (this wizard)",
    "create the GitHub repository from the generated ring (`just repo`)",
    "build the program (`just build`)",
    "deploy with your key as upgrade authority (`just deploy`)",
    "initialize the ring for the selected features (`just init`)",
    "start the ring RPC holding the auditor key (`just rpc`)",
    "transact in the ring (`just transact`)",
];

const FEATURES = [
    #{ id: "confidential", name: "Confidential", example: "Amounts and recipients are hidden on chain", state: "always" },
    #{ id: "auditor_visibility", name: "Auditor visibility", example: "Let compliance, accounting, or regulators view ring activity", state: "always" },
    #{ id: "anonymous", name: "Anonymous", example: "Hide senders and recipients from the ring itself", state: "coming_soon" },
    #{ id: "allowed_assets", name: "Allowed assets", example: "Only USDC or a specific issued stablecoin", state: "coming_soon" },
    #{ id: "freeze_thaw", name: "Freeze/thaw", example: "Freeze a balance while an investigation is pending", state: "coming_soon" },
    #{ id: "transfer_limits", name: "Transfer limits", example: "Require extra approval above a threshold", state: "coming_soon" },
    #{ id: "co_signing", name: "Co-signing", example: "Require compliance approval for selected payments", state: "coming_soon" },
    #{ id: "allowlists", name: "Allowlists", example: "Only allow transfers to approved accounts, merchants, or rings", state: "coming_soon" },
    #{ id: "blocklists", name: "Blocklists", example: "Block sanctioned or risky destinations", state: "coming_soon" },
    #{ id: "permanent_delegate", name: "Permanent delegate", example: "Allow a configured authority to move funds under policy", state: "coming_soon" },
    #{ id: "cross_ring_rules", name: "Cross-ring rules", example: "Allow or block movement between specific rings", state: "coming_soon" },
    #{ id: "withdrawal_rules", name: "Withdrawal rules", example: "Restrict public withdrawals or require approval", state: "coming_soon" },
    #{ id: "smart_account_support", name: "Smart account support", example: "Allow native use with smart accounts such as Squads", state: "coming_soon" },
    #{ id: "account_recovery", name: "Account recovery", example: "Allow a configured authority or fallback identity to recover accounts", state: "coming_soon" },
];

// The API key goes to .env, the URL keeps `${HELIUS_API_KEY}` for the CLI to expand.
const HELIUS_DEVNET_RPC = "https://devnet.helius-rpc.com/?api-key=${HELIUS_API_KEY}";
const PUBLIC_DEVNET_RPC = "https://api.devnet.solana.com";
const DEVNET_INDEXER = "http://zolnet-devnet-1779374825.eu-north-1.elb.amazonaws.com";
const DEVNET_PROVER = "http://zolnet-devnet-1779374825.eu-north-1.elb.amazonaws.com:3001";
const ZOLANA_REPOSITORY = "https://github.com/helius-labs/zolana.git";

fn setting(name, fallback) {
    if variable::is_set(name) {
        variable::get(name)
    } else {
        fallback
    }
}

// With `-d silent=true` every question takes its fallback and a missing required answer aborts.
fn silent() {
    let value = setting("silent", false);
    value == true || value == "true"
}

fn ask(name, text, fallback) {
    if !variable::is_set(name) {
        if silent() {
            variable::set(name, fallback);
        } else {
            variable::set(name, variable::prompt(text, fallback));
        }
    }
    variable::get(name)
}

print("");
print("Custom ring pipeline");
let step = 1;
for line in PIPELINE {
    print(`  ${step}. ${line}`);
    step += 1;
}
print("");

ask("authority_keypair", "Deployer and ring authority keypair", "~/.config/solana/id.json");

// localnet defaults come from the driver.
let ring_rpc_port = setting("default_ring_rpc_port", "8785");
ask("rpc_url", "Localnet Solana RPC URL", setting("default_rpc_url", "http://127.0.0.1:8899"));
ask("indexer_url", "Photon indexer URL", setting("default_indexer_url", "http://127.0.0.1:8784"));
ask("prover_url", "Prover URL", setting("default_prover_url", "http://127.0.0.1:3001"));
ask("ring_rpc_url", "Ring RPC URL", `http://127.0.0.1:${ring_rpc_port}`);
if !variable::is_set("ring_rpc_port") {
    variable::set("ring_rpc_port", ring_rpc_port);
}
if !variable::is_set("devnet_rpc_url") {
    let api_key = ask("helius_api_key", "Helius API key for devnet (empty for the public endpoint)", "");
    variable::set("devnet_rpc_url", if api_key == "" { PUBLIC_DEVNET_RPC } else { HELIUS_DEVNET_RPC });
}
if !variable::is_set("helius_api_key") {
    variable::set("helius_api_key", "");
}
ask("devnet_indexer_url", "Devnet Photon indexer URL", DEVNET_INDEXER);
ask("devnet_prover_url", "Devnet prover URL", DEVNET_PROVER);

// A hand-typed id needs its keypair in keys/program-keypair.json before `just deploy`.
ask("program_id", "Program id (base58 pubkey of keys/program-keypair.json)", "");
if variable::get("program_id") == "" {
    abort("a program id is required, run the wizard through `just ring-new` to have one generated");
}
// `.zolana` is a clone `just source` pins to `zolana_revision`, any other path is used as is.
ask("zolana_path", "Path to the zolana source", ".zolana");
ask("zolana_repository", "Zolana repository", ZOLANA_REPOSITORY);
let revision = ask("zolana_revision", "Zolana revision (40 hex, the commit the ring builds against)", "");
if revision == "" {
    abort("a zolana revision is required, run the wizard through `just ring-new` to pin the checkout's HEAD");
}
let revision_is_hex = revision.len() == 40;
for c in revision {
    if !"0123456789abcdef".contains(c) {
        revision_is_hex = false;
    }
}
if !revision_is_hex {
    abort(`zolana revision ${revision} is not a 40 hex commit`);
}

print("");
print("Features");
let features_toml = "";
let features_markdown = "";
let cargo_features = "";
for feature in FEATURES {
    let enabled = false;
    let status = "";
    switch feature.state {
        "always" => {
            enabled = true;
            status = "enabled";
            print(`  [x] ${feature.name} (always on)`);
        }
        "ready" => {
            // `-d feature_<id>=true` arrives as a string, a prompt as a bool.
            let key = `feature_${feature.id}`;
            enabled = if variable::is_set(key) {
                let answer = variable::get(key);
                answer == true || answer == "true"
            } else if silent() {
                false
            } else {
                variable::prompt(`Enable ${feature.name}? ${feature.example}`, false)
            };
            status = if enabled { "enabled" } else { "disabled" };
            print(`  [${if enabled { "x" } else { " " }}] ${feature.name}`);
        }
        _ => {
            status = "coming soon";
            print(`  [ ] ${feature.name} (coming soon)`);
        }
    }
    // Liquid and `[conditional]` blocks see a bool, never the raw `-d` string.
    variable::set(feature.id + "_enabled", enabled);
    features_toml += feature.id + " = " + enabled + "\n";
    features_markdown += "| " + feature.name + " | " + status + " | " + feature.example + " |\n";
    // The id is the cargo feature name, so both crates declare it verbatim.
    if enabled && feature.state == "ready" {
        if cargo_features != "" {
            cargo_features += ", ";
        }
        cargo_features += "\"" + feature.id + "\"";
    }
}
print("");
variable::set("features_toml", features_toml);
variable::set("features_markdown", features_markdown);
variable::set("cargo_features", cargo_features);
