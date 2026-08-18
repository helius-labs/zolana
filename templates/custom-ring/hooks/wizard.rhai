// The custom ring wizard.
//
// Every answer becomes a template variable. A variable that arrives on the
// command line (`-d name=value`) is kept, so the driver and CI can run this
// without prompts. The feature registry below is the one place a feature is
// declared: add an entry, and the prompt, ring.toml, README and cargo feature
// list follow.

const PIPELINE = [
    "cargo generate template (this wizard)",
    "create the GitHub repository from the generated ring (`just repo`)",
    "build the program (`just build`)",
    "deploy with your key as upgrade authority (`just deploy`)",
    "initialize the ring for the selected features (`just init`)",
    "start the ring RPC holding the auditor key (`just rpc`)",
    "transact in the ring (`just transact`)",
];

// state: "always" is on for every ring, "ready" is offered as a choice,
// "coming_soon" is listed and disabled.
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

const TARGETS = ["localnet", "devnet", "mainnet"];

// Public clusters go through Helius RPC; the API key is the only per-user part.
const HELIUS_RPC = #{
    devnet: "https://devnet.helius-rpc.com/?api-key=",
    mainnet: "https://mainnet.helius-rpc.com/?api-key=",
};

fn setting(name, fallback) {
    if variable::is_set(name) {
        variable::get(name)
    } else {
        fallback
    }
}

// `-d silent=true` (what the driver passes for `--silent`) turns every question
// into its fallback; a missing required answer aborts instead of prompting.
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

// Target. Mainnet is listed so the choice is visible, and refused.
let target = setting("target", "");
if target == "mainnet" {
    abort("mainnet is disabled for custom rings for now, pick localnet or devnet");
}
if silent() && target != "localnet" && target != "devnet" {
    abort("pass -d target=localnet or -d target=devnet when running without prompts");
}
while target != "localnet" && target != "devnet" {
    if target != "" {
        print(`  ${target} is not a target`);
    }
    target = variable::prompt("Deployment target", "localnet", TARGETS);
    if target == "mainnet" {
        print("  mainnet is disabled for custom rings for now");
    }
}
variable::set("target", target);

// The deployer, ring authority and fee payer. The default is the Solana CLI's
// keypair, so an existing setup is picked up without typing.
ask("authority_keypair", "Deployer and ring authority keypair", "~/.config/solana/id.json");

// Service URLs. localnet defaults come from the driver (per-clone port offset);
// devnet has to name its indexer, prover and ring RPC.
let ring_rpc_port = setting("default_ring_rpc_port", "8785");
if target == "localnet" {
    ask("rpc_url", "Solana RPC URL", setting("default_rpc_url", "http://127.0.0.1:8899"));
    ask("indexer_url", "Photon indexer URL", setting("default_indexer_url", "http://127.0.0.1:8784"));
    ask("prover_url", "Prover URL", setting("default_prover_url", "http://127.0.0.1:3001"));
} else {
    if !variable::is_set("rpc_url") {
        let api_key = ask("helius_api_key", "Helius API key", "");
        if api_key == "" {
            abort("a Helius API key is required for " + target + ", pass -d helius_api_key=... or -d rpc_url=...");
        }
        variable::set("rpc_url", HELIUS_RPC[target] + api_key);
    }
    ask("indexer_url", "Photon indexer URL", "");
    ask("prover_url", "Prover URL", "");
}
ask("ring_rpc_url", "Ring RPC URL", `http://127.0.0.1:${ring_rpc_port}`);
if !variable::is_set("ring_rpc_port") {
    variable::set("ring_rpc_port", ring_rpc_port);
}

// The program id is the address the ring deploys to. The driver generates the
// keypair and hands the pubkey in; typing one by hand needs the matching keypair
// in keys/program-keypair.json before `just deploy`.
ask("program_id", "Program id (base58 pubkey of keys/program-keypair.json)", "");
if variable::get("program_id") == "" {
    abort("a program id is required, run the wizard through `just ring-new` to have one generated");
}
ask("zolana_path", "Path to the zolana checkout", "../zolana");

// Features.
print("");
print("Features");
let features_toml = "";
let features_markdown = "";
let program_features = "";
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
            let key = `feature_${feature.id}`;
            if !variable::is_set(key) {
                let answer = if silent() { false } else { variable::prompt(`Enable ${feature.name}? ${feature.example}`, false) };
                variable::set(key, answer);
            }
            enabled = variable::get(key) == true || variable::get(key) == "true";
            status = if enabled { "enabled" } else { "disabled" };
            print(`  [${if enabled { "x" } else { " " }}] ${feature.name}`);
        }
        _ => {
            status = "coming soon";
            print(`  [ ] ${feature.name} (coming soon)`);
        }
    }
    variable::set(`feature_${feature.id}`, enabled);
    features_toml += feature.id + " = " + enabled + "\n";
    features_markdown += "| " + feature.name + " | " + status + " | " + feature.example + " |\n";
    if enabled && feature.state == "ready" {
        if program_features != "" {
            program_features += ", ";
        }
        program_features += `"${feature.id.replace("_", "-")}"`;
    }
}
print("");
variable::set("features_toml", features_toml);
variable::set("features_markdown", features_markdown);
variable::set("program_features", program_features);
