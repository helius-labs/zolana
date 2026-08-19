// The custom ring wizard.
//
// Every answer becomes a template variable. A variable that arrives on the
// command line (`-d name=value`) is kept, so the driver and CI can run this
// without prompts. The feature registry below is the one place a feature is
// declared. Add an entry, and the prompt, ring.toml and README follow. A
// feature that needs on-chain values adds them to `policy_toml`.

const PIPELINE = [
    "cargo generate template (this wizard)",
    "create the GitHub repository from the generated ring (`just repo`)",
    "build the program (`just build`)",
    "deploy with your key as upgrade authority (`just deploy`)",
    "initialize the ring for the selected features (`just init`)",
    "start the ring RPC holding the auditor key (`just rpc`)",
    "transact in the ring (`just transact`)",
];

// The `state` field. "always" is on for every ring, "ready" is offered as a
// choice, "coming_soon" is listed and disabled.
const FEATURES = [
    #{ id: "confidential", name: "Confidential", example: "Amounts and recipients are hidden on chain", state: "always" },
    #{ id: "auditor_visibility", name: "Auditor visibility", example: "Let compliance, accounting, or regulators view ring activity", state: "always" },
    #{ id: "allowed_assets", name: "Allowed assets", example: "Only USDC or a specific issued stablecoin", state: "ready" },
    #{ id: "withdrawal_rules", name: "Withdrawal rules", example: "Block public withdrawals, or require an approver's sign-off, per asset", state: "ready" },
    #{ id: "anonymous", name: "Anonymous", example: "Hide senders and recipients from the ring itself", state: "coming_soon" },
    #{ id: "freeze_thaw", name: "Freeze/thaw", example: "Freeze a balance while an investigation is pending", state: "coming_soon" },
    #{ id: "transfer_limits", name: "Transfer limits", example: "Require extra approval above a threshold", state: "coming_soon" },
    #{ id: "co_signing", name: "Co-signing", example: "Require compliance approval for selected payments", state: "coming_soon" },
    #{ id: "allowlists", name: "Allowlists", example: "Only allow transfers to approved accounts, merchants, or rings", state: "coming_soon" },
    #{ id: "blocklists", name: "Blocklists", example: "Block sanctioned or risky destinations", state: "coming_soon" },
    #{ id: "permanent_delegate", name: "Permanent delegate", example: "Allow a configured authority to move funds under policy", state: "coming_soon" },
    #{ id: "cross_ring_rules", name: "Cross-ring rules", example: "Allow or block movement between specific rings", state: "coming_soon" },
    #{ id: "smart_account_support", name: "Smart account support", example: "Allow native use with smart accounts such as Squads", state: "coming_soon" },
    #{ id: "account_recovery", name: "Account recovery", example: "Allow a configured authority or fallback identity to recover accounts", state: "coming_soon" },
];

// Devnet goes through Helius RPC when an API key is given, else the public
// endpoint. The key is written to the ring's .env (ignored in git) and the URL
// carries `${HELIUS_API_KEY}`, which the CLI expands. The hosted devnet
// indexer and prover are the defaults. The ring picks the cluster later with
// `just localnet` or `just devnet`, the wizard only records both sets of URLs.
const HELIUS_DEVNET_RPC = "https://devnet.helius-rpc.com/?api-key=${HELIUS_API_KEY}";
const PUBLIC_DEVNET_RPC = "https://api.devnet.solana.com";
const DEVNET_INDEXER = "http://zolnet-devnet-1779374825.eu-north-1.elb.amazonaws.com";
const DEVNET_PROVER = "http://zolnet-devnet-1779374825.eu-north-1.elb.amazonaws.com:3001";

fn setting(name, fallback) {
    if variable::is_set(name) {
        variable::get(name)
    } else {
        fallback
    }
}

// `-d silent=true` (what the driver passes for `--silent`) turns every question
// into its fallback. A missing required answer aborts instead of prompting.
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

// The deployer, ring authority and fee payer. The default is the Solana CLI's
// keypair, so an existing setup is picked up without typing.
ask("authority_keypair", "Deployer and ring authority keypair", "~/.config/solana/id.json");

// Service URLs. localnet defaults come from the driver (per-clone port offset).
// devnet uses the same local photon, prover and ring RPC for now, only the
// Solana RPC differs.
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

// The program id is the address the ring deploys to. The driver generates the
// keypair and hands the pubkey in. Typing one by hand needs the matching keypair
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
    // The resolved answer is a bool under a name the wizard owns, so liquid and
    // `[conditional]` blocks never see a raw command-line string.
    variable::set(feature.id + "_enabled", enabled);
    features_toml += feature.id + " = " + enabled + "\n";
    features_markdown += "| " + feature.name + " | " + status + " | " + feature.example + " |\n";
}
print("");
variable::set("features_toml", features_toml);
variable::set("features_markdown", features_markdown);

// Policy the enabled features need. `init` writes it on chain, `policy` edits it.
let policy_toml = "";
if variable::get("allowed_assets_enabled") {
    let assets = if variable::is_set("allowed_assets") {
        variable::get("allowed_assets")
    } else if silent() {
        "SOL"
    } else {
        variable::prompt("Allowed assets, comma separated mints (SOL for native SOL)", "SOL")
    };
    let list = "";
    for entry in assets.split(",") {
        let mint = entry;
        mint.trim();
        if mint == "" { continue; }
        if list != "" { list += ", "; }
        list += `"${mint}"`;
    }
    if list == "" {
        abort("allowed_assets needs at least one mint");
    }
    policy_toml += "allowed_assets = [" + list + "]\n";
}
if variable::get("withdrawal_rules_enabled") {
    // The default rule for every asset. `policy set --asset-withdrawals` and
    // ring.toml's `[policy.asset_withdrawals]` refine it per mint.
    let rule = if variable::is_set("withdrawals") {
        variable::get("withdrawals")
    } else if silent() {
        "blocked"
    } else {
        variable::prompt("Public withdrawals", "blocked", ["blocked", "approval", "open"])
    };
    if rule != "blocked" && rule != "approval" && rule != "open" {
        abort("withdrawals must be blocked, approval or open");
    }
    policy_toml += "withdrawals = \"" + rule + "\"\n";
    if rule == "approval" {
        // The authority approves by default. The driver passes its pubkey.
        let approver = if variable::is_set("approver") {
            variable::get("approver")
        } else if silent() {
            setting("authority_pubkey", "")
        } else {
            variable::prompt("Approver pubkey", setting("authority_pubkey", ""))
        };
        if approver == "" {
            abort("an approval rule needs an approver, pass -d approver=<pubkey>");
        }
        policy_toml += "approver = \"" + approver + "\"\n";
    }
}
variable::set("policy_toml", policy_toml);
