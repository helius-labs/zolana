#!/usr/bin/env python3
"""Profile individual circuit primitives with Xark; generated crates stay in target/."""

import argparse
from dataclasses import dataclass
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


ROOT = Path(__file__).resolve().parents[3]
BENCHES = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Case:
    name: str
    group: str
    parameters: str
    body: str
    outputs: int = 1
    definitions: str = ""
    tests: str = ""


def chain_tests(length):
    return f'''#[cfg(test)]
mod tests {{
    use super::*;
    #[test]
    fn zero_patterns_accept_only_the_expected_chain() {{
        for pattern in 0..(1usize << {length}) {{
            let mut values = [Field::zero(); {length}];
            for (index, value) in values.iter_mut().enumerate() {{
                if pattern & (1 << index) != 0 {{ *value = Field::from((index + 7) as u64); }}
            }}
            let expected = spr_circuit::nonzero_hash_chain(&values).expect("native chain");
            nonzero_chain_{length}(values, expected).expect("satisfied constraints");
            assert!(nonzero_chain_{length}(values, expected + Field::one()).is_err());
        }}
    }}
}}'''


def state_cases():
    cases = []
    account_definition = "#[input]\npub struct Account { pub bytes: [u8; 32] }"
    for unique, operations in [(False, ["spend", "update", "close"]),
                               (True, ["spend", "update", "close", "burn"])]:
        prefix = "unique_state" if unique else "data_state"
        ty = "UniqueDataUtxo" if unique else "DataUtxo"
        for operation in operations:
            closes = operation in ["close", "burn"]
            parameters = "input: Private<spr_circuit::protocol::Utxo>, state: Private<u64>"
            if unique:
                parameters += ", address: Private<Field>"
            if operation == "update":
                parameters += ", updated: Private<u64>"
            if closes:
                parameters += ", account: Private<Account>"
            if not closes or (unique and operation == "close"):
                parameters += ", blinding: Private<Field>"
            arguments = "&input, &address, &state" if unique else "&input, &state"
            mutable = "mut " if operation != "spend" else ""
            body = f'let {mutable}state_utxo = spr_circuit::protocol::{ty}::new_mut({arguments}).expect("spend state");\n'
            if operation == "update":
                body += "    *state_utxo = updated;\n"
            if closes:
                body += '    state_utxo.withdraw_all(&account.bytes).expect("empty state balance");\n'
                body += f"    let state_utxo = state_utxo.{operation}();\n"
            access = "state_utxo.data_utxo()" if unique else "state_utxo"
            body += f'''    let spent = {access}.spent_input().expect("spent state");
    let mut public_transfers = Field::zero();
    for transfer in {access}.public_transfers() {{
        public_transfers += transfer.hash().expect("public transfer hash");
    }}
    let transferred = *{access}.transferred();
'''
            if not closes or (unique and operation == "close"):
                body += f'''    let output = {access}.output().expect("state output").expect("live output");
    let output_hash = output.hash(false, blinding, 0).expect("state UTXO hash");
'''
            else:
                body += f'''    require({access}.output().expect("closed state").is_none());
    let output_hash = Field::zero();
'''
            body += "    let result = [spent.hash, output_hash, public_transfers, transferred];"
            name = f"{prefix}_{operation}"
            tests = state_update_tests(name, unique) if operation == "update" else ""
            cases.append(Case(name, "State lifecycle", parameters, body, 4,
                              account_definition if closes else "", tests))
    return cases


def state_update_tests(name, unique):
    ty = "UniqueDataUtxo" if unique else "DataUtxo"
    initialization = ('spr_circuit::protocol::UniqueDataUtxo::<u64>::new_init(&owner, &Field::from(19u64)).expect("unique state")'
                      if unique else 'spr_circuit::protocol::DataUtxo::<u64>::new_init(&owner)')
    address = "    let address = initial.address();\n" if unique else ""
    access = ".data_utxo()" if unique else ""
    arguments = "&input, &address, &7u64" if unique else "&input, &7u64"
    bad_arguments = "&input, &address, &8u64" if unique else "&input, &8u64"
    circuit_arguments = "input, 7, address, 9, blinding" if unique else "input, 7, 9, blinding"
    bad_circuit_arguments = "input, 8, address, 9, blinding" if unique else "input, 8, 9, blinding"
    return f'''#[cfg(test)]
mod tests {{
    use super::*;
    use spr_circuit::protocol::UtxoTrait;
    #[test]
    fn state_update_matches_native_and_rejects_wrong_state_or_hash() {{
        let owner = spr_circuit::UtxoOwner::default();
        let asset = [23u8; 32];
        let mut initial = {initialization}.with_asset(&asset).expect("state asset");
        *initial = 7;
        initial.deposit(&11, &[29; 32]).expect("fund state");
{address}        let input = spr_circuit::protocol::Utxo {{
            owner, asset, amount: 11, blinding: Field::from(13u64),
            data_hash: initial{access}.output().expect("initial output").expect("live").data_hash,
            ..spr_circuit::protocol::Utxo::default()
        }};
        let blinding = Field::from(17u64);
        let mut updated = spr_circuit::protocol::{ty}::new_mut({arguments}).expect("native spend");
        *updated = 9;
        let output = updated{access}.output().expect("updated output").expect("live");
        let expected = [input.hash().expect("input hash"), output.hash(false, blinding, 0).expect("output hash"), Field::zero(), Field::zero()];
        {name}({circuit_arguments}, expected).expect("valid compiled update");
        let mut wrong_hash = expected;
        wrong_hash[1] += Field::one();
        assert!({name}({circuit_arguments}, wrong_hash).is_err());
        assert!({name}({bad_circuit_arguments}, expected).is_err());
        assert!(std::panic::catch_unwind(|| spr_circuit::protocol::{ty}::new_mut({bad_arguments})).is_err());
    }}
}}'''


def ordering_cases():
    definitions = f'''extern crate alloc;
use spr_circuit::protocol::SpentInput;
#[path = {json.dumps(str(ROOT / 'sdk-libs/circuit/src/protocol/input_order.rs'))}]
mod input_order;
#[input]
pub struct OrderInput {{ pub hash: Field, pub meta: spr_circuit::protocol::UtxoMeta, pub dummy: bool }}'''
    return [Case(f"input_order_{length}", "Input ordering", f"input: Private<[OrderInput; {length}]>", f'''
    let slots = input.iter().map(|slot| (SpentInput {{ hash: slot.hash, meta: slot.meta }}, slot.dummy)).collect();
    let ordered = input_order::ordered_inputs(slots);
    let mut result = [Field::zero(); {length * 4}];
    for (index, slot) in ordered.iter().enumerate() {{
        result[index * 4] = slot.hash;
        result[index * 4 + 1] = slot.meta.nullifier;
        result[index * 4 + 2] = Field::from(slot.meta.latest_tree_id);
        result[index * 4 + 3] = Field::from(slot.meta.has_latest_tree_id);
    }}''', length * 4, definitions, ordering_tests(length) if length == 5 else "") for length in [1, 2, 5, 10]]


def ordering_tests(length):
    return f'''#[cfg(test)]
mod tests {{
    use super::*;
    #[test]
    fn all_dummy_patterns_preserve_stable_order_and_metadata() {{
        for pattern in 0..(1usize << {length}) {{
            let input: [OrderInput; {length}] = core::array::from_fn(|index| OrderInput {{
                hash: Field::from(index as u64 + 1),
                meta: spr_circuit::protocol::UtxoMeta {{ nullifier: Field::from(index as u64 + 101), latest_tree_id: index as u16 + 301,
                    has_latest_tree_id: index % 2 == 0 }},
                dummy: pattern & (1 << index) != 0,
            }});
            let mut expected = [Field::zero(); {length * 4}];
            for (position, slot) in input.iter().filter(|slot| !slot.dummy)
                .chain(input.iter().filter(|slot| slot.dummy)).enumerate() {{
                expected[position * 4..position * 4 + 4].copy_from_slice(&[
                    slot.hash, slot.meta.nullifier, Field::from(slot.meta.latest_tree_id), Field::from(slot.meta.has_latest_tree_id)
                ]);
            }}
            input_order_{length}(input, expected).expect("stable partition");
            expected[0] += Field::one();
            assert!(input_order_{length}(input, expected).is_err());
        }}
    }}
}}'''


def transaction_tests(length):
    return f'''#[cfg(test)]
mod tests {{
    use super::*;
    #[test]
    fn transaction_hashes_match_native_and_reject_nondefault_rings() {{
        let owner = spr_circuit::UtxoOwner::new(spr_circuit::SigningPubkey::new(0x53, [7; 32]), Field::from(11u64));
        let context = spr_circuit::protocol::TxContext {{ blinding_seed: Field::from(13u64), output_tree_id: 17, uses_output_tree_id: true }};
        for pattern in 1..(1usize << {length}) {{
            let input: [spr_circuit::protocol::Utxo; {length}] = core::array::from_fn(|index| {{
                if pattern & (1 << index) == 0 {{ spr_circuit::protocol::Utxo::dummy() }} else {{
                    spr_circuit::protocol::Utxo {{ owner, asset: [19; 32], amount: index as u64 + 23,
                        blinding: Field::from(index as u64 + 29),
                        meta: spr_circuit::protocol::UtxoMeta {{ nullifier: Field::from(index as u64 + 31), ..Default::default() }},
                        ..spr_circuit::protocol::Utxo::default() }}
                }}
            }});
            let tokens = spr_circuit::protocol::TokenUtxos::new_mut(&input).expect("native tokens");
            let checked = spr_circuit::protocol::ConfidentialTransaction::new(&context, &TransactionPublic).with(tokens).check().expect("native transaction");
            let expected = *checked.public_hash();
            token_transaction_{length}(input, context, expected).expect("compiled transaction");
            assert!(token_transaction_{length}(input, context, expected + Field::one()).is_err());
            if pattern == 1 {{
                for index in [0, {length - 1}] {{
                    for program_id in [false, true] {{
                        let mut invalid = input;
                        if program_id {{ invalid[index].ring_program_id = Field::one(); }}
                        else {{ invalid[index].ring_data_hash = Field::one(); }}
                        assert!(token_transaction_{length}(invalid, context, expected).is_err());
                    }}
                }}
            }}
        }}
    }}
}}'''


def transaction_cases():
    definitions = '''struct TransactionPublic;
impl spr_circuit::protocol::PublicInputs for TransactionPublic {
    fn hash(&self, transaction_hash: &Field) -> Result<Field, spr_circuit::CircuitError> { Ok(*transaction_hash) }
}'''
    return [Case(f"token_transaction_{length}", "Token transactions",
                 f"input: Private<[spr_circuit::protocol::Utxo; {length}]>, context: Private<spr_circuit::protocol::TxContext>", '''
    let tokens = spr_circuit::protocol::TokenUtxos::new_mut(&input).expect("tokens");
    let checked = spr_circuit::protocol::ConfidentialTransaction::new(&context, &TransactionPublic).with(tokens).check().expect("transaction");
    let result = *checked.public_hash();''', definitions=definitions,
                 tests=transaction_tests(length) if length in [1, 5] else "") for length in [1, 2, 5]]


def cases():
    result = [
        Case("field_identity", "Controls", "input: Private<Field>", "let result = input;"),
        Case("u64_identity", "Controls", "input: Private<u64>", "let result = Field::from(input);"),
        Case("constant_scalar_equality", "Equality controls", "input: Private<Field>",
             "require_eq(0u8, 0u8);\n    let result = input;"),
        Case("constant_asset_equality", "Equality controls", "input: Private<Field>",
             "require_eq([0u8; 32], [0u8; 32]);\n    let result = input;"),
        Case("same_wire_asset_equality", "Equality controls", "input: Private<Asset>",
             "require_eq(input.asset, input.asset);\n    let result = Field::from(input.asset[0]);",
             definitions="#[input]\npub struct Asset { pub asset: [u8; 32] }"),
    ]
    result += [Case(f"poseidon_{n}", "Poseidon", f"input: Private<[Field; {n}]>",
                    'let result = spr_circuit::poseidon(&input).expect("poseidon");')
               for n in range(1, 13)]
    result += [Case(f"hash_bytes_{n}", "Byte hashing", "input: Private<Bytes>",
                    'let result = spr_circuit::hash_bytes(&input.bytes).expect("bytes");',
                    definitions=f"#[input]\npub struct Bytes {{ pub bytes: [u8; {n}] }}")
               for n in [0, 1, 16, 31, 32, 33, 62, 63, 64, 96]]
    result += [Case(f"nonzero_chain_{n}", "Nonzero hash chains", f"input: Private<[Field; {n}]>",
                    'let result = spr_circuit::nonzero_hash_chain(&input).expect("chain");',
                    tests=chain_tests(n) if n in [1, 3] else "")
               for n in [0, 1, 2, 3, 5, 10]]
    for name, ty, expression in [
        ("signing_key_identity", "spr_circuit::SigningPubkey", "input.identity()"),
        ("owner_hash", "spr_circuit::UtxoOwner", "input.hash()"),
        ("shielded_address_hash", "spr_circuit::ShieldedAddress", "input.hash()"),
        ("utxo_hash", "spr_circuit::protocol::Utxo", "input.hash()"),
    ]:
        result.append(Case(name, "Owners and UTXOs", f"input: Private<{ty}>",
                           f'let result = {expression}.expect("hash");'))
    result += [
        Case("utxo_hash_with", "Owners and UTXOs",
             "input: Private<spr_circuit::protocol::Utxo>, owner_hash: Private<Field>, asset_hash: Private<Field>",
             'let result = input.hash_with(&owner_hash, &asset_hash).expect("cached hashes");'),
        Case("default_ring", "Owners and UTXOs",
             "data_hash: Private<Field>, program_id: Private<Field>",
             '''let mut input = spr_circuit::protocol::Utxo::default();
    input.ring_data_hash = data_hash;
    input.ring_program_id = program_id;
    input.assert_default_ring().expect("default ring");
    let result = Field::zero();'''),
        Case("public_transfer_hash", "Owners and UTXOs",
             "input: Private<Transfer>",
             '''let transfer = spr_circuit::protocol::PublicTransfer {
        asset: input.asset, account: input.account, amount: input.amount, is_deposit: input.deposit,
    };
    let result = transfer.hash().expect("public transfer");''',
             definitions="#[input]\npub struct Transfer { pub asset: [u8; 32], pub account: [u8; 32], pub amount: u64, pub deposit: bool }"),
        Case("data_output", "State and addresses", "state: Private<u64>",
             '''let mut output = spr_circuit::protocol::DataUtxo::<u64>::new_init(&spr_circuit::UtxoOwner::default());
    *output = state;
    let result = output.output().expect("output").expect("live").data_hash;'''),
    ]
    for operation in ["address", "output", "close"]:
        body = '''let mut output = spr_circuit::protocol::UniqueDataUtxo::<u64>::new_init(&owner, &seed).expect("address");
    *output = state;
'''
        if operation == "address":
            body += "    let result = output.address();"
        elif operation == "output":
            body += '    let result = output.data_utxo().output().expect("output").expect("live").data_hash;'
        else:
            body += '    let result = output.close().data_utxo().output().expect("output").expect("closed marker").data_hash;'
        result.append(Case(f"unique_{operation}", "State and addresses",
                           "owner: Private<spr_circuit::UtxoOwner>, seed: Private<Field>, state: Private<u64>", body))
    result += state_cases()
    for n in [1, 5]:
        result.append(Case(f"array_vec_u64_{n}", "Bounded inputs", f"input: Private<spr_circuit::ArrayVec<u64, {n}>>",
                           '''let mut result = Field::zero();
    for amount in input.padded() { result += Field::from(amount); }'''))
    for n in [1, 2, 5]:
        result.append(Case(f"token_inputs_{n}", "Token aggregation", f"input: Private<[spr_circuit::protocol::Utxo; {n}]>",
                           '''let tokens = spr_circuit::protocol::TokenUtxos::new_mut(&input).expect("tokens");
    let mut hashes = Field::zero();
    for (spent, _) in tokens.spent_inputs() { hashes += spent.hash; }
    let result = [hashes, Field::from(tokens.amount().expect("amount"))];''', 2))
    operations = {
        "baseline": "",
        "deposit": 'destination.deposit(&amount, &[0; 32]).expect("deposit");',
        "transfer": 'source.transfer(&mut destination, &amount).expect("transfer");',
        "transfer_all": 'source.transfer_all(&mut destination).expect("transfer all");',
        "withdraw": 'source.withdraw(&amount, &[0; 32]).expect("withdraw");',
        "withdraw_all": 'source.withdraw_all(&[0; 32]).expect("withdraw all");',
    }
    # Compile the real private Balance implementation in the generated crate.
    # This permits direct initialization without expanding the SDK's public API.
    arithmetic = f'''extern crate alloc;
use spr_circuit::{{CircuitError, UtxoOwner}};
mod protocol {{ pub use spr_circuit::protocol::PublicTransfer; }}
#[path = {json.dumps(str(ROOT / 'sdk-libs/circuit/src/protocol/utxo/balance.rs'))}]
mod isolated_balance;
use isolated_balance::{{Balance, HasBalance, UtxoTrait}};
struct BalanceFixture {{ balance: Balance }}
impl HasBalance for BalanceFixture {{
    fn balance(&self) -> &Balance {{ &self.balance }}
    fn balance_mut(&mut self) -> &mut Balance {{ &mut self.balance }}
    fn is_closed(&self) -> bool {{ false }}
}}'''
    for operation, expression in operations.items():
        result.append(Case(f"balance_{operation}", "Balances", "initial: Private<u64>, amount: Private<u64>", f'''
    let _ = &amount;
    let owner = spr_circuit::UtxoOwner::default();
    let mut source = spr_circuit::protocol::TokenUtxos::new_init(&owner, &[0; 32]);
    let mut destination = spr_circuit::protocol::TokenUtxos::new_init(&owner, &[0; 32]);
    source.deposit(&initial, &[0; 32]).expect("fund source");
    {expression}
    let result = [Field::from(source.amount().expect("source")), Field::from(destination.amount().expect("destination"))];''', 2))
        result.append(Case(f"balance_arithmetic_{operation}", "Balance arithmetic",
                           "initial: Private<u128>, received: Private<u128>, amount: Private<u64>", f'''
    let _ = &amount;
    let owner = UtxoOwner::default();
    let mut source = BalanceFixture {{ balance: Balance::new(owner, [0; 32], initial) }};
    let mut destination = BalanceFixture {{ balance: Balance::new(owner, [0; 32], received) }};
    {expression}
    let result = [Field::from(source.balance.amount), Field::from(destination.balance.amount)];''',
                           2, arithmetic))
        result.append(Case(f"balance_complete_{operation}", "Balances with protocol outputs",
                           "initial: Private<u64>, amount: Private<u64>, blinding: Private<[Field; 2]>", f'''
    let _ = &amount;
    let owner = spr_circuit::UtxoOwner::default();
    let mut source = spr_circuit::protocol::TokenUtxos::new_init(&owner, &[0; 32]);
    let mut destination = spr_circuit::protocol::TokenUtxos::new_init(&owner, &[0; 32]);
    source.deposit(&initial, &[0; 32]).expect("fund source");
    {expression}
    let mut public_transfers = Field::zero();
    for transfer in source.public_transfers().iter().chain(destination.public_transfers()) {{
        public_transfers += transfer.hash().expect("public transfer hash");
    }}
    let source_transferred = *source.transferred();
    let destination_transferred = *destination.transferred();
    let source_output = source.change().expect("source change").expect("source output");
    let destination_output = destination.change().expect("destination change").expect("destination output");
    let source_hash = source_output.hash(source_output.is_zero(), blinding[0], 0).expect("source hash");
    let destination_hash = destination_output.hash(destination_output.is_zero(), blinding[1], 0).expect("destination hash");
    let result = [source_hash, destination_hash, public_transfers, source_transferred, destination_transferred];''', 5))
        private_body = result[-1].body.replace('    let owner = spr_circuit::UtxoOwner::default();\n', '')
        private_body = private_body.replace('new_init(&owner, &[0; 32]);', 'new_init(&parties.source_owner, &parties.asset);', 1)
        private_body = private_body.replace('new_init(&owner, &[0; 32]);', 'new_init(&parties.destination_owner, &parties.asset);', 1)
        private_body = private_body.replace('&[0; 32]', '&parties.account')
        result.append(Case(f"balance_private_{operation}", "Private balances with protocol outputs",
                           "initial: Private<u64>, amount: Private<u64>, blinding: Private<[Field; 2]>, parties: Private<Parties>",
                           private_body, 5, """#[input]
pub struct Parties {
    pub source_owner: spr_circuit::UtxoOwner,
    pub destination_owner: spr_circuit::UtxoOwner,
    pub asset: [u8; 32],
    pub account: [u8; 32],
}"""))
    return result + ordering_cases() + transaction_cases()


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, text=True, **kwargs)


def write_changed(path, text):
    if not path.exists() or path.read_text() != text:
        path.write_text(text)


def source(case):
    output = "Field" if case.outputs == 1 else f"[Field; {case.outputs}]"
    binding = "require_eq(result, expected);" if case.outputs == 1 else "\n    ".join(
        f"require_eq(result[{i}], expected[{i}]);" for i in range(case.outputs))
    balance_import = case.group in ['Balances', 'Balances with protocol outputs', 'Private balances with protocol outputs', 'Token aggregation']
    balance_import |= case.group == "State lifecycle" and case.name.endswith(("close", "burn"))
    return f'''use xark::prelude::*;
{('use spr_circuit::protocol::UtxoTrait;' if balance_import else '')}
{case.definitions}
#[circuit]
pub fn {case.name}({case.parameters}, expected: Public<{output}>) {{
    {case.body.strip()}
    {binding}
}}
{case.tests}
'''


def fingerprint():
    digest = hashlib.sha256()
    crate = ROOT / "sdk-libs/circuit"
    for path in sorted([*crate.joinpath("src").rglob("*.rs"), crate / "build.rs", crate / "Cargo.toml", ROOT / "Cargo.lock"]):
        digest.update(path.relative_to(ROOT).as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return digest.hexdigest()


def profile(case, output, xark, checkout):
    crate = output / "cases" / case.name
    artifacts = output / "profiles" / case.name
    crate.joinpath("src").mkdir(parents=True, exist_ok=True)
    write_changed(crate / "Cargo.toml", f'''[package]
name = "spr-primitive-{case.name.replace('_', '-')}"
version = "0.0.0"
edition = "2024"
publish = false
[workspace]
[lib]
crate-type = ["cdylib", "rlib"]
[dependencies]
xark = {{ path = {json.dumps(str(checkout / 'crates/lang'))} }}
spr-circuit = {{ path = {json.dumps(str(ROOT / 'sdk-libs/circuit'))} }}
[lints.rust]
unexpected_cfgs = {{ level = "warn", check-cfg = ['cfg(xark)', 'cfg(xark_client)'] }}
''')
    write_changed(crate / "src/lib.rs", source(case))
    lock_hash = hashlib.sha256(ROOT.joinpath("Cargo.lock").read_bytes()).hexdigest()
    stamp = crate / ".workspace-lock-sha256"
    if not stamp.exists() or stamp.read_text() != lock_hash:
        shutil.copyfile(ROOT / "Cargo.lock", crate / "Cargo.lock")
        stamp.write_text(lock_hash)
    shared = output / "cases/field_identity/target"
    shared.mkdir(parents=True, exist_ok=True)
    target = crate / "target"
    if not target.exists():
        target.symlink_to(shared, target_is_directory=True)
    with output.joinpath(f"{case.name}.log").open("w") as log:
        command = [str(xark), "profile", str(crate), "--out", str(artifacts), "--json"]
        completed = run(command, stdout=subprocess.PIPE, stderr=log)
    summary = json.loads(completed.stdout)
    output.joinpath(f"{case.name}.json").write_text(json.dumps(summary, indent=2) + "\n")
    total = summary["total"]
    assert sum(row["count"] for row in summary["kinds"]) == total
    assert sum(row["total"] for row in summary["lines"]) == total
    input_line = source(case).splitlines().index("#[circuit]") + 1
    inputs = sum(row["total"] for row in summary["lines"] if row["file"] == "src/lib.rs" and row["line"] == input_line)
    binding_lines = [row for row in summary["lines"]
                     if row["file"] == "src/lib.rs" and row["src"].strip().startswith("require_eq(result")]
    if len(binding_lines) != case.outputs or any(row["total"] < 1 for row in binding_lines):
        raise ValueError(f"{case.name}: missing explicit output bindings")
    bindings = case.outputs
    body = total - inputs - bindings
    print(f"{case.name}: total={total} inputs={inputs} body={body} binding={bindings}", flush=True)
    return {"name": case.name, "group": case.group, "total": total, "inputs": inputs,
            "body": body, "bindings": bindings, "kinds": {row["kind"]: row["count"] for row in summary["kinds"]}}


def report(rows, metadata):
    lines = ["# Circuit primitive constraint benchmarks", "",
             "Each case profiles one primitive or public API operation implemented in `spr-circuit`, using `xark profile --json`.", "",
             "## Snapshot", "", f"Recorded on {metadata['date']} with BN254.", "",
             f"- SDK revision: `{metadata['sdk']}`" + (" with working-tree circuit changes." if metadata['source_dirty'] else "."), f"- Xark CLI: `{metadata['xark']}`.",
             f"- Xark checkout: `{metadata['checkout']}`.", f"- Circuit source/dependency SHA-256: `{metadata['source_hash']}`.", "",
             "Input rows are checks emitted at `#[circuit]`, including ranges and reconstruction. Each explicit field-output equality contributes one binding row (tagged Equality or Mul by Xark); deferred result materialization stays in the body cost. Body rows are `total - inputs - bindings`, including callees. These are compiler R1CS counts before proving-key setup.", ""]
    groups = list(dict.fromkeys(row["group"] for row in rows))
    for group in groups:
        lines += [f"## {group}", "", "| Case | Body | Input rows | Binding rows | Constraints |", "| --- | ---: | ---: | ---: | ---: |"]
        for row in rows:
            if row["group"] == group:
                lines.append(f"| `{row['name']}` | {row['body']:,} | {row['inputs']:,} | {row['bindings']:,} | {row['total']:,} |")
        lines.append("")
    lines += ["## Incremental balance costs", "",
              "Each column subtracts its own baseline. Amount-only cases include funding and balance-read checks; arithmetic cases initialize the real Balance implementation directly; complete cases retain protocol outputs, with constant or private owners/assets/accounts as labeled. Complete deltas include changes to output emptiness; an operation can reduce cost when its empty output skips owner/asset hashing.", "",
              "| Operation | Amount-only delta | Arithmetic delta | Complete delta | Private complete delta |", "| --- | ---: | ---: | ---: | ---: |"]
    by_name = {row["name"]: row["body"] for row in rows}
    for operation in ["deposit", "transfer", "transfer_all", "withdraw", "withdraw_all"]:
        deltas = [by_name[f"{prefix}_{operation}"] - by_name[f"{prefix}_baseline"]
                  for prefix in ["balance", "balance_arithmetic", "balance_complete", "balance_private"]]
        lines.append(f"| `{operation}` | " + " | ".join(f"{delta:,}" for delta in deltas) + " |")
    lines += ["", "## Optimization comparison", "",
              "Before: SDK `aae7ddec2`, Xark CLI `38c0de6fec56`. After: the snapshot above. Ordering and transaction cases were added before changing their implementations; ordering originally used the same function body from transaction.rs. All values below exclude input rows and output bindings.", "",
              "| Case | Before body | After body | Saved |", "| --- | ---: | ---: | ---: |"]
    for name, before in [("constant_asset_equality", 32), ("balance_arithmetic_deposit", 341),
                         ("balance_arithmetic_transfer", 504), ("balance_arithmetic_withdraw", 138),
                         ("token_inputs_5", 6622), ("token_transaction_5", 9863),
                         ("input_order_5", 526), ("input_order_10", 274130)]:
        after = by_name[name]
        lines.append(f"| `{name}` | {before:,} | {after:,} | {before - after:,} |")
    lines += ["", "Default-ring spending still validates both supplied ring fields, then hashes their known zero values. Native integer operations share an unconditional borrow/remainder proof in Xark; overflow, underflow and immediate u64 debit narrowing remain enforced. Stable input ordering swaps the records conditionally and updates dummy flags directly using AND/OR. It still performs a quadratic number of adjacent comparisons.", "",
              "Explicit SDK owner/asset hash caches were tested and removed: they saved only one row in the five-input transaction after ring specialization. Xark already reuses identical Poseidon multiplication products across calls. No extra cache fields or public cache API are needed.", ""]
    kinds = sorted({kind for row in rows for kind in row["kinds"]},
                   key=lambda kind: (-sum(row["kinds"].get(kind, 0) for row in rows), kind))
    lines += ["", "## Constraint kinds (total rows)", "",
              "These totals include input checks and output bindings. Function call chains and source-line attribution are retained in each case's JSON.", "",
              "| Case | " + " | ".join(kinds) + " |",
              "| --- | " + " | ".join("---:" for _ in kinds) + " |"]
    for row in rows:
        counts = " | ".join(f"{row['kinds'].get(kind, 0):,}" for kind in kinds)
        lines.append(f"| `{row['name']}` | {counts} |")
    lines.append("")
    lines += ["## Reading the cases", "",
              "Poseidon varies the input arity from 1 through 12. `hash_bytes` packs up to 31 bytes directly into one big-endian field element without a Poseidon permutation (empty input returns zero). Each further chunk adds one two-input Poseidon permutation. This is a fixed-length encoding: length is not absorbed, so leading-zero aliases across different lengths must be separated by the caller's domain.", "",
              "Nonzero chains use private values, so zero/nonzero selection is included. Initializing from the first element removes the unnecessary first selection/permutation: the one-element case previously cost 245 body rows. Owner and UTXO cases keep their protocol inputs private; `utxo_hash_with` receives precomputed owner/asset hashes.", "",
              "Bounded-input cases sum the padded u64 slots with field additions. Token aggregation exposes the sum of spent-input hashes to retain their computation. Unique-address output cases include address initialization and expose data hashes, rather than full output UTXO hashes.", "",
              "The amount-only balance baseline funds a source and reads both balances. Arithmetic cases include the SDK's actual private `balance.rs` by path in the generated crate, using a minimal HasBalance fixture to initialize two private u128 balances directly. They remove token setup, funding, hashing and amount-read narrowing, while retaining the API's validation, overflow/borrow checks, and asset checks. Public-transfer records and transferred counters are unused in arithmetic cases.", "",
              "Complete balance cases retain both output UTXO hashes, the sum of all public-transfer record hashes (including the funding deposit), and both transferred counters. Private blindings prevent output hashes from becoming constants; tree IDs are zero. These cover token outputs and records, rather than a full transaction proof. The owner, asset and public-transfer account are constants in these original complete cases. `balance_private_*` repeats each operation with two private owners and private asset/account bytes, retaining the same output UTXO hashes, record hashes and transferred counters.", "",
              "State lifecycle cases spend private UTXOs whose private state preimages must match their stored data hashes. Spend cases preserve state; update cases replace the private u64 state. Every case retains the spent-input hash. Live outputs and unique close markers expose full output UTXO hashes with private blindings. Close/burn cases withdraw the entire input balance to a private account first, retaining all public-transfer hashes; ordinary close and unique burn assert that no output remains. These cases exclude address creation, encryption and transaction aggregation.", "",
              "Input-order cases retain every ordered hash, nullifier, latest tree ID and availability flag, including dummy slots, so the measurement covers metadata movement and stable ordering. Capacities are 1, 2, 5 and 10; a 20-slot experiment was stopped because symbolic selection compilation remained expensive and is not included as a completed measurement. Token-transaction cases retain the complete private transaction hash for private input UTXOs and a private context; the public-input wrapper returns that hash directly to isolate SDK transaction assembly.", "",
              "## Xark equality finding", "",
              "The baseline equality controls retained one body row for equal constant scalars and 32 for identical assets or the same private asset wire. The array RequireEqCircuit implementation dispatches each byte to the scalar intrinsic. Xark now skips identically-zero differences in `crates/frontend/src/builder.rs::emit_require_eq`, matching the existing gated behavior. All three controls now have zero body rows. SDK asset validation remains in place; distinct private wires still require equality, and unequal constants remain unsatisfiable.", "",
              "## Reproduce", "", "From the workspace root, set `XARK_SOURCE` to the dependency checkout and place the matching `xark` CLI on `PATH`:", "", "```sh",
              "python3 sdk-libs/circuit/benches/profile_primitives.py --write-report", "```", "",
              "Run one case or inspect its source/function/kind breakdown:", "", "```sh",
              "python3 sdk-libs/circuit/benches/profile_primitives.py --case poseidon_2",
              "xark profile target/benchmarks/spr-circuit/cases/poseidon_2 \\",
              "  --out target/benchmarks/spr-circuit/profiles/poseidon_2",
              "jq '{total, kinds, functions, lines}' target/benchmarks/spr-circuit/poseidon_2.json", "```", "",
              "The one- and three-element chain cases also generate compiled-circuit acceptance tests for every zero/nonzero position pattern, rejecting a changed expected hash:", "", "```sh",
              "xark test target/benchmarks/spr-circuit/cases/nonzero_chain_1",
              "xark test target/benchmarks/spr-circuit/cases/nonzero_chain_3", "```", "",
              "The data/unique state-update cases generate native-versus-compiled acceptance tests, including rejection of a wrong state preimage or output hash:", "", "```sh",
              "xark test target/benchmarks/spr-circuit/cases/data_state_update",
              "xark test target/benchmarks/spr-circuit/cases/unique_state_update", "```", "",
              "Ordering tests cover every five-slot dummy pattern and all metadata. Transaction tests compare native/compiled hashes across every nonempty real/dummy pattern and reject changed hashes or either nondefault ring field in real and dummy slots:", "", "```sh",
              "xark test target/benchmarks/spr-circuit/cases/input_order_5",
              "xark test target/benchmarks/spr-circuit/cases/token_transaction_1",
              "xark test target/benchmarks/spr-circuit/cases/token_transaction_5", "```", "",
              "Generated entrypoint crates, raw per-constraint profiles and aggregated JSON stay under `target/benchmarks/spr-circuit/`. No proving keys are generated. Function counts include callees and overlap. Source attribution currently refers to the generated entrypoint lines; the call chains identify primitive internals.", "",
              "Full escrow/withdraw circuit profiles belong in [`sdk-tests/timelock-escrow/program/benches/BENCHMARKS.md`](../../../sdk-tests/timelock-escrow/program/benches/BENCHMARKS.md).", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--case", action="append", choices=[case.name for case in cases()])
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--out", type=Path, default=ROOT / "target/benchmarks/spr-circuit")
    parser.add_argument("--write-report", action="store_true")
    args = parser.parse_args()
    if args.list:
        print("\n".join(case.name for case in cases()))
        return
    if args.case and args.write_report:
        parser.error("--write-report requires the full case matrix")
    checkout = ROOT / ".tools/xark"
    selected_checkout = Path(os.environ.get("XARK_SOURCE", str(checkout))).expanduser()
    if selected_checkout.resolve() != checkout.resolve():
        parser.error("XARK_SOURCE must match the workspace's .tools/xark dependency")
    if not checkout.joinpath("crates/lang/Cargo.toml").is_file():
        parser.error("set XARK_SOURCE to the matching Xark checkout")
    binary = shutil.which("xark") or checkout / "target/release/xark"
    if not Path(binary).is_file():
        parser.error("build the matching Xark CLI or put it on PATH")
    output = args.out.resolve()
    output.mkdir(parents=True, exist_ok=True)
    before = fingerprint()
    source_dirty = subprocess.run(["git", "diff", "--quiet", "HEAD", "--", "sdk-libs/circuit/src", "sdk-libs/circuit/build.rs"], cwd=ROOT).returncode != 0
    selected = [case for case in cases() if not args.case or case.name in args.case]
    rows = []
    for case in selected:
        rows.append(profile(case, output, binary, checkout))
        if fingerprint() != before:
            raise RuntimeError("circuit sources changed during profiling; rerun the matrix")
    metadata = {"date": str(date.today()), "sdk": run(["git", "rev-parse", "HEAD"], cwd=ROOT, stdout=subprocess.PIPE).stdout.strip(),
                "xark": run([str(binary), "--version"], stdout=subprocess.PIPE).stdout.strip(),
                "checkout": run(["git", "rev-parse", "HEAD"], cwd=checkout, stdout=subprocess.PIPE).stdout.strip(), "source_hash": before,
                "source_dirty": source_dirty, "workspace_lock_sha256": hashlib.sha256(ROOT.joinpath("Cargo.lock").read_bytes()).hexdigest()}
    output.joinpath("summary.json").write_text(json.dumps({"metadata": metadata, "cases": rows}, indent=2) + "\n")
    if args.write_report:
        BENCHES.joinpath("BENCHMARKS.md").write_text(report(rows, metadata))


if __name__ == "__main__":
    main()
