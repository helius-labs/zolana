use zolana_client::ProofInputUtxo;
use zolana_gnark_ffi_prover::{decimal, utxo_proof_inputs, ProofInputMap};

pub trait ProofInputs {
    fn write(&self, writer: &mut ProofInputWriter<'_>);
}

pub struct ProofInputWriter<'a> {
    prefix: String,
    map: &'a mut ProofInputMap,
}

impl ProofInputWriter<'_> {
    pub fn field(&mut self, name: &str, value: &[u8; 32]) {
        self.map.insert(self.key(name), vec![decimal(value)]);
    }

    pub fn u64(&mut self, name: &str, value: u64) {
        let mut field = [0u8; 32];
        if let Some(low_bytes) = field.last_chunk_mut::<8>() {
            *low_bytes = value.to_be_bytes();
        }
        self.field(name, &field);
    }

    pub fn fields(&mut self, name: &str, values: &[[u8; 32]]) {
        self.map
            .insert(self.key(name), values.iter().map(decimal).collect());
    }

    pub fn nested(&mut self, name: &str, inputs: &impl ProofInputs) {
        let mut writer = ProofInputWriter {
            prefix: self.key(name),
            map: self.map,
        };
        inputs.write(&mut writer);
    }

    fn key(&self, name: &str) -> String {
        if self.prefix.is_empty() {
            name.to_string()
        } else {
            format!("{}_{name}", self.prefix)
        }
    }
}

pub fn proof_input_map(inputs: &impl ProofInputs) -> ProofInputMap {
    let mut map = ProofInputMap::new();
    inputs.write(&mut ProofInputWriter {
        prefix: String::new(),
        map: &mut map,
    });
    map
}

impl ProofInputs for ProofInputUtxo {
    fn write(&self, writer: &mut ProofInputWriter<'_>) {
        let entries = utxo_proof_inputs(self, &writer.prefix);
        writer.map.extend(entries.into_iter().map(|(key, values)| {
            let key = key.strip_prefix('_').map(str::to_string).unwrap_or(key);
            (key, values)
        }));
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use zolana_gnark_ffi_prover::utxo_proof_input_keys;

    use super::*;

    struct Inner {
        value: [u8; 32],
        path: [[u8; 32]; 2],
        utxo: ProofInputUtxo,
    }

    impl ProofInputs for Inner {
        fn write(&self, writer: &mut ProofInputWriter<'_>) {
            writer.field("Value", &self.value);
            writer.fields("Path", &self.path);
            writer.nested("Utxo", &self.utxo);
        }
    }

    struct Outer {
        top: u64,
        inner: Inner,
    }

    impl ProofInputs for Outer {
        fn write(&self, writer: &mut ProofInputWriter<'_>) {
            writer.u64("Top", self.top);
            writer.nested("Inner", &self.inner);
        }
    }

    #[test]
    fn nested_fields_join_their_path_with_underscores() {
        let mut value = [0u8; 32];
        value[31] = 7;
        let map = proof_input_map(&Outer {
            top: 300,
            inner: Inner {
                value,
                path: [[0u8; 32], value],
                utxo: ProofInputUtxo::default(),
            },
        });

        let mut expected: BTreeSet<String> = [
            "Top".to_string(),
            "Inner_Value".to_string(),
            "Inner_Path".to_string(),
        ]
        .into();
        expected.extend(utxo_proof_input_keys("Inner_Utxo"));
        assert_eq!(
            (
                map.keys().cloned().collect::<BTreeSet<String>>(),
                map.get("Top").cloned(),
                map.get("Inner_Value").cloned(),
                map.get("Inner_Path").cloned(),
            ),
            (
                expected,
                Some(vec!["300".to_string()]),
                Some(vec!["7".to_string()]),
                Some(vec!["0".to_string(), "7".to_string()]),
            )
        );
    }

    #[test]
    fn a_utxo_at_the_root_writes_its_bare_field_names() {
        let keys: BTreeSet<String> = proof_input_map(&ProofInputUtxo::default())
            .keys()
            .cloned()
            .collect();

        assert_eq!(
            keys,
            [
                "Domain",
                "Owner",
                "Asset",
                "Amount",
                "Blinding",
                "DataHash",
                "RingDataHash",
                "RingProgramID",
                "TreeID"
            ]
            .into_iter()
            .map(str::to_string)
            .collect::<BTreeSet<String>>()
        );
    }
}
