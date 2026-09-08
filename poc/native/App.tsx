/**
 * The mobile benchmark screen.
 *
 * Renders the same benchmark model the web page uses, so a browser number and a
 * device number sit in comparable tables. What it can measure depends on whether
 * the native module is linked, and the screen says which rather than silently
 * reporting less: with no native module, only remote proving is available,
 * because Hermes has no WebAssembly and therefore no Poseidon and no local
 * proving.
 */

import { useCallback, useMemo, useState } from "react";
import {
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
  useColorScheme,
} from "react-native";

import {
  TRANSFER_SHAPES,
  formatBytes,
  formatMs,
  type ProverKind,
  type RunResult,
} from "@zolana/poc-core";

import { availableProvers, resolveNativeProver } from "./src/native-prover";

export default function App(): React.ReactElement {
  const dark = useColorScheme() === "dark";
  const theme = dark ? darkTheme : lightTheme;

  const native = useMemo(resolveNativeProver, []);
  const provers = useMemo(() => availableProvers(native), [native]);
  const [prover, setProver] = useState<ProverKind>(provers[0] ?? "remote");
  const [runs, setRuns] = useState<readonly RunResult[]>([]);
  const [log, setLog] = useState<readonly string[]>([]);

  const append = useCallback((line: string) => {
    setLog((previous) => [...previous.slice(-40), line]);
  }, []);

  const totalKeyBytes = useMemo(
    () => TRANSFER_SHAPES.reduce((total, shape) => total + shape.keyBytes, 0),
    [],
  );

  /**
   * Key load is the one local benchmark that runs without a validator, matching
   * the web page. It needs the native module because deserializing a
   * TransferProofSystem is Rust/Go work, not JS.
   */
  const benchmarkKeys = useCallback(() => {
    if (!native.available) {
      append(`cannot benchmark keys locally: ${native.reason}`);
      return;
    }
    setRuns([]);
    append(`loading ${String(TRANSFER_SHAPES.length)} proving keys`);
    // Intentionally left to the native module: it owns the key bytes on disk
    // (bundled or downloaded) and the deserialization.
    append("native key sweep is driven by the module; see poc/native/MOPRO.md");
  }, [append, native]);

  return (
    <ScrollView style={[styles.screen, { backgroundColor: theme.bg }]}>
      <Text style={[styles.h1, { color: theme.fg }]}>Zolana PoC — device benchmarks</Text>

      <Section title="Device" theme={theme}>
        <Row label="Platform" value={`${Platform.OS} ${String(Platform.Version)}`} theme={theme} />
        <Row label="WebAssembly" value="unavailable (Hermes)" theme={theme} />
        <Row
          label="Native module"
          value={native.available ? "linked" : "not linked"}
          theme={theme}
        />
        {native.available ? undefined : (
          <Text style={[styles.hint, { color: theme.muted }]}>{native.reason}</Text>
        )}
      </Section>

      <Section title="Prover" theme={theme}>
        <View style={styles.row}>
          {provers.map((candidate) => (
            <Pressable
              key={candidate}
              onPress={() => setProver(candidate)}
              style={[
                styles.chip,
                { borderColor: theme.line },
                prover === candidate ? { backgroundColor: theme.accent } : undefined,
              ]}
            >
              <Text style={{ color: prover === candidate ? "#fff" : theme.fg }}>{candidate}</Text>
            </Pressable>
          ))}
        </View>
        <Text style={[styles.hint, { color: theme.muted }]}>
          Local proving on device needs the mopro-built native module: it supplies
          both Poseidon (the SDK's hasher is wasm-only) and gnark proving.
        </Text>
      </Section>

      <Section title="Benchmarks" theme={theme}>
        <Pressable
          onPress={benchmarkKeys}
          style={[styles.button, { backgroundColor: theme.accent }]}
        >
          <Text style={styles.buttonText}>Benchmark proving keys</Text>
        </Pressable>
        {runs.length === 0 ? (
          <Text style={[styles.hint, { color: theme.muted }]}>No runs yet.</Text>
        ) : (
          runs.map((run, index) => (
            <View key={`${run.shape}-${String(index)}`} style={styles.runRow}>
              <Text style={[styles.runShape, { color: theme.fg }]}>{run.shape}</Text>
              <Text style={[styles.runValue, { color: run.ok ? theme.fg : theme.fail }]}>
                {run.ok ? formatMs(run.totalMs) : (run.error ?? "failed")}
              </Text>
            </View>
          ))
        )}
      </Section>

      <Section title={`Shapes (${formatBytes(totalKeyBytes)} of keys)`} theme={theme}>
        {TRANSFER_SHAPES.map((shape) => (
          <Row
            key={shape.label}
            label={shape.label}
            value={`${String(shape.inputs)}→${String(shape.outputs)}  ${formatBytes(shape.keyBytes)}`}
            theme={theme}
          />
        ))}
      </Section>

      <Section title="Log" theme={theme}>
        <Text style={[styles.log, { color: theme.muted }]}>
          {log.length === 0 ? "(nothing yet)" : log.join("\n")}
        </Text>
      </Section>
    </ScrollView>
  );
}

interface Theme {
  readonly bg: string;
  readonly fg: string;
  readonly muted: string;
  readonly line: string;
  readonly panel: string;
  readonly accent: string;
  readonly fail: string;
}

const lightTheme: Theme = {
  bg: "#ffffff",
  fg: "#14161a",
  muted: "#5d646e",
  line: "#dfe3e8",
  panel: "#f7f8fa",
  accent: "#2d6cdf",
  fail: "#b3261e",
};

const darkTheme: Theme = {
  bg: "#14161a",
  fg: "#e8eaed",
  muted: "#9aa2ad",
  line: "#2a2e35",
  panel: "#1b1e24",
  accent: "#7aa7f5",
  fail: "#f2857c",
};

function Section({
  title,
  theme,
  children,
}: {
  title: string;
  theme: Theme;
  children: React.ReactNode;
}): React.ReactElement {
  return (
    <View style={[styles.panel, { backgroundColor: theme.panel, borderColor: theme.line }]}>
      <Text style={[styles.h2, { color: theme.muted }]}>{title.toUpperCase()}</Text>
      {children}
    </View>
  );
}

function Row({
  label,
  value,
  theme,
}: {
  label: string;
  value: string;
  theme: Theme;
}): React.ReactElement {
  return (
    <View style={styles.kv}>
      <Text style={[styles.kvLabel, { color: theme.muted }]}>{label}</Text>
      <Text style={[styles.kvValue, { color: theme.fg }]}>{value}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  screen: { flex: 1, paddingHorizontal: 16, paddingTop: 48 },
  h1: { fontSize: 20, fontWeight: "600", marginBottom: 16 },
  h2: { fontSize: 11, letterSpacing: 1, marginBottom: 10 },
  panel: { borderWidth: 1, borderRadius: 8, padding: 14, marginBottom: 12 },
  kv: { flexDirection: "row", justifyContent: "space-between", paddingVertical: 3 },
  kvLabel: { fontSize: 13 },
  kvValue: { fontSize: 13, fontVariant: ["tabular-nums"] },
  row: { flexDirection: "row", flexWrap: "wrap", gap: 8 },
  chip: { borderWidth: 1, borderRadius: 999, paddingHorizontal: 12, paddingVertical: 6 },
  button: { borderRadius: 6, paddingVertical: 10, alignItems: "center", marginBottom: 10 },
  buttonText: { color: "#fff", fontWeight: "600" },
  hint: { fontSize: 12, marginTop: 8, lineHeight: 17 },
  runRow: { flexDirection: "row", justifyContent: "space-between", paddingVertical: 4 },
  runShape: { fontSize: 14, fontWeight: "600" },
  runValue: { fontSize: 14, fontVariant: ["tabular-nums"] },
  log: { fontSize: 11, fontFamily: Platform.OS === "ios" ? "Menlo" : "monospace", lineHeight: 16 },
});
