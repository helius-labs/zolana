/**
 * The on-page benchmark output.
 *
 * Every row carries the prover it was measured with, because a remote number and
 * a local-wasm number answer different questions and a table that blends them is
 * misleading. Failed runs stay in the table with their error rather than
 * disappearing -- a shape that cannot prove locally is the most interesting
 * result the sweep can produce.
 */

import { Fragment } from "react";

import type { Measurement, RunResult, StepName } from "@zolana/poc-core";
import { formatBytes, formatMs, proveMs } from "@zolana/poc-core";

const STEP_LABELS: Readonly<Record<StepName, string>> = {
  "poseidon-init": "Poseidon init",
  "key-fetch": "Key fetch",
  "key-load": "Key deserialize",
  "wallet-sync": "Wallet sync",
  "shield-build": "Shield build",
  "shield-submit": "Shield",
  "transfer-build": "Split (fan-out)",
  "transfer-prove": "Transfer prove",
  "transfer-submit": "Transfer",
  "unshield-build": "Unshield build",
  "unshield-prove": "Unshield prove",
  "unshield-submit": "Unshield",
};

function StepRows({ measurements }: { measurements: readonly Measurement[] }): React.ReactElement {
  return (
    <>
      {measurements.map((measurement, index) => (
        <tr key={`${measurement.step}-${String(index)}`} className="step">
          <td className="indent">{STEP_LABELS[measurement.step]}</td>
          <td className="num">{formatMs(measurement.ms)}</td>
          <td className="num">
            {measurement.bytes === undefined ? "" : formatBytes(measurement.bytes)}
          </td>
          <td className="note">{measurement.note ?? ""}</td>
        </tr>
      ))}
    </>
  );
}

export function BenchTable({
  runs,
  expanded,
}: {
  runs: readonly RunResult[];
  expanded: boolean;
}): React.ReactElement {
  if (runs.length === 0) {
    return <p className="empty">No runs yet.</p>;
  }
  return (
    <table className="bench">
      <thead>
        <tr>
          <th>Shape / step</th>
          <th className="num">Time</th>
          <th className="num">Bytes</th>
          <th>Detail</th>
        </tr>
      </thead>
      <tbody>
        {runs.map((run, index) => {
          const proving = proveMs(run);
          return (
            <Fragment key={`${run.shape}-${run.prover}-${String(index)}`}>
              <tr className={run.ok ? "run" : "run failed"}>
                <td>
                  <strong>{run.shape}</strong> <span className="tag">{run.prover}</span>
                </td>
                <td className="num">
                  <strong>{formatMs(run.totalMs)}</strong>
                </td>
                <td className="num">{proving > 0 ? `${formatMs(proving)} proving` : ""}</td>
                <td className="note">
                  {run.ok ? `${String(run.measurements.length)} steps` : (run.error ?? "failed")}
                </td>
              </tr>
              {expanded ? <StepRows measurements={run.measurements} /> : undefined}
            </Fragment>
          );
        })}
      </tbody>
    </table>
  );
}
