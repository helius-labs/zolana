import { RingError } from "./error.js";

export function checkRingElf(bytes: Uint8Array): void {
  const invalid = () => new RingError("RING_PROGRAM_BINARY_INVALID");
  if (!(bytes instanceof Uint8Array) || bytes.length < 64) throw invalid();
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (
    view.getUint32(0, false) !== 0x7f454c46 ||
    bytes[4] !== 2 ||
    bytes[5] !== 1 ||
    bytes[6] !== 1 ||
    bytes[7] !== 0 ||
    view.getUint16(16, true) !== 3 ||
    ![247, 263].includes(view.getUint16(18, true)) ||
    view.getUint32(20, true) !== 1 ||
    view.getUint16(52, true) !== 64
  ) {
    throw invalid();
  }

  const range = (offset: bigint, length: bigint): number => {
    if (offset + length > BigInt(bytes.length)) throw invalid();
    return Number(offset);
  };
  const programs = view.getUint16(56, true);
  const sections = view.getUint16(60, true);
  const programOffset = view.getBigUint64(32, true);
  const sectionOffset = view.getBigUint64(40, true);
  const sectionNames = view.getUint16(62, true);
  if (
    programs === 0 ||
    programOffset < 64n ||
    view.getUint16(54, true) !== 56 ||
    (sections !== 0 && (sectionOffset < 64n || view.getUint16(58, true) !== 64)) ||
    (sections === 0 ? sectionNames !== 0 : sectionNames >= sections)
  ) {
    throw invalid();
  }
  const programStart = range(programOffset, BigInt(programs) * 56n);
  const sectionStart = range(sectionOffset, BigInt(sections) * 64n);
  let executable = false;
  for (let index = 0; index < programs; index += 1) {
    const start = programStart + index * 56;
    const length = view.getBigUint64(start + 32, true);
    range(view.getBigUint64(start + 8, true), length);
    if (
      view.getUint32(start, true) === 1 &&
      (view.getUint32(start + 4, true) & 1) !== 0 &&
      length !== 0n
    ) {
      executable = true;
    }
  }
  if (!executable) throw invalid();
  for (let index = 0; index < sections; index += 1) {
    const start = sectionStart + index * 64;
    // SHT_NOBITS occupies memory without bytes in the artifact.
    if (view.getUint32(start + 4, true) !== 8) {
      range(view.getBigUint64(start + 24, true), view.getBigUint64(start + 32, true));
    }
  }
}
