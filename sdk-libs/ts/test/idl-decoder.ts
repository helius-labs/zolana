import { getBase58Decoder } from "@solana/kit";
import shieldedPool from "../idl/shieldedPool.json" with { type: "json" };
import userRegistry from "../idl/userRegistry.json" with { type: "json" };

/** Values decoded from the shipped, versioned IDLs. u64 values remain bigint. */
export type DecodedValue =
  | null
  | boolean
  | number
  | bigint
  | string
  | Uint8Array
  | DecodedValue[]
  | { [key: string]: DecodedValue };
export type DecodedFields = { [key: string]: DecodedValue };
export type ProgramName = "shieldedPool" | "userRegistry";

interface WireNode {
  kind: string;
  name?: string;
  type?: WireNode;
  fields?: WireNode[];
  item?: WireNode;
  size?: number | WireNode;
  prefix?: WireNode;
  fixed?: boolean;
  count?: WireNode;
  value?: number;
  number?: number;
  format?: string;
  endian?: string;
  variants?: WireNode[];
  discriminator?: number;
  struct?: WireNode;
  data?: WireNode;
  defaultValue?: WireNode;
  constant?: { type: WireNode; value: WireNode };
  offset?: number;
  arguments?: WireNode[];
  discriminators?: WireNode[];
}
interface WireIdl {
  program: {
    publicKey: string;
    instructions: WireNode[];
    accounts: WireNode[];
    definedTypes?: WireNode[];
  };
}
const idls: Record<ProgramName, WireIdl> = { shieldedPool, userRegistry };

export class IdlDecodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "IdlDecodeError";
  }
}
const required = <T>(value: T | undefined, label: string): T => {
  if (value === undefined) throw new IdlDecodeError(`Missing ${label}`);
  return value;
};

class Reader {
  offset = 0;
  constructor(readonly bytes: Uint8Array) {
    if (bytes.length > 1_048_576) throw new IdlDecodeError("Payload exceeds decoder limit");
  }
  take(size: number): Uint8Array {
    if (!Number.isSafeInteger(size) || size < 0 || size > this.bytes.length - this.offset)
      throw new IdlDecodeError("Truncated payload");
    const result = this.bytes.slice(this.offset, this.offset + size);
    this.offset += size;
    return result;
  }
  remaining(): number {
    return this.bytes.length - this.offset;
  }
  finish(): void {
    if (this.remaining()) throw new IdlDecodeError("Trailing payload bytes");
  }
}

function decode(type: WireNode, reader: Reader, idl: WireIdl, depth = 0): DecodedValue {
  if (depth > 64) throw new IdlDecodeError("Nested type limit exceeded");
  const read = (child: WireNode, from = reader) => decode(child, from, idl, depth + 1);
  switch (type.kind) {
    case "numberTypeNode": {
      const widths: Record<string, number> = { u8: 1, u16: 2, u32: 4, u64: 8 };
      const width = required(widths[required(type.format, "number format")], "number width");
      const bytes = reader.take(width);
      let result = 0n;
      for (let i = 0; i < width; i++)
        result |= BigInt(bytes[i]!) << BigInt(8 * (type.endian === "be" ? width - i - 1 : i));
      return width === 8 ? result : Number(result);
    }
    case "booleanTypeNode": {
      const value = read(required(type.size as WireNode | undefined, "boolean size"));
      if (value !== 0 && value !== 1) throw new IdlDecodeError("Invalid boolean");
      return value === 1;
    }
    case "publicKeyTypeNode":
      return getBase58Decoder().decode(reader.take(32));
    case "bytesTypeNode":
      return reader.take(reader.remaining());
    case "fixedSizeTypeNode": {
      const nested = new Reader(
        reader.take(required(type.size as number | undefined, "fixed size")),
      );
      // Fixed-size accounts may pad variable Borsh data (UserRecord).
      return read(required(type.type, "fixed type"), nested);
    }
    case "sizePrefixTypeNode": {
      const size = read(required(type.prefix, "size prefix"));
      if (typeof size !== "number") throw new IdlDecodeError("Invalid size prefix");
      const nested = new Reader(reader.take(size));
      const result = read(required(type.type, "prefixed type"), nested);
      nested.finish();
      return result;
    }
    case "arrayTypeNode": {
      const count = required(type.count, "array count");
      const size =
        count.kind === "fixedCountNode"
          ? count.value
          : read(required(count.prefix, "count prefix"));
      if (typeof size !== "number" || size > 4096 || size < 0)
        throw new IdlDecodeError("Invalid array length");
      return Array.from({ length: size }, () => read(required(type.item, "array item")));
    }
    case "structTypeNode":
      return Object.fromEntries(
        (type.fields ?? []).map((field) => [
          required(field.name, "field name"),
          read(required(field.type, "field type")),
        ]),
      );
    case "optionTypeNode": {
      const present = read(required(type.prefix, "option prefix"));
      if (present !== 0 && present !== 1) throw new IdlDecodeError("Invalid option tag");
      const item = required(type.item, "option item");
      if (present === 1) return read(item);
      if (type.fixed) {
        const value = read(item);
        if (!(value instanceof Uint8Array) || value.some((byte) => byte !== 0))
          throw new IdlDecodeError("Absent fixed option must be zero");
      }
      return null;
    }
    case "remainderOptionTypeNode":
      return reader.remaining() ? read(required(type.item, "remainder item")) : null;
    case "enumTypeNode": {
      const tag = read(required(type.size as WireNode | undefined, "enum size"));
      const variant = required(type.variants, "enum variants").find(
        (v, i) => (v.discriminator ?? i) === tag,
      );
      if (!variant) throw new IdlDecodeError("Unknown enum variant");
      return {
        variant: required(variant.name, "variant name"),
        ...fields(read(required(variant.struct, "variant struct"))),
      };
    }
    case "definedTypeLinkNode": {
      const defined = idl.program.definedTypes?.find((entry) => entry.name === type.name);
      return read(required(defined?.type, `defined type ${type.name}`));
    }
    default:
      throw new IdlDecodeError(`Unsupported IDL node ${type.kind}`);
  }
}

export interface DecodedPrivacyInstruction {
  readonly name: string;
  readonly tag: number;
  readonly data: DecodedValue;
}

/** Decodes instruction bytes, not their provenance or execution success. */
export function decodeInstruction(
  program: ProgramName,
  bytes: Uint8Array,
): DecodedPrivacyInstruction {
  const idl = idls[program];
  const tag = bytes[0];
  const instruction = idl.program.instructions.find(
    (entry) => entry.arguments?.[0]?.defaultValue?.number === tag,
  );
  if (!instruction || tag === undefined) throw new IdlDecodeError("Unknown instruction tag");
  const reader = new Reader(bytes);
  const values = required(instruction.arguments, "instruction arguments").map((arg) =>
    decode(required(arg.type, "argument type"), reader, idl),
  );
  reader.finish();
  return { name: required(instruction.name, "instruction name"), tag, data: values[1] ?? null };
}

/** Caller must verify account ownership and provenance before trusting decoded fields. */
export function decodeAccount(
  program: ProgramName,
  name: string,
  bytes: Uint8Array,
): DecodedFields {
  const idl = idls[program];
  const account = idl.program.accounts.find((entry) => entry.name === name);
  if (!account) throw new IdlDecodeError("Unknown account type");
  if (typeof account.size === "number" && account.size !== bytes.length)
    throw new IdlDecodeError("Wrong account size");
  const discriminator = account.discriminators?.[0]?.constant?.value.number;
  if (discriminator === undefined || bytes[0] !== discriminator)
    throw new IdlDecodeError("Wrong account discriminator");
  const reader = new Reader(bytes);
  const value = fields(decode(required(account.data, "account data"), reader, idl));
  reader.finish();
  return value;
}

export function fields(value: DecodedValue | undefined): DecodedFields {
  if (!value || typeof value !== "object" || Array.isArray(value) || value instanceof Uint8Array)
    throw new IdlDecodeError("Expected decoded struct");
  return value;
}
