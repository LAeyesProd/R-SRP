import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

type Vector = {
  id: string;
  kind: string;
  proof_envelope_version: number;
  encoding_version: number;
  signature_algorithm_code: number;
  signer_key_id: string;
  binding_hash_hex: string;
  ed25519_public_key_hex: string;
  signature_bytes_hex: string;
  policy_hash_hex: string;
  bytecode_hash_hex: string;
  input_hash_hex: string;
  state_hash_hex: string;
  signing_bytes_len: number;
  signing_bytes_hex: string;
  canonical_bytes_len: number;
  canonical_bytes_hex: string;
  canonical_bytes_sha256_hex: string;
  runtime_version_packed_u32_be_hex: string;
  decision_code: number;
};

type VectorDoc = {
  schema: string;
  version: number;
  vectors: Vector[];
  negative_cases: NegativeCase[];
};

type NegativeCase = {
  id: string;
  source_vector: string;
  mutation: string;
  expected_error: string;
};

function hexToBuf(hex: string): Buffer {
  if (!/^(?:[0-9a-fA-F]{2})*$/.test(hex)) throw new Error("invalid hex");
  return Buffer.from(hex, "hex");
}

class ParseError extends Error {}

function parseEnvelope(bytes: Buffer) {
  let cursor = 0;
  const read = (length: number): Buffer => {
    if (bytes.length - cursor < length) throw new ParseError("TRUNCATED");
    const value = bytes.subarray(cursor, cursor + length);
    cursor += length;
    return value;
  };
  const version = read(1)[0];
  const encoding = read(1)[0];
  const runtime = read(4);
  const hashes = Array.from({ length: 4 }, () => read(32));
  const decisionOffset = cursor;
  const decision = read(1)[0];
  const metadataLengthOffset = cursor;
  const metaLen = read(2).readUInt16BE();
  const metadata = read(metaLen);
  if (metadata.length !== 65 || metadata[0] !== 1) throw new ParseError("INVALID_METADATA");
  const signing = bytes.subarray(0, cursor);
  const sigLen = read(4).readUInt32BE();
  const signature = read(sigLen);
  if (sigLen !== 64) throw new ParseError("INVALID_SIGNATURE_LENGTH");
  if (cursor !== bytes.length) throw new ParseError("TRAILING_BYTES");
  if (version !== 1 || encoding !== 2) throw new ParseError("UNSUPPORTED_VERSION");
  if (![1, 2, 3, 4].includes(decision)) throw new ParseError("UNKNOWN_DECISION");
  if (metadata.subarray(1, 33).equals(Buffer.alloc(32)) || metadata.subarray(33).equals(Buffer.alloc(32)))
    throw new ParseError("INVALID_METADATA");
  return { version, encoding, runtime, hashes, decision, metadata, signing, signature, decisionOffset, metadataLengthOffset };
}

function verifyVector(v: Vector): void {
  if (v.kind !== "ed25519") throw new Error(`${v.id}: unsupported signature kind`);
  const signing = hexToBuf(v.signing_bytes_hex);
  const canonical = hexToBuf(v.canonical_bytes_hex);
  const keyHash = crypto.createHash("sha256").update(v.signer_key_id, "utf8").digest();
  const bindingHash = hexToBuf(v.binding_hash_hex);
  if (bindingHash.length !== 32) throw new Error(`${v.id}: invalid binding hash`);
  const metadata = Buffer.concat([Buffer.from([v.signature_algorithm_code]), keyHash, bindingHash]);
  const metaLength = Buffer.alloc(2);
  metaLength.writeUInt16BE(metadata.length);
  const reconstructed = Buffer.concat([
    Buffer.from([v.proof_envelope_version, v.encoding_version]),
    hexToBuf(v.runtime_version_packed_u32_be_hex),
    hexToBuf(v.policy_hash_hex),
    hexToBuf(v.bytecode_hash_hex),
    hexToBuf(v.input_hash_hex),
    hexToBuf(v.state_hash_hex),
    Buffer.from([v.decision_code]),
    metaLength,
    metadata,
  ]);
  if (!reconstructed.equals(signing)) throw new Error(`${v.id}: semantic reconstruction mismatch`);

  if (signing.length !== v.signing_bytes_len) throw new Error(`${v.id}: signing len mismatch`);
  if (canonical.length !== v.canonical_bytes_len) throw new Error(`${v.id}: canonical len mismatch`);
  const parsed = parseEnvelope(canonical);
  if (!parsed.signing.equals(signing) || !parsed.runtime.equals(hexToBuf(v.runtime_version_packed_u32_be_hex)) ||
      parsed.hashes.some((hash, i) => !hash.equals(hexToBuf([v.policy_hash_hex, v.bytecode_hash_hex, v.input_hash_hex, v.state_hash_hex][i]))) ||
      parsed.version !== v.proof_envelope_version || parsed.encoding !== v.encoding_version ||
      parsed.decision !== v.decision_code || !parsed.metadata.equals(metadata))
    throw new Error(`${v.id}: parsed field mismatch`);
  if (v.kind === "ed25519") {
    if (parsed.signature.toString("hex") !== v.signature_bytes_hex) throw new Error(`${v.id}: signature bytes mismatch`);
    const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
    const publicKey = crypto.createPublicKey({
      key: Buffer.concat([spkiPrefix, hexToBuf(v.ed25519_public_key_hex)]),
      format: "der",
      type: "spki",
    });
    if (!crypto.verify(null, parsed.signing, publicKey, parsed.signature)) throw new Error(`${v.id}: Ed25519 signature verification failed`);
    const tampered = Buffer.from(signing);
    tampered[2 + parsed.runtime.length] ^= 1;
    if (crypto.verify(null, tampered, publicKey, parsed.signature)) throw new Error(`${v.id}: tampered payload signature accepted`);
  }

  const digest = crypto.createHash("sha256").update(canonical).digest("hex");
  if (digest !== v.canonical_bytes_sha256_hex) throw new Error(`${v.id}: sha256 mismatch`);
}

function verifyNegativeCase(test: NegativeCase, vectors: Map<string, Vector>): void {
  const source = vectors.get(test.source_vector);
  if (!source) throw new Error(`${test.id}: source vector not found`);
  const canonical = Buffer.from(hexToBuf(source.canonical_bytes_hex));
  const parsed = parseEnvelope(canonical);
  let mutatedCanonical = canonical;
  switch (test.mutation) {
    case "flip_signing_byte_6": canonical[2 + parsed.runtime.length] ^= 1; break;
    case "flip_last_signature_byte": canonical[canonical.length - 1] ^= 1; break;
    case "set_version_2": canonical[0] = 2; break;
    case "set_decision_0": canonical[parsed.decisionOffset] = 0; break;
    case "append_zero_byte": mutatedCanonical = Buffer.concat([canonical, Buffer.from([0])]); break;
    case "truncate_last_byte": mutatedCanonical = canonical.subarray(0, -1); break;
    case "set_metadata_length_zero": canonical.writeUInt16BE(0, parsed.metadataLengthOffset); break;
    case "set_signature_length_63": canonical.writeUInt32BE(63, parsed.signing.length); break;
    default: throw new Error(`${test.id}: unknown mutation ${test.mutation}`);
  }
  let actualError: string;
  try {
    const decoded = parseEnvelope(mutatedCanonical);
    const key = crypto.createPublicKey({
      key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), hexToBuf(source.ed25519_public_key_hex)]),
      format: "der", type: "spki",
    });
    actualError = crypto.verify(null, decoded.signing, key, decoded.signature) ? "VALID" : "INVALID_SIGNATURE";
  } catch (error) {
    if (!(error instanceof ParseError)) throw error;
    actualError = error.message;
  }
  if (actualError !== test.expected_error) throw new Error(`${test.id}: expected ${test.expected_error}, got ${actualError}`);
}

function main(): void {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(here, "..", "..");
  const vectorsPath = path.join(repoRoot, "docs", "PROOF_ENVELOPE_V1_TEST_VECTORS.json");
  const data = JSON.parse(fs.readFileSync(vectorsPath, "utf8")) as VectorDoc;

  if (data.schema !== "rsrp.proof-envelope-v1.test-vectors") throw new Error("schema mismatch");
  if (data.version !== 1) throw new Error("version mismatch");
  if (!data.vectors?.length) throw new Error("vector corpus must not be empty");
  if (!data.negative_cases?.length) throw new Error("negative vector corpus must not be empty");

  for (const v of data.vectors ?? []) verifyVector(v);
  const vectors = new Map(data.vectors.map((vector) => [vector.id, vector]));
  for (const test of data.negative_cases) verifyNegativeCase(test, vectors);
  console.log(`ok: ${data.vectors.length} positive and ${data.negative_cases.length} negative ProofEnvelopeV1 vector(s) verified`);
}

main();
