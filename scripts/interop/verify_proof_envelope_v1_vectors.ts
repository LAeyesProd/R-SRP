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
  return Buffer.from(hex, "hex");
}

function verifyVector(v: Vector): void {
  const signing = hexToBuf(v.signing_bytes_hex);
  const canonical = hexToBuf(v.canonical_bytes_hex);
  const keyHash = crypto.createHash("sha256").update(v.signer_key_id, "utf8").digest();
  const metadata = Buffer.concat([Buffer.from([v.signature_algorithm_code]), keyHash]);
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
  if (signing.length < 138) throw new Error(`${v.id}: signing bytes too short`);
  if (canonical.length < signing.length + 4) throw new Error(`${v.id}: canonical bytes too short`);
  if (!canonical.subarray(0, signing.length).equals(signing)) throw new Error(`${v.id}: canonical prefix mismatch`);

  const sigLen = canonical.readUInt32BE(signing.length);
  const sig = canonical.subarray(signing.length + 4);
  if (sig.length !== sigLen) throw new Error(`${v.id}: signature len suffix mismatch`);

  const runtimePacked = signing.subarray(2, 6).toString("hex");
  if (runtimePacked !== v.runtime_version_packed_u32_be_hex) throw new Error(`${v.id}: runtime pack mismatch`);

  const decisionCode = signing[134];
  if (decisionCode !== v.decision_code) throw new Error(`${v.id}: decision code mismatch`);
  if (signing[0] !== 1 || signing[0] !== v.proof_envelope_version) throw new Error(`${v.id}: envelope version mismatch`);
  if (signing[1] !== 1 || signing[1] !== v.encoding_version) throw new Error(`${v.id}: encoding version mismatch`);
  if (![1, 2, 3, 4].includes(decisionCode)) throw new Error(`${v.id}: unknown decision code`);

  const metaLen = signing.readUInt16BE(135);
  const meta = signing.subarray(137);
  if (meta.length !== metaLen) throw new Error(`${v.id}: signature metadata length mismatch`);
  if (meta[0] !== v.signature_algorithm_code) throw new Error(`${v.id}: algorithm code mismatch`);
  if (v.kind === "ed25519") {
    if (metaLen !== 33) throw new Error(`${v.id}: invalid Ed25519 metadata length`);
    if (!meta.subarray(1).equals(keyHash)) throw new Error(`${v.id}: signer key id hash mismatch`);
    if (sigLen !== 64) throw new Error(`${v.id}: invalid Ed25519 signature length`);
    if (sig.toString("hex") !== v.signature_bytes_hex) throw new Error(`${v.id}: signature bytes mismatch`);
    const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
    const publicKey = crypto.createPublicKey({
      key: Buffer.concat([spkiPrefix, hexToBuf(v.ed25519_public_key_hex)]),
      format: "der",
      type: "spki",
    });
    if (!crypto.verify(null, signing, publicKey, sig)) throw new Error(`${v.id}: Ed25519 signature verification failed`);
    const tampered = Buffer.from(signing);
    tampered[6] ^= 1;
    if (crypto.verify(null, tampered, publicKey, sig)) throw new Error(`${v.id}: tampered payload signature accepted`);
  }

  const digest = crypto.createHash("sha256").update(canonical).digest("hex");
  if (digest !== v.canonical_bytes_sha256_hex) throw new Error(`${v.id}: sha256 mismatch`);
}

function verifyNegativeCase(test: NegativeCase, vectors: Map<string, Vector>): void {
  const source = vectors.get(test.source_vector);
  if (!source) throw new Error(`${test.id}: source vector not found`);
  const signing = Buffer.from(source.signing_bytes_hex, "hex");
  const canonical = Buffer.from(source.canonical_bytes_hex, "hex");
  let mutatedCanonical = canonical;
  switch (test.mutation) {
    case "flip_signing_byte_6": signing[6] ^= 1; canonical[6] ^= 1; break;
    case "flip_last_signature_byte": canonical[canonical.length - 1] ^= 1; break;
    case "set_version_2": signing[0] = canonical[0] = 2; break;
    case "set_decision_0": signing[134] = canonical[134] = 0; break;
    case "append_zero_byte": mutatedCanonical = Buffer.concat([canonical, Buffer.from([0])]); break;
    default: throw new Error(`${test.id}: unknown mutation ${test.mutation}`);
  }
  let actualError: string;
  if (mutatedCanonical[0] !== 1) actualError = "UNSUPPORTED_VERSION";
  else if (![1, 2, 3, 4].includes(mutatedCanonical[134])) actualError = "UNKNOWN_DECISION";
  else if (mutatedCanonical.length !== signing.length + 4 + mutatedCanonical.readUInt32BE(signing.length)) actualError = "TRAILING_BYTES";
  else {
    const key = crypto.createPublicKey({
      key: Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), hexToBuf(source.ed25519_public_key_hex)]),
      format: "der", type: "spki",
    });
    actualError = crypto.verify(null, signing, key, mutatedCanonical.subarray(-64)) ? "VALID" : "INVALID_SIGNATURE";
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
