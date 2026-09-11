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

function main(): void {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const repoRoot = path.resolve(here, "..", "..");
  const vectorsPath = path.join(repoRoot, "docs", "PROOF_ENVELOPE_V1_TEST_VECTORS.json");
  const data = JSON.parse(fs.readFileSync(vectorsPath, "utf8")) as VectorDoc;

  if (data.schema !== "rsrp.proof-envelope-v1.test-vectors") throw new Error("schema mismatch");
  if (data.version !== 1) throw new Error("version mismatch");
  if (!data.vectors?.length) throw new Error("vector corpus must not be empty");

  for (const v of data.vectors ?? []) verifyVector(v);
  console.log(`ok: ${data.vectors.length} ProofEnvelopeV1 vector(s) verified`);
}

main();
