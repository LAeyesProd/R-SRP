import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

type Vector = {
  id: string;
  signing_bytes_len: number;
  signing_bytes_hex: string;
  canonical_bytes_len: number;
  canonical_bytes_hex: string;
  canonical_bytes_sha256_hex: string;
  runtime_version_packed_u16_be_hex: string;
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

  if (signing.length !== v.signing_bytes_len) throw new Error(`${v.id}: signing len mismatch`);
  if (canonical.length !== v.canonical_bytes_len) throw new Error(`${v.id}: canonical len mismatch`);
  if (!canonical.subarray(0, signing.length).equals(signing)) throw new Error(`${v.id}: canonical prefix mismatch`);

  const sigLen = canonical.readUInt32BE(signing.length);
  const sig = canonical.subarray(signing.length + 4);
  if (sig.length !== sigLen) throw new Error(`${v.id}: signature len suffix mismatch`);

  const runtimePacked = signing.subarray(2, 4).toString("hex");
  if (runtimePacked !== v.runtime_version_packed_u16_be_hex) throw new Error(`${v.id}: runtime pack mismatch`);

  const decisionCode = signing[132];
  if (decisionCode !== v.decision_code) throw new Error(`${v.id}: decision code mismatch`);

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

  for (const v of data.vectors ?? []) verifyVector(v);
  console.log(`ok: ${data.vectors.length} ProofEnvelopeV1 vector(s) verified`);
}

main();
