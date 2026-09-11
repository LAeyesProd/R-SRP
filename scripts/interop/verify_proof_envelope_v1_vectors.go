package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

type vector struct {
	ID                         string `json:"id"`
	Kind                       string `json:"kind"`
	ProofEnvelopeVersion       int    `json:"proof_envelope_version"`
	EncodingVersion            int    `json:"encoding_version"`
	SignatureAlgorithmCode     int    `json:"signature_algorithm_code"`
	SignerKeyID                string `json:"signer_key_id"`
	Ed25519PublicKeyHex        string `json:"ed25519_public_key_hex"`
	SignatureBytesHex          string `json:"signature_bytes_hex"`
	PolicyHashHex              string `json:"policy_hash_hex"`
	BytecodeHashHex            string `json:"bytecode_hash_hex"`
	InputHashHex               string `json:"input_hash_hex"`
	StateHashHex               string `json:"state_hash_hex"`
	SigningBytesLen            int    `json:"signing_bytes_len"`
	SigningBytesHex            string `json:"signing_bytes_hex"`
	CanonicalBytesLen          int    `json:"canonical_bytes_len"`
	CanonicalBytesHex          string `json:"canonical_bytes_hex"`
	CanonicalBytesSHA256Hex    string `json:"canonical_bytes_sha256_hex"`
	RuntimeVersionPackedU32Hex string `json:"runtime_version_packed_u32_be_hex"`
	DecisionCode               int    `json:"decision_code"`
}

type vectorDoc struct {
	Schema        string         `json:"schema"`
	Version       int            `json:"version"`
	Vectors       []vector       `json:"vectors"`
	NegativeCases []negativeCase `json:"negative_cases"`
}

type negativeCase struct {
	ID            string `json:"id"`
	SourceVector  string `json:"source_vector"`
	Mutation      string `json:"mutation"`
	ExpectedError string `json:"expected_error"`
}

func verifyNegativeCase(test negativeCase, vectors map[string]vector) {
	source, ok := vectors[test.SourceVector]
	if !ok {
		fail("%s: source vector not found", test.ID)
	}
	signing, _ := hex.DecodeString(source.SigningBytesHex)
	canonical, _ := hex.DecodeString(source.CanonicalBytesHex)
	switch test.Mutation {
	case "flip_signing_byte_6":
		signing[6] ^= 1
		canonical[6] ^= 1
	case "flip_last_signature_byte":
		canonical[len(canonical)-1] ^= 1
	case "set_version_2":
		signing[0], canonical[0] = 2, 2
	case "set_decision_0":
		signing[134], canonical[134] = 0, 0
	case "append_zero_byte":
		canonical = append(canonical, 0)
	default:
		fail("%s: unknown mutation %s", test.ID, test.Mutation)
	}
	actualError := ""
	if canonical[0] != 1 {
		actualError = "UNSUPPORTED_VERSION"
	} else if canonical[134] < 1 || canonical[134] > 4 {
		actualError = "UNKNOWN_DECISION"
	} else {
		sigLen := int(canonical[len(signing)])<<24 | int(canonical[len(signing)+1])<<16 |
			int(canonical[len(signing)+2])<<8 | int(canonical[len(signing)+3])
		if len(canonical) != len(signing)+4+sigLen {
			actualError = "TRAILING_BYTES"
		} else {
			publicKey, _ := hex.DecodeString(source.Ed25519PublicKeyHex)
			if ed25519.Verify(ed25519.PublicKey(publicKey), signing, canonical[len(canonical)-64:]) {
				actualError = "VALID"
			} else {
				actualError = "INVALID_SIGNATURE"
			}
		}
	}
	if actualError != test.ExpectedError {
		fail("%s: expected %s, got %s", test.ID, test.ExpectedError, actualError)
	}
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func verifyVector(v vector) {
	signing, err := hex.DecodeString(v.SigningBytesHex)
	if err != nil {
		fail("%s: invalid signing hex: %v", v.ID, err)
	}
	canonical, err := hex.DecodeString(v.CanonicalBytesHex)
	if err != nil {
		fail("%s: invalid canonical hex: %v", v.ID, err)
	}
	keyHash := sha256.Sum256([]byte(v.SignerKeyID))
	metadata := append([]byte{byte(v.SignatureAlgorithmCode)}, keyHash[:]...)
	reconstructed := []byte{byte(v.ProofEnvelopeVersion), byte(v.EncodingVersion)}
	for _, value := range []string{
		v.RuntimeVersionPackedU32Hex, v.PolicyHashHex, v.BytecodeHashHex,
		v.InputHashHex, v.StateHashHex,
	} {
		decoded, decodeErr := hex.DecodeString(value)
		if decodeErr != nil {
			fail("%s: invalid semantic field hex: %v", v.ID, decodeErr)
		}
		reconstructed = append(reconstructed, decoded...)
	}
	reconstructed = append(reconstructed, byte(v.DecisionCode), byte(len(metadata)>>8), byte(len(metadata)))
	reconstructed = append(reconstructed, metadata...)
	if hex.EncodeToString(reconstructed) != hex.EncodeToString(signing) {
		fail("%s: semantic reconstruction mismatch", v.ID)
	}

	if len(signing) != v.SigningBytesLen {
		fail("%s: signing len mismatch", v.ID)
	}
	if len(canonical) != v.CanonicalBytesLen {
		fail("%s: canonical len mismatch", v.ID)
	}
	if len(signing) < 138 {
		fail("%s: signing bytes too short", v.ID)
	}
	if len(canonical) < len(signing)+4 {
		fail("%s: canonical too short", v.ID)
	}
	for i := range signing {
		if canonical[i] != signing[i] {
			fail("%s: canonical prefix mismatch", v.ID)
		}
	}

	sigLen := int(canonical[len(signing)])<<24 |
		int(canonical[len(signing)+1])<<16 |
		int(canonical[len(signing)+2])<<8 |
		int(canonical[len(signing)+3])
	if len(canonical[len(signing)+4:]) != sigLen {
		fail("%s: signature len suffix mismatch", v.ID)
	}

	if hex.EncodeToString(signing[2:6]) != v.RuntimeVersionPackedU32Hex {
		fail("%s: runtime pack mismatch", v.ID)
	}
	if int(signing[134]) != v.DecisionCode {
		fail("%s: decision code mismatch", v.ID)
	}
	if signing[0] != 1 || int(signing[0]) != v.ProofEnvelopeVersion {
		fail("%s: envelope version mismatch", v.ID)
	}
	if signing[1] != 1 || int(signing[1]) != v.EncodingVersion {
		fail("%s: encoding version mismatch", v.ID)
	}
	if v.DecisionCode < 1 || v.DecisionCode > 4 {
		fail("%s: unknown decision code", v.ID)
	}
	metaLen := int(signing[135])<<8 | int(signing[136])
	meta := signing[137:]
	if len(meta) != metaLen || len(meta) == 0 {
		fail("%s: signature metadata length mismatch", v.ID)
	}
	if int(meta[0]) != v.SignatureAlgorithmCode {
		fail("%s: algorithm code mismatch", v.ID)
	}
	if v.Kind == "ed25519" {
		if metaLen != 33 || sigLen != 64 {
			fail("%s: invalid Ed25519 lengths", v.ID)
		}
		if hex.EncodeToString(meta[1:]) != hex.EncodeToString(keyHash[:]) {
			fail("%s: signer key id hash mismatch", v.ID)
		}
		if hex.EncodeToString(canonical[len(signing)+4:]) != v.SignatureBytesHex {
			fail("%s: signature bytes mismatch", v.ID)
		}
		publicKey, err := hex.DecodeString(v.Ed25519PublicKeyHex)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			fail("%s: invalid Ed25519 public key", v.ID)
		}
		if !ed25519.Verify(ed25519.PublicKey(publicKey), signing, canonical[len(signing)+4:]) {
			fail("%s: Ed25519 signature verification failed", v.ID)
		}
		tampered := append([]byte(nil), signing...)
		tampered[6] ^= 1
		if ed25519.Verify(ed25519.PublicKey(publicKey), tampered, canonical[len(signing)+4:]) {
			fail("%s: tampered payload signature accepted", v.ID)
		}
	}

	digest := sha256.Sum256(canonical)
	if hex.EncodeToString(digest[:]) != v.CanonicalBytesSHA256Hex {
		fail("%s: sha256 mismatch", v.ID)
	}
}

func main() {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		fail("resolve script path: runtime.Caller failed")
	}
	repoRoot, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	if err != nil {
		fail("resolve repo root: %v", err)
	}
	vectorsPath := filepath.Join(repoRoot, "docs", "PROOF_ENVELOPE_V1_TEST_VECTORS.json")
	raw, err := os.ReadFile(vectorsPath)
	if err != nil {
		fail("read vectors: %v", err)
	}

	var doc vectorDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		fail("parse vectors json: %v", err)
	}
	if doc.Schema != "rsrp.proof-envelope-v1.test-vectors" {
		fail("schema mismatch")
	}
	if doc.Version != 1 {
		fail("version mismatch")
	}
	if len(doc.Vectors) == 0 {
		fail("vector corpus must not be empty")
	}
	if len(doc.NegativeCases) == 0 {
		fail("negative vector corpus must not be empty")
	}

	vectorsByID := make(map[string]vector, len(doc.Vectors))
	for _, v := range doc.Vectors {
		verifyVector(v)
		vectorsByID[v.ID] = v
	}
	for _, test := range doc.NegativeCases {
		verifyNegativeCase(test, vectorsByID)
	}
	fmt.Printf("ok: %d positive and %d negative ProofEnvelopeV1 vector(s) verified\n", len(doc.Vectors), len(doc.NegativeCases))
}
