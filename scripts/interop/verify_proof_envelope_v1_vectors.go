package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
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
	BindingHashHex             string `json:"binding_hash_hex"`
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

type envelope struct {
	signing, signature, runtime, metadata []byte
	hashes                                [4][]byte
	version, encoding, decision           byte
	decisionOffset, metadataLengthOffset  int
}

func parseEnvelope(data []byte) (envelope, string) {
	var result envelope
	cursor := 0
	read := func(n int) ([]byte, bool) {
		if len(data)-cursor < n {
			return nil, false
		}
		value := data[cursor : cursor+n]
		cursor += n
		return value, true
	}
	readField := func(n int) ([]byte, string) {
		value, ok := read(n)
		if !ok {
			return nil, "TRUNCATED"
		}
		return value, ""
	}
	version, err := readField(1)
	if err != "" {
		return result, err
	}
	result.version = version[0]
	encoding, err := readField(1)
	if err != "" {
		return result, err
	}
	result.encoding = encoding[0]
	result.runtime, err = readField(4)
	if err != "" {
		return result, err
	}
	for i := range result.hashes {
		result.hashes[i], err = readField(32)
		if err != "" {
			return result, err
		}
	}
	result.decisionOffset = cursor
	decision, err := readField(1)
	if err != "" {
		return result, err
	}
	result.decision = decision[0]
	result.metadataLengthOffset = cursor
	metaLen, err := readField(2)
	if err != "" {
		return result, err
	}
	result.metadata, err = readField(int(binary.BigEndian.Uint16(metaLen)))
	if err != "" {
		return result, err
	}
	if len(result.metadata) != 65 || result.metadata[0] != 1 {
		return result, "INVALID_METADATA"
	}
	result.signing = data[:cursor]
	sigLen, err := readField(4)
	if err != "" {
		return result, err
	}
	size := binary.BigEndian.Uint32(sigLen)
	if uint64(size) > uint64(len(data)-cursor) {
		return result, "TRUNCATED"
	}
	result.signature, err = readField(int(size))
	if err != "" {
		return result, err
	}
	if size != ed25519.SignatureSize {
		return result, "INVALID_SIGNATURE_LENGTH"
	}
	if cursor != len(data) {
		return result, "TRAILING_BYTES"
	}
	if result.version != 1 || result.encoding != 2 {
		return result, "UNSUPPORTED_VERSION"
	}
	if result.decision < 1 || result.decision > 4 {
		return result, "UNKNOWN_DECISION"
	}
	if bytes.Equal(result.metadata[1:33], make([]byte, 32)) || bytes.Equal(result.metadata[33:], make([]byte, 32)) {
		return result, "INVALID_METADATA"
	}
	return result, ""
}

func verifyNegativeCase(test negativeCase, vectors map[string]vector) {
	source, ok := vectors[test.SourceVector]
	if !ok {
		fail("%s: source vector not found", test.ID)
	}
	canonical, decodeErr := hex.DecodeString(source.CanonicalBytesHex)
	if decodeErr != nil {
		fail("%s: invalid source hex: %v", test.ID, decodeErr)
	}
	parsed, parseErr := parseEnvelope(canonical)
	if parseErr != "" {
		fail("%s: invalid source: %s", test.ID, parseErr)
	}
	switch test.Mutation {
	case "flip_signing_byte_6":
		canonical[2+len(parsed.runtime)] ^= 1
	case "flip_last_signature_byte":
		canonical[len(canonical)-1] ^= 1
	case "set_version_2":
		canonical[0] = 2
	case "set_decision_0":
		canonical[parsed.decisionOffset] = 0
	case "append_zero_byte":
		canonical = append(canonical, 0)
	case "truncate_last_byte":
		canonical = canonical[:len(canonical)-1]
	case "set_metadata_length_zero":
		binary.BigEndian.PutUint16(canonical[parsed.metadataLengthOffset:], 0)
	case "set_signature_length_63":
		binary.BigEndian.PutUint32(canonical[len(parsed.signing):], 63)
	default:
		fail("%s: unknown mutation %s", test.ID, test.Mutation)
	}
	decoded, actualError := parseEnvelope(canonical)
	if actualError == "" {
		publicKey, keyErr := hex.DecodeString(source.Ed25519PublicKeyHex)
		if keyErr != nil || len(publicKey) != ed25519.PublicKeySize {
			fail("%s: invalid public key", test.ID)
		}
		if ed25519.Verify(ed25519.PublicKey(publicKey), decoded.signing, decoded.signature) {
			actualError = "VALID"
		} else {
			actualError = "INVALID_SIGNATURE"
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
	if v.Kind != "ed25519" {
		fail("%s: unsupported signature kind", v.ID)
	}
	signing, err := hex.DecodeString(v.SigningBytesHex)
	if err != nil {
		fail("%s: invalid signing hex: %v", v.ID, err)
	}
	canonical, err := hex.DecodeString(v.CanonicalBytesHex)
	if err != nil {
		fail("%s: invalid canonical hex: %v", v.ID, err)
	}
	keyHash := sha256.Sum256([]byte(v.SignerKeyID))
	bindingHash, err := hex.DecodeString(v.BindingHashHex)
	if err != nil || len(bindingHash) != 32 {
		fail("%s: invalid binding hash", v.ID)
	}
	metadata := append([]byte{byte(v.SignatureAlgorithmCode)}, keyHash[:]...)
	metadata = append(metadata, bindingHash...)
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
	parsed, parseErr := parseEnvelope(canonical)
	if parseErr != "" {
		fail("%s: %s", v.ID, parseErr)
	}
	if !bytes.Equal(parsed.signing, signing) || hex.EncodeToString(parsed.runtime) != v.RuntimeVersionPackedU32Hex ||
		int(parsed.version) != v.ProofEnvelopeVersion || int(parsed.encoding) != v.EncodingVersion ||
		int(parsed.decision) != v.DecisionCode || !bytes.Equal(parsed.metadata, metadata) {
		fail("%s: parsed field mismatch", v.ID)
	}
	for i, expected := range []string{v.PolicyHashHex, v.BytecodeHashHex, v.InputHashHex, v.StateHashHex} {
		if hex.EncodeToString(parsed.hashes[i]) != expected {
			fail("%s: hash mismatch", v.ID)
		}
	}
	if v.Kind == "ed25519" {
		if hex.EncodeToString(parsed.signature) != v.SignatureBytesHex {
			fail("%s: signature bytes mismatch", v.ID)
		}
		publicKey, err := hex.DecodeString(v.Ed25519PublicKeyHex)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			fail("%s: invalid Ed25519 public key", v.ID)
		}
		if !ed25519.Verify(ed25519.PublicKey(publicKey), parsed.signing, parsed.signature) {
			fail("%s: Ed25519 signature verification failed", v.ID)
		}
		tampered := append([]byte(nil), signing...)
		tampered[2+len(parsed.runtime)] ^= 1
		if ed25519.Verify(ed25519.PublicKey(publicKey), tampered, parsed.signature) {
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
