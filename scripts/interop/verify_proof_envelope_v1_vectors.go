package main

import (
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
	SigningBytesLen            int    `json:"signing_bytes_len"`
	SigningBytesHex            string `json:"signing_bytes_hex"`
	CanonicalBytesLen          int    `json:"canonical_bytes_len"`
	CanonicalBytesHex          string `json:"canonical_bytes_hex"`
	CanonicalBytesSHA256Hex    string `json:"canonical_bytes_sha256_hex"`
	RuntimeVersionPackedU16Hex string `json:"runtime_version_packed_u16_be_hex"`
	DecisionCode               int    `json:"decision_code"`
}

type vectorDoc struct {
	Schema  string   `json:"schema"`
	Version int      `json:"version"`
	Vectors []vector `json:"vectors"`
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

	if len(signing) != v.SigningBytesLen {
		fail("%s: signing len mismatch", v.ID)
	}
	if len(canonical) != v.CanonicalBytesLen {
		fail("%s: canonical len mismatch", v.ID)
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

	if hex.EncodeToString(signing[2:4]) != v.RuntimeVersionPackedU16Hex {
		fail("%s: runtime pack mismatch", v.ID)
	}
	if int(signing[132]) != v.DecisionCode {
		fail("%s: decision code mismatch", v.ID)
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

	for _, v := range doc.Vectors {
		verifyVector(v)
	}
	fmt.Printf("ok: %d ProofEnvelopeV1 vector(s) verified\n", len(doc.Vectors))
}
