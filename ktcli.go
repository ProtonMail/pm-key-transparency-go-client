// Package ktclient provides verification of Key Transparency leaf proofs.
//
// The client verifies whether a given leaf belongs to an epoch, and is in the
// correct position. The first statement is verified by checking that the
// Merkle path from the leaf with the neighbours list indeed leads to the
// claimed root hash. The second statement is verified by validating the VRF
// public key.
package ktclient // import "github.com/ProtonMail/pm-key-transparency-go-client"

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

// Data contains necessary fields to perform a full KT verification.
type Data struct {
	// API-specific data
	Email         []byte // This package does not perform email validation
	SignedKeyList []byte
	Revision      int

	// Verifiable Random Functions - see
	// https://tools.ietf.org/html/draft-irtf-cfrg-vrf-08
	VRFProof []byte

	// Merkle tree insertion
	Neighbours        map[uint8][]byte // In hashing order
	RootHash          []byte           // Merkle tree root hash
	PreviousChainHash []byte
	ChainHash         []byte

	// TLS certificates separated by '\n'
	Certificates []byte // X509 certificates chain
}

// Verify checks the proof for correctness. If any verification step fails, it
// is reported in the returned error.
//
// This function MUST be checked for errors. If err != nil, the proof is
// INVALID.
//
// Assuming the VRF proof and rootHash are or verified values, this function
// returns nil if, and only if, the proof is VALID.
func (data *Data) Verify() error {
	// 1. Signed Key List is correctly encoded in a leaf of a consistent Merkle
	// tree, at address given by the VRF output of Email,
	rev := []byte{
		byte(data.Revision >> 24), byte(data.Revision >> 16),
		byte(data.Revision >> 8), byte(data.Revision),
	}
	h := sha256.New()
	h.Write(data.SignedKeyList) //nolint:errcheck,gosec
	val := append(h.Sum(nil), rev...)
	lip := &leafInsertionProof{
		data.Email, val, data.VRFProof, data.RootHash, data.Neighbours,
	}
	if err := lip.verify(); err != nil {
		return err
	}

	// 2. hash(previous_hash || rootHash) = chainHash,
	h.Reset()
	concat := append(data.PreviousChainHash, data.RootHash...)
	h.Write(concat) //nolint:errcheck,gosec
	if !bytes.Equal(data.ChainHash, h.Sum(nil)) {
		return fmt.Errorf("%w: inconsistent chainHash", ErrIntegrity)
	}

	// 3. chainHash is a prefix of the certificate alternate name,
	// 4. the certificate list is consistent (certificate 'n' signs
	// certificate 'n-1' and the last certificate is signed by
	// https://crt.sh/?id=8395)
	if err := verifyCert(data.ChainHash, data.Certificates); err != nil {
		return fmt.Errorf("certificate chain: %w", err)
	}

	return nil
}
