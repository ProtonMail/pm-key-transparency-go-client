// Package ktclient provides the proof and certificate verification for key transparency.
package ktclient

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"hash"

	"github.com/pkg/errors"
)

// InsertionProof contains all data necessary to verify the inclusion
// proof in the merkle tree.
type InsertionProof struct {
	ProofType   int
	VRFProofHex string
	Neighbours  map[uint8][]byte
}

// VerifyInsertionProof verifies that the signed key list
// is correctly inserted in the merkle tree, at the correct location
// associated with the VRF output for the given email.
func VerifyInsertionProof(
	email string,
	revision int,
	signedKeyList string,
	minEpochID int,
	vrfPublicKeyBase64 string,
	rootHashHex string,
	proof *InsertionProof,
) error {
	vrfHash, err := verifyVRFOutput(email, proof.VRFProofHex, vrfPublicKeyBase64)
	if err != nil {
		return errors.Wrap(err, "ktclient: VRF proof")
	}
	treePath := append(
		vrfHash[0:28],
		byte(revision>>24), byte(revision>>16),
		byte(revision>>8), byte(revision),
	)
	hashFunc := sha256.New()
	emptyNode := make([]byte, hashFunc.Size())
	leafHash, err := computeLeafNode(proof, emptyNode, hashFunc, minEpochID, signedKeyList)
	if err != nil {
		return err
	}
	computedRootHash, err := computeRootHash(treePath, proof, emptyNode, leafHash, hashFunc)
	if err != nil {
		return err
	}
	rootHash, err := decodeHex(rootHashHex)
	if err != nil {
		return errors.Wrap(err, "ktclient: invalid root hash hex encoding")
	}

	if !bytes.Equal(computedRootHash, rootHash) {
		return fmt.Errorf("ktclient: %w: path does not lead to 'RootHash'", errIntegrity)
	}

	return nil
}

func computeRootHash(
	treePath []byte,
	proof *InsertionProof,
	emptyNode []byte,
	leafNode []byte,
	hashFunc hash.Hash,
) ([]byte, error) {
	currentHash := leafNode
	var concat []byte
	reachedNonEmptyTree := false
	for treeLevel := 255; treeLevel >= 0; treeLevel-- {
		bit := (treePath[treeLevel/8] >> (8 - (treeLevel % 8) - 1)) & 0x01
		neighbour, ok := proof.Neighbours[uint8(treeLevel)]
		if !ok {
			if !reachedNonEmptyTree && proof.ProofType == absenceProofType {
				continue
			}
			neighbour = emptyNode
		} else {
			reachedNonEmptyTree = true
		}
		if bit == 0 {
			concat = append(currentHash, neighbour...)
		} else {
			concat = append(neighbour, currentHash...)
		}
		hashFunc.Reset()
		_, err := hashFunc.Write(concat)
		if err != nil {
			return nil, errors.Wrap(err, "ktclient: error while hashing")
		}
		currentHash = hashFunc.Sum(nil)
	}

	return currentHash, nil
}

func computeLeafNode(
	proof *InsertionProof,
	emptyNode []byte,
	hashFunc hash.Hash,
	minEpochID int,
	signedKeyList string,
) ([]byte, error) {
	var currentHash []byte
	switch proof.ProofType {
	case absenceProofType:
		currentHash = emptyNode
	case presenceProofType, obsolescenceProofType:
		minEpochIDBytes := []byte{
			byte(minEpochID >> 24), byte(minEpochID >> 16),
			byte(minEpochID >> 8), byte(minEpochID),
		}
		hashFunc.Reset()
		_, err := hashFunc.Write([]byte(signedKeyList))
		if err != nil {
			return nil, errors.Wrap(err, "ktclient: error while hashing")
		}
		leaf := append(hashFunc.Sum(nil), minEpochIDBytes...)
		hashFunc.Reset()
		_, err = hashFunc.Write(leaf)
		if err != nil {
			return nil, errors.Wrap(err, "ktclient: error while hashing")
		}
		currentHash = hashFunc.Sum(nil)
	default:
		return nil, errors.Wrapf(errMerkleProof, "ktclient: unknown proof type: %d", proof.ProofType)
	}

	return currentHash, nil
}
