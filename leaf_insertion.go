package ktclient

import (
	"bytes"
	"crypto/sha256"
	"fmt"

	"github.com/r2ishiguro/vrf/go/vrf_ed25519"
)

// leafInsertion constitutes a correctness proof of the unique and randomized
// insertion of a leaf value in an epoch, according to the key transparency
// design. It assumes that rootHash and the VRF key are verified or trusted.
type leafInsertionProof struct {
	msg        []byte
	val        []byte // Value of the leaf (ready to be hashed)
	proof      []byte // Proof that VRF(sk, msg) = leaf address
	rootHash   []byte
	neighbours map[uint8][]byte
}

func (li *leafInsertionProof) verify() error {
	b, err := vrf_ed25519.ECVRF_verify(_vrfPubKey, li.proof, li.msg)
	if err != nil {
		return fmt.Errorf("VRF proof: %w", err)
	}
	if !b {
		return fmt.Errorf("%w: incorrect VRF proof", ErrVRFProof)
	}
	r, _, _, err := vrf_ed25519.ECVRF_decode_proof(li.proof)
	if err != nil {
		return fmt.Errorf("%w: cannot decode from VRF proof", ErrVRFProof)
	}

	addr := new([32]byte)
	r.ToBytes(addr)

	h := sha256.New()
	h.Write(li.val) //nolint:errcheck,gosec
	currentHash := h.Sum(nil)
	emptyNode := make([]byte, h.Size())

	var concat []byte
	for i := 0; i < 256; i++ {
		neighbour, ok := li.neighbours[uint8(i)]
		if !ok {
			neighbour = emptyNode
		}
		if addr[31-i/8]>>byte(i%8)&0x01 == 0 {
			concat = append(currentHash, neighbour...)
		} else {
			concat = append(neighbour, currentHash...)
		}
		h.Reset()
		h.Write(concat) //nolint:errcheck,gosec
		currentHash = h.Sum(nil)
	}

	if !bytes.Equal(currentHash, li.rootHash) {
		return fmt.Errorf("%w: path does not lead to 'RootHash'", ErrIntegrity)
	}

	return nil
}
