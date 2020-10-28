package ktclient

import (
	"bytes"
	"crypto/sha256"
)

// Node TODO: doc
type Node struct {
	key []byte // The binary key, indicating the position in the tree
	val []byte   // The value stored in this node
}

// VerifyProof TODO: doc
func (node *Node) VerifyProof(root []byte, neighbours map[uint8][]byte) bool {
	h := sha256.New()
	currentHash := node.val[:]
	var lh, rh []byte

	for j := 0; j < 32; j++ {
		b := node.key[31-j/8]
		for i := 0; i < 8; i++ {
			index := 8 * j + i
			neighbour, ok := neighbours[uint8(index)]
			if !ok {
				neighbour = make([]byte, h.BlockSize())
			}
			if b & 0x01 == 0 {
				lh = currentHash
				rh = neighbour
			} else { // TODO: Use swap instead
				lh = neighbour
				rh = currentHash
			}
			h.Write(lh)
			h.Write(rh)
			currentHash = h.Sum(nil)
			b >>= 1
		}
	}
	return bytes.Equal(currentHash, root[:])
}
