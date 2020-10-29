package ktclient

import (
	"encoding/hex"
	"fmt"
)

// Neighbours is a map of neighbours, used for gomobile.
type Neighbours struct {
	neighbours map[uint8][]byte
}

// SetNeighbour adds a new neighbour to the neighbour map.
func (n *Neighbours) SetNeighbour(key int, neighborHex string) error {
	if key < 0 || key > 255 {
		return errInvalidNeighbourKey
	}
	if n.neighbours == nil {
		n.neighbours = make(map[uint8][]byte)
	}
	neighborBytes, err := decodeHex(neighborHex)
	if err != nil {
		return err
	}
	n.neighbours[uint8(key)] = neighborBytes

	return nil
}

func decodeHex(s string) ([]byte, error) {
	res, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("error decoding hex: %w", err)
	}

	return res, nil
}

// NewInsertionProof creates a new InsertionProof object.
// It uses a Neighbours object to bypass gomobile limitations.
func NewInsertionProof(
	proofTypeValue int,
	revisionValue int,
	vrfProofHexValue string,
	neighboursWrapper *Neighbours,
) *InsertionProof {
	var neighboursMap map[uint8][]byte
	if neighboursWrapper != nil {
		neighboursMap = neighboursWrapper.neighbours
	}

	return &InsertionProof{
		ProofType:   proofTypeValue,
		Revision:    revisionValue,
		VRFProofHex: vrfProofHexValue,
		Neighbours:  neighboursMap,
	}
}

// NewEpoch creates a new Epoch object.
// Used as a constructor for mobile applications.
func NewEpoch(
	epochIDVal int,
	previousChainHashVal string,
	certificateChainVal string,
	certificateIssuerVal int,
	treeHashVal string,
	chainHashVal string,
	certificateTimeVal int64,
) *Epoch {
	return &Epoch{
		EpochID:           epochIDVal,
		PreviousChainHash: previousChainHashVal,
		CertificateChain:  certificateChainVal,
		CertificateIssuer: certificateIssuerVal,
		TreeHash:          treeHashVal,
		ChainHash:         chainHashVal,
		CertificateTime:   certificateTimeVal,
	}
}
