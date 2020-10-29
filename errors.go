package ktclient

import (
	"errors"
)

// Static errors.
var (
	errCert                = errors.New("TLS certificate")
	errIntegrity           = errors.New("integrity")
	errSCT                 = errors.New("SCT")
	errMerkleProof         = errors.New("MerkleTree proof")
	errVRFProof            = errors.New("VRF proof")
	errInvalidNeighbourKey = errors.New("ktclient: invalid new key")
)
