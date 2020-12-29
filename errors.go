package ktclient

import (
	"errors"
)

// Static errors.
var (
	ErrCert      = errors.New("TLS certificate")
	ErrIntegrity = errors.New("integrity")
	ErrSCT       = errors.New("SCT")
	ErrVRFProof  = errors.New("VRF proof")
)
