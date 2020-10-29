package ktclient

import (
	"encoding/base64"
	"fmt"

	"github.com/ProtonMail/go-ecvrf/ecvrf"
	"github.com/pkg/errors"
)

func verifyVRFOutput(
	email string,
	vrfProofHex string,
	vrfPublicKeyBase64 string,
) ([]byte, error) {
	vrfPublicKey, err := base64.StdEncoding.DecodeString(vrfPublicKeyBase64)
	if err != nil {
		return nil, errors.Wrap(err, "ktclient: can't decode VRF key")
	}
	publicKey, err := ecvrf.NewPublicKey(vrfPublicKey)
	if err != nil {
		return nil, errors.Wrap(err, "ktclient: VRF key")
	}
	vrfProof, err := decodeHex(vrfProofHex)
	if err != nil {
		return nil, errors.Wrap(err, "ktclient: VRF proof hex decoding")
	}
	verified, key, err := publicKey.Verify([]byte(email), vrfProof)
	if err != nil {
		return nil, errors.Wrap(err, "ktclient: VRF proof")
	}
	if !verified {
		return nil, fmt.Errorf("ktclient: %w: incorrect VRF proof", errVRFProof)
	}

	return key, nil
}
