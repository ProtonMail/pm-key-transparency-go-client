package ktclient

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
)

const testVRFPublicKey = "LXaI/rQp9xTxAvdYQSzUuBM3swcSJ3D2IK2eSsiYous="

func TestGoodVrfProof(t *testing.T) {
	t.Parallel()
	email := "pro@proton.black"
	vrfProof := "60fbad6a1d20d5dc2753dcd643ab9226444994cc9b00214901596bbd59d3219da8063f2c9e65f6a28b9672444742185ca570fc152e78c080ea1a0e6d16f1f60205afa2027193bba2f0ea72363ec2510a" //nolint:lll
	expectedKey, _ := hex.DecodeString("561f329bff63f44fdb1215e9348ea69881429b0ac18432fe2c7a8efd1618d42f510b67440f83b6c469cc6395f70a85c2b17ff39e31fef9bcc932d8331bee8351")         //nolint:lll
	key, err := verifyVRFOutput(email, vrfProof, testVRFPublicKey)
	assert.NoError(t, err)
	assert.Equal(t, expectedKey, key)
}

func TestBadProof(t *testing.T) {
	t.Parallel()
	email := "bad@proton.black"
	vrfProof := "60fbad6a1d20d5dc2753dcd643ab9226444994cc9b00214901596bbd59d3219da8063f2c9e65f6a28b9672444742185ca570fc152e78c080ea1a0e6d16f1f60205afa2027193bba2f0ea72363ec2510a" //nolint:lll
	_, err := verifyVRFOutput(email, vrfProof, testVRFPublicKey)
	assert.Error(t, err)
}
