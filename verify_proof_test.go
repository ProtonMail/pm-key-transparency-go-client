package ktclient

import (
	"encoding/hex"
	"testing"

	"github.com/pkg/errors"
)

type TestData struct {
	proofType     int
	email         string
	vrfProof      string
	rootHash      string
	neighbours    map[uint8]string
	revision      int
	minEpochID    int
	signedKeyList string
}

func (testData *TestData) getProof() (*InsertionProof, error) {
	neighbours := make(map[uint8][]byte)
	for index, neighbourHex := range testData.neighbours {
		neighbour, err := hex.DecodeString(neighbourHex)
		if err != nil {
			return nil, errors.Wrap(err, "can't decode neighbour")
		}
		neighbours[index] = neighbour
	}

	return &InsertionProof{
		ProofType:   testData.proofType,
		VRFProofHex: testData.vrfProof,
		Neighbours:  neighbours,
	}, nil
}

func TestValidExistenceProof(t *testing.T) {
	t.Parallel()
	testData := &TestData{
		proofType:     presenceProofType,
		email:         "kttests@willis.proton.black",
		vrfProof:      "4231d686832adf245ffa6321a063cdd2e88f739d2708b195fb4e343db13c816c15110d16a14814fe3f8f7c819aca9c2794d90287d197a00caa943e22ed8665f3004bb8848a9fb1f578b017f34962ec02", //nolint: lll
		rootHash:      "84d99a676ae5985ded5aecd61ed2aa8d72655ae328b1dc53d2c53bc2c26c1dd9",
		revision:      1,
		minEpochID:    571,
		signedKeyList: `[{"Primary":1,"Flags":3,"Fingerprint":"43eb8f7cc59576c0bca4414258518450b9119b5d","SHA256Fingerprints":["357f701a502e62192022d363af687d52308352ef8ac53a8bd139fa2b9dd3c6a9","d2c59421d8dea08f7d3e0a41a301a245fbe834ef0ec7e96fd6ee870fe75e45ac"]}]`, //nolint: lll
		neighbours: map[uint8]string{
			0: "03ed34a89422d83338dca4ed9bbc4a66b1d27e82e57552b5ac8d21c1ed9099d5",
			1: "1ed3b9e5d0ed19a5f058dfbbd2511bb2d7191126e5c276e99f38a616f5d7d3f1",
			2: "27cca2c43a813a001c307aa6c8edc7568d9412100ff234c0524b47c78ac19488",
			3: "2875a21426aedacc16ece71ed250eeb940c97c1bf990eebc5b265468b11b009c",
			4: "87047a94f7bed857880e6c0434e11b56258db98cc792856847a87edb8778270f",
			7: "d6a370681090122cfe9eb29001feddc1dea2ef0a48a44a2947d14ac2e486cfd8",
		},
	}
	proof, err := testData.getProof()
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyInsertionProof(
		testData.email,
		testData.revision,
		testData.signedKeyList,
		testData.minEpochID,
		testVRFPublicKey,
		testData.rootHash,
		proof,
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidObsolescenceProof(t *testing.T) {
	t.Parallel()
	testData := &TestData{
		proofType:     obsolescenceProofType,
		email:         "disabledtest@disabled.2.willis.protonhub.org",
		vrfProof:      "80619aac087ff2e9209c265bff1d82dbbf8f8634fcafb1b82bca6e81a45b56c14cdbfbac17cc33868281e84636f515f0125ca118e49228d842d3a757764c495e15cee89704b26a82fa9165ee9ccf8300", //nolint: lll
		rootHash:      "300daa5756ce8a9b955bed0c7d2b478c47813eaaa0296e2db56413c5222df708",
		revision:      2,
		minEpochID:    573,
		signedKeyList: "0000000064ad241e27f7fe3fb1542f23ebad09847beab8f526fb854a",
		neighbours: map[uint8]string{
			0:   "883b1df249a3aa75a8d5df286d028131cfd2ace624415e86ccc78c9d1c4c7937",
			1:   "4842cdc862a9ea3f36567029bc4f154bba7b6d027757ec61e8cea4422ee9d95d",
			2:   "b2930af948e8e8ea01292d456879c9cc18552e7867e278ffa7f9b81704ee8a7b",
			3:   "ad3427ef2b37be9080c165ac96faf945ad060c807dd2783e1dfe04cfe8ba82ec",
			4:   "d70267757c07c95baba677b5ef9c35930a56129d8c4efc58657ff2c4dd6c8003",
			5:   "8d1bfbf3332f2d4ed5ab26c58ea0e85f7d3b6d60cc00fedd925cc9e3712d42cc",
			254: "8f6a3dd6c529cf5517f3d0d7cb32615fff870d85926dae55e9fb975d27d4aed8",
		},
	}
	proof, err := testData.getProof()
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyInsertionProof(
		testData.email,
		testData.revision,
		testData.signedKeyList,
		testData.minEpochID,
		testVRFPublicKey,
		testData.rootHash,
		proof,
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidAbsenceProof(t *testing.T) {
	t.Parallel()
	testData := &TestData{
		proofType:     absenceProofType,
		email:         "kttests@willis.proton.black",
		vrfProof:      "4231d686832adf245ffa6321a063cdd2e88f739d2708b195fb4e343db13c816c15110d16a14814fe3f8f7c819aca9c2794d90287d197a00caa943e22ed8665f3004bb8848a9fb1f578b017f34962ec02", //nolint: lll
		rootHash:      "84d99a676ae5985ded5aecd61ed2aa8d72655ae328b1dc53d2c53bc2c26c1dd9",
		revision:      2,
		minEpochID:    0,
		signedKeyList: "",
		neighbours: map[uint8]string{
			0:   "03ed34a89422d83338dca4ed9bbc4a66b1d27e82e57552b5ac8d21c1ed9099d5",
			1:   "1ed3b9e5d0ed19a5f058dfbbd2511bb2d7191126e5c276e99f38a616f5d7d3f1",
			2:   "27cca2c43a813a001c307aa6c8edc7568d9412100ff234c0524b47c78ac19488",
			3:   "2875a21426aedacc16ece71ed250eeb940c97c1bf990eebc5b265468b11b009c",
			4:   "87047a94f7bed857880e6c0434e11b56258db98cc792856847a87edb8778270f",
			7:   "d6a370681090122cfe9eb29001feddc1dea2ef0a48a44a2947d14ac2e486cfd8",
			254: "10bab3850f37d0448992ae971bcff00ecb63110fc372ae6a4bdf84638a70aa7a",
		},
	}
	proof, err := testData.getProof()
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyInsertionProof(
		testData.email,
		testData.revision,
		testData.signedKeyList,
		testData.minEpochID,
		testVRFPublicKey,
		testData.rootHash,
		proof,
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestBadMerkleProof(t *testing.T) {
	t.Parallel()
	testData := &TestData{
		proofType:     presenceProofType,
		email:         "kttests@willis.proton.black",
		vrfProof:      "4231d686832adf245ffa6321a063cdd2e88f739d2708b195fb4e343db13c816c15110d16a14814fe3f8f7c819aca9c2794d90287d197a00caa943e22ed8665f3004bb8848a9fb1f578b017f34962ec02", //nolint: lll
		rootHash:      "84d99a676ae5985ded5aecd61ed2aa8d72655ae328b1dc53d2c53bc2c26c1dd9",
		revision:      1,
		minEpochID:    571,
		signedKeyList: `[{"Primary":1,"Flags":3,"Fingerprint":"43eb8f7cc59576c0bca4414258518450b9119b5d","SHA256Fingerprints":["357f701a502e62192022d363af687d52308352ef8ac53a8bd139fa2b9dd3c6a9","d2c59421d8dea08f7d3e0a41a301a245fbe834ef0ec7e96fd6ee870fe75e45ac"]}]`, //nolint: lll
		neighbours: map[uint8]string{
			0: "03ed34a89422d83338dca4ed9bbc4a66b1d27e82e57552b5ac8d21c1ed9099d5",
			1: "1ed3b9e5d0ed19a5f058dfbbd2511bb2d7191126e5c276e99f38a616f5d7d3f1",
			2: "27cca2c43a813a001c307aa6c8edc7568d9412100ff234c0524b47c78ac19488",
			3: "2875a21426aedacc16ece71ed250eeb940c97c1bf990eebc5b265468b11b009c",
			4: "87047a94f7bed857880e6c0434e11b56258db98cc792856847a87edb8778270f",
			7: "d6a370681090122cfe9eb29001feddcdf3a2ef0a48a44a2947d14ac2e486cfd8",
		},
	}
	proof, err := testData.getProof()
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyInsertionProof(
		testData.email,
		testData.revision,
		testData.signedKeyList,
		testData.minEpochID,
		testVRFPublicKey,
		testData.rootHash,
		proof,
	)
	if err == nil {
		t.Fatal("Expected an error, got nil")
	}
}

func TestModifiedSKLError(t *testing.T) {
	t.Parallel()
	testData := &TestData{
		proofType:     presenceProofType,
		email:         "kttests@willis.proton.black",
		vrfProof:      "4231d686832adf245ffa6321a063cdd2e88f739d2708b195fb4e343db13c816c15110d16a14814fe3f8f7c819aca9c2794d90287d197a00caa943e22ed8665f3004bb8848a9fb1f578b017f34962ec02", //nolint: lll
		rootHash:      "84d99a676ae5985ded5aecd61ed2aa8d72655ae328b1dc53d2c53bc2c26c1dd9",
		revision:      1,
		minEpochID:    571,
		signedKeyList: `[{"Primary":1,"Flags":15,"Fingerprint":"43eb8f7cc59576c0bca4414258518450b9119b5d","SHA256Fingerprints":["357f701a502e62192022d363af687d52308352ef8ac53a8bd139fa2b9dd3c6a9","d2c59421d8dea08f7d3e0a41a301a245fbe834ef0ec7e96fd6ee870fe75e45ac"]}]`, //nolint: lll
		neighbours: map[uint8]string{
			0: "03ed34a89422d83338dca4ed9bbc4a66b1d27e82e57552b5ac8d21c1ed9099d5",
			1: "1ed3b9e5d0ed19a5f058dfbbd2511bb2d7191126e5c276e99f38a616f5d7d3f1",
			2: "27cca2c43a813a001c307aa6c8edc7568d9412100ff234c0524b47c78ac19488",
			3: "2875a21426aedacc16ece71ed250eeb940c97c1bf990eebc5b265468b11b009c",
			4: "87047a94f7bed857880e6c0434e11b56258db98cc792856847a87edb8778270f",
			7: "d6a370681090122cfe9eb29001feddc1dea2ef0a48a44a2947d14ac2e486cfd8",
		},
	}
	proof, err := testData.getProof()
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyInsertionProof(
		testData.email,
		testData.revision,
		testData.signedKeyList,
		testData.minEpochID,
		testVRFPublicKey,
		testData.rootHash,
		proof,
	)
	if err == nil {
		t.Fatal("Expected an error, got nil")
	}
}
