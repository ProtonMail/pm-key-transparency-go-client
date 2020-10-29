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
		Revision:    testData.revision,
		VRFProofHex: testData.vrfProof,
		Neighbours:  neighbours,
	}, nil
}

func TestValidExistenceProof(t *testing.T) {
	t.Parallel()
	testData := &TestData{
		proofType:     presenceProofType,
		email:         "pro@proton.black",
		vrfProof:      "60fbad6a1d20d5dc2753dcd643ab9226444994cc9b00214901596bbd59d3219da8063f2c9e65f6a28b9672444742185ca570fc152e78c080ea1a0e6d16f1f60205afa2027193bba2f0ea72363ec2510a", //nolint: lll
		rootHash:      "d61969ba4ab30507809aec0d3a49810433c9abc5a28c17b1f160692766b60595",
		revision:      0,
		signedKeyList: `[{"Primary":1,"Flags":3,"Fingerprint":"552acf5984e187edc0682d84395469b11f04cd64","SHA256Fingerprints":["ef445078489f7feec6af4b0e23f9bad8bc883e4c4166bd81478851cfa9090b6c","92c8c4a69a75f83af7c13c9049c94e7f75b3ccd8ca33c6c302cd04286a556387"]},{"Primary":0,"Flags":3,"Fingerprint":"5372de721b9971518273581e04cd9dc25fbae509","SHA256Fingerprints":["4380c60bc440132428390868598b9872ed4efad6a87e2c7aad25807fe7f675b0","bad8f749883cc2873d09e66cfce2604855b85aaaa7215311d444e2b60a96cd59"]}]`, //nolint: lll
		neighbours: map[uint8]string{
			0:  "d6a32d69fe74b4f4c7783624a1f9dc29faae7abedb9f7a35667b403b54949c51",
			1:  "dc5dd14729a0e5ec0b9947517c8dbc5900ed9b45cae579b81421a2c7474a4bc5",
			2:  "e1666a9c0be19d3fa50227a3421209459a83f8922ac4da44262a13176b5682b1",
			3:  "59af0d29c47e774217a867c193ad43dccf8aa841d4ba8341f504a3ae08dd500a",
			4:  "a6a3dd3ec7ee85af3ecde7ae1e769c50fb3fab6f407b1f68635b68bf8bd9f7ab",
			5:  "4c9c6081f317911d4fd41b4a58b21cf64da8d2352abb5a0f43bb0e9d78d9685d",
			6:  "b7500c93afd823e443a57701fc4396a20bc2b930c20b62f34e488a42f4a73b2e",
			7:  "d8d01da11426f7170541260b970c23a93d89d4d9a6be889bd698c531c9f511a7",
			8:  "a6c59154f274e6cfc9fc6c85e4c8c63e4c08303960eaf0d97154882c349cac81",
			9:  "135bcd400baa90cae2ef72522e1ed6481d559bbf1869c0fb44ec229d4a11dabd",
			10: "9a6221223169dc031b37e32133ef20ca0b1e0a6a7f1c960415a71852d308db6a",
			11: "80db7974dfa860c3ec31429a7c168364ccb7a3104c298ddc9a22a523edd65806",
			12: "187e1ae64197a1cc4ada1885ca744cd398a5497c7766f00421d9a0b0ced1ad2f",
			13: "66cb75d9d6561ccd765da48c10e9d4641ef0b654ed24e00f5ea07b11da219654",
		},
	}
	proof, err := testData.getProof()
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyInsertionProof(
		testData.email,
		testData.signedKeyList,
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
		email:         "pro1@proton.black",
		vrfProof:      "49ac8f3b66376ac6d4f12baecb713188142b8142c8df40fb15e2d2f3f8b1d4fdb53c4aa7f319448458e11e688df80c6f694258876341408f0e03e83b773ed370abd1f762b13d6533bf5e8e09a244810e", //nolint: lll
		rootHash:      "d61969ba4ab30507809aec0d3a49810433c9abc5a28c17b1f160692766b60595",
		revision:      0,
		signedKeyList: "f96960a10cb3777ed0761f87edd048bed0862c98",
		neighbours: map[uint8]string{
			0:  "b452e2045a2b57e7cf1bc3eba7fe4c121e7cd5d0aab93339ece0f97e11fe3cf4",
			1:  "5fb78ab31e22423d4474792a971a983434a708d1a6d8ca0956578198a6d2ac8e",
			2:  "f0bdd408bdb1c3545512d87fb7fb98210bc79791bfef4d2dbdcc2c0d3ed51204",
			3:  "0451eb9d6ca068381e54b419496eb575606aebdd896d41003f685f4a46895932",
			4:  "8f65ed38a744c15318503b68aaf8d681b65b882d2e4cdc49af12277533b9da46",
			5:  "659239c5cd2f8f24dc57eba5136d49f43b42ca1af4822a40584d1a4eb72942b5",
			6:  "fc5b2a9223a008ced5ec23cfb09adbefb77f6e45ff8b414872f594299610077c",
			7:  "e6ca38d07004fe894e25e39e5e18a2a300acf81c46ab689c09dd8ef87b3e0e10",
			8:  "166fe60da4ada8ccb6d7a6183690fb02b2764b7978b4af7a630251c005056e0f",
			9:  "3a2e9c1682d2fd2a9211dc7c244a2aa351c33cdeec3592e42175b7270bf31b74",
			10: "03f2fa571ebcab222d95dbe8b695b6f708dc43f651afc836dae469ad9e271154",
			11: "b1f14dae9b1a981c34e67227a7d4cd59a4fd2a939d6c6082738796c4853f9cbc",
			12: "1f39723c1c0847fe843b24ee2a7e61738a81b22cc6fb45b6b3ec65ad3ac43479",
			13: "681c3bcb0b95f208be399ebb2a67d0d882f0376a36dd72e9b47a3ffddafe9ace",
			14: "34e819e6b71bc00377557c15414dc000ac68d6d034cf3df11b76d0891fa4cf5e",
		},
	}
	proof, err := testData.getProof()
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyInsertionProof(
		testData.email,
		testData.signedKeyList,
		testVRFPublicKey,
		testData.rootHash,
		proof,
	)
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidCatchallAbsenceProof(t *testing.T) {
	t.Parallel()
	testData := &TestData{
		proofType:     absenceProofType,
		email:         "@proton.black",
		vrfProof:      "80b2a7b23c6ebd91fae224f908d0e629d6417526f532aa1d6ff357071068ceac5d235c166ce6e82ca336b0cfea30bae386182d1af8d9b6cffdf244ff5b7ce9e9a5a47a8eb87eb1ec9f7bb5f61a7d0803", //nolint: lll
		rootHash:      "d61969ba4ab30507809aec0d3a49810433c9abc5a28c17b1f160692766b60595",
		revision:      0,
		signedKeyList: "",
		neighbours: map[uint8]string{
			0:  "b452e2045a2b57e7cf1bc3eba7fe4c121e7cd5d0aab93339ece0f97e11fe3cf4",
			1:  "d041cf05d3ce71b839d5796d7a159a3f9919259285d178d1df831e3465c08858",
			2:  "ed277d24ff3acb8127e0720d44dfa805924779bc6c4250bbc1767d672e279e71",
			3:  "de8e91ab945440e732ca1e7008ff198d4754512ce31d5b5b0ff435825a33d1ea",
			4:  "db613a009e045dad364055cae2cdbf41c3f9628a7e4cc9c3f78727b5624216d3",
			5:  "9119b6d7efcb29cb69d496f6e5c443de1b2e897a8fd20c57426a5baf8ad716d5",
			6:  "2914895187c3f38b3768394d55bef5d3c8ad2e81575bd4790a1f3f922d831c9a",
			7:  "9f2396f3dde750606f629b3ae0e7bfcee5146c20faa0c63f568c09f6051119e0",
			8:  "1eb6540efc98d46a5e743b6c3004f738113b516f860322855ef67ad925fbceda",
			9:  "3c43301750257c638c6bc98bdbb84f55221e924a28c6c6076b8873d748acf780",
			10: "f1c12de7a26dcb79bb9626c3ac61dd973693927a06304c1b5f967f25b69fb0fe",
			11: "7c1d9db1a11f01e63c12e1acb10a80c55272ab368e0bb17e4b44367484cd4ab9",
			12: "b827e9ae932569d4ec9eef9620af430e6fb1588a744255767ee547c762d97152",
			13: "d67d4e3059da9d3a2fea648561838cf7964a6211e898c9def46f8860435ceff7",
			14: "9f647574915e89d094b2a3ae483e5e557ca60aeede0615d7151f200159dac3e3",
			18: "e2c6a4fba4ababf4182b78ea907f8a9031ff41b3b7699a98368a3a62e3f5ba41",
		},
	}
	proof, err := testData.getProof()
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyInsertionProof(
		testData.email,
		testData.signedKeyList,
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
		email:         "pro@proton.black",
		vrfProof:      "60fbad6a1d20d5dc2753dcd643ab9226444994cc9b00214901596bbd59d3219da8063f2c9e65f6a28b9672444742185ca570fc152e78c080ea1a0e6d16f1f60205afa2027193bba2f0ea72363ec2510a", //nolint: lll
		rootHash:      "d61969ba4ab30507809aec0d3a49810433c9abc5a28c17b1f160692766b60595",
		revision:      0,
		signedKeyList: `[{"Primary":1,"Flags":3,"Fingerprint":"552acf5984e187edc0682d84395469b11f04cd64","SHA256Fingerprints":["ef445078489f7feec6af4b0e23f9bad8bc883e4c4166bd81478851cfa9090b6c","92c8c4a69a75f83af7c13c9049c94e7f75b3ccd8ca33c6c302cd04286a556387"]},{"Primary":0,"Flags":3,"Fingerprint":"5372de721b9971518273581e04cd9dc25fbae509","SHA256Fingerprints":["4380c60bc440132428390868598b9872ed4efad6a87e2c7aad25807fe7f675b0","bad8f749883cc2873d09e66cfce2604855b85aaaa7215311d444e2b60a96cd59"]}]`, //nolint: lll
		neighbours: map[uint8]string{
			0:  "d6a32d69fe74b4f4c7783624a1f9dc29faae7abedb9f7a35667b403b54949c51",
			1:  "dc5dd14729a0e5ec0b9947517c8dbc5900ed9b45cae579b81421a2c7474a4bc5",
			2:  "e1666a9c0be19d3fa50227a3421209459a83f8922ac4da44262a13176b5682b1",
			3:  "59af0d29c47e774217a867c193ad43dccf8aa841d4ba8341f504a3ae08dd500a",
			4:  "a6a3dd3ec7ee85af3ecde7ae1e769c50fb3fab6f407b1f68635b68bf8bd9f7ab",
			5:  "4c9c6081f317911d4fd41b4a58b21cf64da8d2352abb5a0f43bb0e9d78d9685d",
			6:  "b7500c93afd823e443a57701fc4396a20bc2b930c20b62f34e488a42f4a73b2e",
			7:  "b7500c93afd823e443a57701fc4396a20bc2b930c20b62f34e488a42f4a73b2e",
			8:  "a6c59154f274e6cfc9fc6c85e4c8c63e4c08303960eaf0d97154882c349cac81",
			9:  "135bcd400baa90cae2ef72522e1ed6481d559bbf1869c0fb44ec229d4a11dabd",
			10: "9a6221223169dc031b37e32133ef20ca0b1e0a6a7f1c960415a71852d308db6a",
			11: "80db7974dfa860c3ec31429a7c168364ccb7a3104c298ddc9a22a523edd65806",
			12: "187e1ae64197a1cc4ada1885ca744cd398a5497c7766f00421d9a0b0ced1ad2f",
			13: "66cb75d9d6561ccd765da48c10e9d4641ef0b654ed24e00f5ea07b11da219654",
		},
	}
	proof, err := testData.getProof()
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyInsertionProof(
		testData.email,
		testData.signedKeyList,
		testVRFPublicKey,
		testData.rootHash,
		proof,
	)
	if err == nil {
		t.Fatal("Expected an error, got nil")
	}
}

func TestBadSKL(t *testing.T) {
	t.Parallel()
	testData := &TestData{
		proofType:     presenceProofType,
		email:         "pro@proton.black",
		vrfProof:      "60fbad6a1d20d5dc2753dcd643ab9226444994cc9b00214901596bbd59d3219da8063f2c9e65f6a28b9672444742185ca570fc152e78c080ea1a0e6d16f1f60205afa2027193bba2f0ea72363ec2510a", //nolint: lll
		rootHash:      "d61969ba4ab30507809aec0d3a49810433c9abc5a28c17b1f160692766b60595",
		revision:      0,
		signedKeyList: `[{"Primary":1,"Flags":3,"Fingerprint":"552acf5984e187edc0682d84395469b11f04cd64","SHA256Fingerprints":["ef445078489f7feec6af4b0e23f9bad8bc883e4c4166bd81478851cfa9090b6c","92c8c4a69a75f83af7c13c9049c94e7f75b3ccd8ca33c6c302cd04286a556387"]},{"Primary":0,"Flags":3,"Fingerprint":"5372de721b9971518273581e04cd9dc25fbae509","SHA256Fingerprints":["4380c60bc440132428390868598b9872ed4efad6a87e2c7aad25807fe7f675b0","bad8f749883cc2873d09e66cfce2604855b85aaaa7215311d444e2b60a96cd59"]}]`, //nolint: lll
		neighbours: map[uint8]string{
			0:  "d6a32d69fe74b4f4c7783624a1f9dc29faae7abedb9f7a35667b403b54949c51",
			1:  "dc5dd14729a0e5ec0b9947517c8dbc5900ed9b45cae579b81421a2c7474a4bc5",
			2:  "e1666a9c0be19d3fa50227a3421209459a83f8922ac4da44262a13176b5682b1",
			3:  "59af0d29c47e774217a867c193ad43dccf8aa841d4ba8341f504a3ae08dd500a",
			4:  "a6a3dd3ec7ee85af3ecde7ae1e769c50fb3fab6f407b1f68635b68bf8bd9f7ab",
			5:  "4c9c6081f317911d4fd41b4a58b21cf64da8d2352abb5a0f43bb0e9d78d9685d",
			6:  "b7500c93afd823e443a57701fc4396a20bc2b930c20b62f34e488a42f4a73b2e",
			7:  "b7500c93afd823e443a57701fc4396a20bc2b930c20b62f34e488a42f4a73b2e",
			8:  "a6c59154f274e6cfc9fc6c85e4c8c63e4c08303960eaf0d97154882c349cac81",
			9:  "135bcd400baa90cae2ef72522e1ed6481d559bbf1869c0fb44ec229d4a11dabd",
			10: "9a6221223169dc031b37e32133ef20ca0b1e0a6a7f1c960415a71852d308db6a",
			11: "80db7974dfa860c3ec31429a7c168364ccb7a3104c298ddc9a22a523edd65806",
			12: "187e1ae64197a1cc4ada1885ca744cd398a5497c7766f00421d9a0b0ced1ad2f",
			13: "66cb75d9d6561ccd765da48c10e9d4641ef0b654ed24e00f5ea07b11da219654",
		},
	}
	proof, err := testData.getProof()
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyInsertionProof(
		testData.email,
		testData.signedKeyList,
		testVRFPublicKey,
		testData.rootHash,
		proof,
	)
	if err == nil {
		t.Fatal("Expected an error, got nil")
	}
}
