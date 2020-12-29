package api_test

import (
	"fmt"
	"ktclient"
	"ktclient/helpers/api"
	"testing"
)

func TestLiveAPI(t *testing.T) {
	data := &ktclient.Data{
		Email:         []byte("testkt@protonmail.blue"),
		SignedKeyList: []byte("[{\"Primary\":1,\"Flags\":3,\"Fingerprint\":\"d13f0f38a39e89a51c1b78ee2d3dfd91f0ae410e\",\"SHA256Fingerprints\":[\"a2bc20d55c951e60ce9d9250bd7cdb011564b29797b575b9a342d211cacac752\",\"3e41fa1a3a06a30866d24fd83aef33e82508a417b7338f3fb9caee12781ff320\"]},{\"Primary\":0,\"Flags\":3,\"Fingerprint\":\"e58be912d7d1496242a0e2e7c2fb1ebe40827a37\",\"SHA256Fingerprints\":[\"79bede9527be6b05103de4d8217bd8dadf7cc080b9c21462f1ddd4f160929d60\",\"2a8afc978459ba42e3a64806acedc931c4bcc755d2dfd2d0ffaed88f923da2a7\"]},{\"Primary\":0,\"Flags\":3,\"Fingerprint\":\"ec50bbef6936be962650cbb53d973820a422fcf0\",\"SHA256Fingerprints\":[\"f468211106512bcec301e8eaa4799b038d83739ff5fbb2ab3e1bcd02ab7df012\",\"660f2d02e99c5a6a2518c40c852bebf7f1e22fcb18c3c8f1d7447cf5e635bf18\"]}]"), //nolint:lll
	}

	fmt.Print(" --> GET kt/epochs ... ")
	epochIDs, err := api.GetEpochIDs()
	if err != nil {
		t.Fatal(err)
	}
	if len(epochIDs) == 0 {
		t.Fatal("No epoch IDs received")
	}
	epochID := epochIDs[0]
	fmt.Printf("OK (got %d epochs)\n", len(epochIDs))

	fmt.Printf(" --> GET kt/epochs/%d ... ", epochID)
	if err := api.GetEpochData(epochID, data); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("OK\n")

	fmt.Printf(" --> GET kt/epochs/%d/proof/%s ... ", epochID, data.Email)
	if err := api.GetProofData(epochID, data); err != nil {
		t.Fatal(err)
	}
	fmt.Println("OK")
	if err := data.Verify(); err != nil {
		t.Fatal(err)
	}
	fmt.Printf(" --- Full proof verified.\n")
}
