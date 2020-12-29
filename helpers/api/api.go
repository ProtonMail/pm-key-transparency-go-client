// Package api helps to perform http requests to ProtonMail's KT api.
package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"ktclient"
	"net/http"
)

type apiResp struct {
	Code   int `json:"Code"`
	Epochs []struct {
		EpochID int
	} `json:"Epochs"`
	EpochID       int      `json:"EpochID"`
	TreeHash      string   `json:"TreeHash"`
	ChainHash     string   `json:"ChainHash"`
	PrevChainHash string   `json:"PrevChainHash"`
	Certificate   string   `json:"Certificate"`
	Neighbors     []string `json:"Neighbors"`
	Revision      int      `json:"Revision"`
	Proof         string   `json:"Proof"`
}

// GetEpochIDs performs GET /epochs, verifies the return code, and returns the
// list of epochIDs.
func GetEpochIDs() ([]int, error) {
	var resp apiResp
	url := baseURL + "/epochs"
	if err := get(url, &resp); err != nil {
		return nil, fmt.Errorf("error in GET %s: %w", url, err)
	}
	epochIDs := make([]int, 0)
	for _, e := range resp.Epochs {
		epochIDs = append(epochIDs, e.EpochID)
	}

	return epochIDs, nil
}

// GetEpochData performs GET /epoch/<epochID>, verifies the return code, and
// populates the epoch-related fields of the given ktclient.Data object:
// RootHash, ChainHash, PreviousChainHash, and Certificates.
func GetEpochData(id int, data *ktclient.Data) error {
	url := baseURL + "/epochs/" + fmt.Sprint(id)
	var resp apiResp
	if err := get(url, &resp); err != nil {
		return fmt.Errorf("error in GET %s: %w", url, err)
	}
	data.RootHash = dcd(resp.TreeHash)
	data.ChainHash = dcd(resp.ChainHash)
	data.PreviousChainHash = dcd(resp.PrevChainHash)
	data.Certificates = []byte(resp.Certificate)

	return nil
}

// GetProofData performs GET /epochs/<epochID>/proof/<email>, verifies the
// return code, and populates the proof-related fields of the given
// ktclient.Data object: Revision, VRFProof, and Neighbours.
func GetProofData(id int, data *ktclient.Data) error {
	if data.Email == nil {
		return fmt.Errorf("%w: no email in ktclient.Data", ErrMissingData)
	}
	url := baseURL + "/epochs/" + fmt.Sprintf("%d/proof/%s", id, data.Email)
	var resp apiResp
	if err := get(url, &resp); err != nil {
		return fmt.Errorf("error in GET %s: %w", url, err)
	}
	data.Revision = resp.Revision
	data.VRFProof = dcd(resp.Proof)
	l := len(resp.Neighbors)
	if l < 256 {
		return fmt.Errorf("%w: response has %d neighbours", ErrBadResponse, l)
	}
	data.Neighbours = make(map[uint8][]byte)
	for i := 0; i < 255; i++ {
		if resp.Neighbors[i] != "" {
			data.Neighbours[uint8(255-i)] = dcd(resp.Neighbors[i])
		}
	}

	return nil
}

func dcd(s string) []byte {
	res, err := hex.DecodeString(s)
	if err != nil {
		panic("non-hex input")
	}

	return res
}

// Performs GET <url> and populates 'x' with the response JSON fields.
func get(url string, x *apiResp) error {
	client := &http.Client{}
	ctx := context.Background()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error in request: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck
	raw, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("cannot read request body: %w", err)
	}
	if err := json.Unmarshal(raw, x); err != nil {
		return fmt.Errorf("error decoding request body: %w", err)
	}
	if x.Code != 1000 {
		return fmt.Errorf("%w: response code %d", ErrBadResponse, x.Code)
	}

	return nil
}
