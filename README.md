# This repository has been open sourced: https://github.com/ProtonMail/pm-key-transparency-go-client

# ktclient

A Go package that verifies ProtonMail's Key Transparency proofs.

## Usage

### Verify a proof
A key transparency proof is encoded in a `ktclient.InsertionProof` object consisting of
compulsory fields:
```go
type InsertionProof struct {
	ProofType   int // absence, obsolescence or existence
	Revision    int // revision of the skl
	VRFProofHex string // vrf proof
	Neighbours  map[uint8][]byte // merkle tree proof
}
```
The corresponding proof can be verified as
follows

```go
import ktclient "github.com/ProtonMail/pm-key-transparency-go-client"

err := ktclient.VerifyInsertionProof(
	email, // address email
	signedKeyList, // address signed key list to verify
	vrfPublicKeyBase64, // vrf public key
	rootHashHex, // epoch root hash
	proof, // proof that the SKL is in the merkle tree
)
if err != nil {
    // Verification failed!
}
```

### Verify an epoch

A key transparency epoch is encoded in a `ktclient.Epoch` object consisting of
compulsory fields:
```go
type Epoch struct {
	EpochID           int
	PreviousChainHash string
	CertificateChain  string
	CertificateIssuer int
	TreeHash          string
	ChainHash         string
	CertificateTime   int64
}
```
The corresponding proof can be verified as
follows

```go
import ktclient "github.com/ProtonMail/pm-key-transparency-go-client"

notBefore, err := ktclient.VerifyEpoch(
	epoch,
	baseDomain,
	currentUnixTime,
)
if err != nil {
    // Verification failed!
}
```

## Dependencies

- VRF verification `github.com/ProtonMail/go-ecvrf` (implements [the VRF spec](https://tools.ietf.org/html/draft-irtf-cfrg-vrf-02))
- Various X509- and SCT-related functionalities: `github.com/google/certificate-transparency-go` v1.1.1
- Code linters `github.com/golangci/golangci-lint` v1.32.0

Refer to [go.mod](#) for an up-to-date list.

## Contribute

Code guidelines are roughly dictated by the selected linters. Commands `make
install-linters, make lint` and `make test` are provided.

Run benchmarks with
```
$ make bench
go test -bench=.
goos: linux
goarch: amd64
pkg: kt
BenchmarkVerify-8   	 1985052	       560 ns/op
PASS
ok  	kt	2.853s
```
