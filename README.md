# ktclient

A Go package that verifies ProtonMail's Key Transparency proofs.

## Usage

#### Against local data
A key transparency proof is encoded in a `ktclient.Data` object consisting of
the following compulsory fields:
```
type Data struct {
	// API-specific data
	Email         []byte // This package does not perform email validation
	SignedKeyList []byte
	Revision      int

	// Verifiable Random Functions
	VRFProof []byte

	// Merkle tree insertion
	Neighbours        map[uint8][]byte // In hashing order
	RootHash          []byte           // Merkle tree root hash
	PreviousChainHash []byte
	ChainHash         []byte

	// TLS certificates, separated by '\n'
	Certificates []byte // X509 certificates chain
}
```
The corresponding proof can be verified as
follows

```
import "github.com/ProtonMail/pm-key-transparency-go-client"

var good = &ktclient.Input {
    <Populate all fields>
}
if err := good.Verify(); err != nil {
    // Verification failed!
}
```

#### Against ProtonMail's Key Transparency API

The package `api` provides functions to populate a `ktclient.Data` object using
a KT API, for full proof verification. An example is provided in
[helpers/api/api_test.go](https://github.com/ProtonMail/pm-key-transparency-go-client/blob/master/helpers/api/api_test.go).

## Dependencies

- VRF verification https://github.com/r2ishiguro/vrf/ (implements [the VRF spec](https://tools.ietf.org/html/draft-irtf-cfrg-vrf-08))
- Various X509- and SCT-related functionalities: [certificate-transparency-go](https://github.com/google/certificate-transparency-go) v1.1.1
- Cryptography [x/crypto](https://golang.org/x/crypto)
- Code linters [golangci-lint](https://github.com/golangci/golangci-lint) v1.32.0

Refer to [go.mod](https://github.com/ProtonMail/pm-key-transparency-go-client/blob/master/go.mod) for an up-to-date list.

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
