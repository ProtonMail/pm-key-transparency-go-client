# This repository has been open sourced: https://github.com/ProtonMail/pm-key-transparency-go-client

# ktclient

A Go package that verifies ProtonMail's Key Transparency proofs.

## Usage

#### Against local data
A key transparency proof is encoded in a `ktclient.Data` object consisting of
compulsory fields:
```
type ktclient.Data struct {
	Email             []byte
	SignedKeyList     []byte
	Revision          int
	VRFProof          []byte
	Neighbours        map[uint8][]byte // In hashing order
	RootHash          []byte
	PreviousChainHash []byte
	ChainHash         []byte
	Certificates      []byte
}
```
The corresponding proof can be verified as
follows

```
import "gitlab.protontech.ch/crypto/ktclient"

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
[helpers/api/api_test.go](#).

## Dependencies

- VRF verification https://github.com/r2ishiguro/vrf/ (implements [the VRF spec](https://tools.ietf.org/html/draft-irtf-cfrg-vrf-02))
- Various X509- and SCT-related functionalities: github.com/google/certificate-transparency-go v1.1.1
- Cryptography golang.org/x/crypto
- Code linters github.com/golangci/golangci-lint v1.32.0

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
