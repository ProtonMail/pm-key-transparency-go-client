package ktclient

import _ "embed" // needed for embedded files

// Version the version of the library.
const Version = "0.0.1"

const (
	letsEncryptIssuer = 0
	zeroSSLIssuer     = 1
)

const (
	absenceProofType      = 0
	presenceProofType     = 1
	obsolescenceProofType = 2
)

const nameVersion = 0

//go:embed internal/lets_encrypt.crt
var letsEncryptCertificate string

//go:embed internal/zerossl_certificate.crt
var zeroSSLCertificate string

//go:embed internal/ct_log_list.json
var ctLogs string
