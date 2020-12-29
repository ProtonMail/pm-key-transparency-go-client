package ktclient

var _vrfPubKey = []byte{
	45, 118, 136, 254, 180, 41, 247, 20, 241, 2, 247, 88, 65, 44, 212, 184, 19,
	55, 179, 7, 18, 39, 112, 246, 32, 173, 158, 74, 200, 152, 162, 235,
}

const (
	_letsEncryptCertificate = "internal/8395.crt"
	_ctLogs                 = "internal/ct_log_list.json"
)

// Maps CT logs `log_id:key`.
var _ctPublicKeys map[string]string
