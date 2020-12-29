package ktclient

import (
	"crypto/rand"
	"encoding/hex"
	"io/ioutil"
	mathrand "math/rand"
	"testing"
)

var (
	logDir  = "testdata/logs/"
	certDir = "testdata/certs/"
)

func TestGoodProof(t *testing.T) {
	t.Parallel()
	goodLog := logDir + "good_log.json"
	if err := parseCTPublicKeys(goodLog); err != nil {
		t.Fatal(err)
	}
	if err := good.Verify(); err != nil {
		t.Error(err)
	}
}

// Tests verification on random proof, and on single fields corruption of a
// good proof.
func TestBadMerkleProofs(t *testing.T) {
	t.Parallel()
	badInputs := [9]Data{
		*good, *good, *good, *good, *good, *good, *good, *good,
		*randomInput(),
	}
	badInputs[0].Email = bad.Email
	badInputs[1].SignedKeyList = bad.SignedKeyList
	badInputs[2].Revision = bad.Revision
	badInputs[3].VRFProof = bad.VRFProof
	badInputs[4].Neighbours = bad.Neighbours
	badInputs[5].RootHash = bad.RootHash
	badInputs[6].PreviousChainHash = bad.PreviousChainHash
	badInputs[7].ChainHash = bad.ChainHash

	goodLog := logDir + "good_log.json"
	if err := parseCTPublicKeys(goodLog); err != nil {
		t.Fatal(err)
	}

	var err error
	for _, data := range badInputs {
		if err = data.Verify(); err == nil {
			t.Fatal("expected bad Merkle proof to fail")
		}
	}
}

// Tests verification on corrupt ct_log operators.
func TestBadSCTLogs(t *testing.T) {
	badLogs := []string{
		"corrupt_ct_log_id.json",
		"corrupt_ct_key.json",
	}
	for _, badLog := range badLogs {
		if err := parseCTPublicKeys(logDir + badLog); err != nil {
			t.Fatal(err)
		}
		if err := good.Verify(); err == nil {
			t.Fatal("expected bad SCT proof to fail")
		}
	}
}

func TestSCTBadCert(t *testing.T) {
	goodLog := logDir + "good_log.json"
	if err := parseCTPublicKeys(goodLog); err != nil {
		t.Fatal(err)
	}
	badCert, err := ioutil.ReadFile(certDir + "bad_cert")
	if err != nil {
		t.Fatal(err)
	}
	if err = verifyCert(good.ChainHash, badCert); err == nil {
		t.Fatal("expected SCT proof to fail on bad cert")
	}
}

func dcd(s string) []byte {
	res, err := hex.DecodeString(s)
	if err != nil {
		panic("non-hex input")
	}

	return res
}

func BenchmarkVerify(b *testing.B) {
	proof := randomInput()
	for n := 0; n < b.N; n++ {
		proof.Verify() // nolint
	}
}

func randomInput() *Data {
	size := 32
	randomBytes := make([]byte, 6*size)
	rand.Read(randomBytes) //nolint
	email := randomBytes[0*size : (0+1)*size]
	skl := randomBytes[1*size : 2*size]
	proof := randomBytes[2*size : 3*size]
	rootHash := randomBytes[3*size : 4*size]
	prevChainHash := randomBytes[4*size : 5*size]
	chainHash := randomBytes[5*size : 6*size]
	rev := mathrand.Int() //nolint:gosec
	neighbours := make(map[uint8][]byte)
	for i := 0; i < 256; i++ {
		neighbours[uint8(i)] = make([]byte, size)
		rand.Read(neighbours[uint8(i)]) //nolint
	}

	return &Data{
		email, skl, rev, proof,
		neighbours, rootHash, prevChainHash, chainHash,
		nil,
	}
}

var bad = &Data{
	Email:         []byte("marco3@protonmail.blue"),
	SignedKeyList: []byte("[{\"Fingerprint\":\"31fdac6f513a83c575ba92d7ff8b2644208f3d8a\",\"SHA256Fingerprints\":[\"6056661868ad76be81a23cbf61d117ecc5d051d65ae6ac2e765c5a39c30ca9dc\",\"3ff8b7ac7afae405fd2ca9b45f287852c4d3b27f6978df9440aaaf66244e6481\"],\"Primary\":1,\"Flags\":3}]\n"), //nolint:lll
	Revision:      1,
	VRFProof:      dcd("0314eaa98be32751c5500c6a6f1080784911ba45d97487cffb41b4ff596127469df44b0c8f3f29a701359b2a3e66cd9608477aac404232f11ecef7ce2557dbd73f6def8721bae81da3ac3ecf7902fe82dd"), //nolint:lll
	Neighbours: map[uint8][]byte{
		248: dcd("b8ea8d1bea7cb7072906fba274476feef4b3d06ce0d86a739eb6a0fdf1717fe6"),
		250: dcd("9e7d12972a0cbbf39d5bc939ee21185c8ccc7e189e31a54097f3934bb5601833"),
		251: dcd("c583e7322cd8b6918a49e886860a826ccb6e10351d729426ca13d87d2eb5ba01"),
		// (Missing neighbour #252)
		253: dcd("723bfb692cdbcd6d9839a7e023d298a0e45989017fb7cab11ccc79868e1bfe41"),
		254: dcd("82262c8ac1dacd5585800c5226703cd32f66666429c899ab0efc49be105bc77c"),
		255: dcd("4e39d02eb9c310780c4b4fb39e493db040bb91870b57b0f505d1187954c4e22c"),
	},
	RootHash:          dcd("041b9b2f8bb8235c75b89d4805b46c4203edb295045fa0cdade3fd4235d26ea5"),
	PreviousChainHash: dcd("08fb0d25cb1f1cd2d85f277cb2061e78ed64660ed61f11ba4ef322f5ffc20e8b"),
	ChainHash:         dcd("02e38f13bf0f1b9a078f470bf0d858528af5fd226f50d0dd96aceaef54c64248"),
}

var good = &Data{
	Email:         []byte("kt@protonmail.blue"),
	SignedKeyList: []byte("[{\"Primary\":1,\"Flags\":3,\"Fingerprint\":\"0101e52faf9a76ecb4ec9d0626797727831ea0ee\",\"SHA256Fingerprints\":[\"b41659afa6bf8ad3312c46e6ea2025b3dee25a16372516d925f088a54ecf2d4f\",\"71bbb94edf7624c552d9af10b4ce41997e53e9158e645849eec0c6df7553afdb\"]},{\"Primary\":0,\"Flags\":3,\"Fingerprint\":\"7a24efd2f31ad24279d1ba810175014fc317488a\",\"SHA256Fingerprints\":[\"07131fe53986e90d481ef73a9136e3c8c45122f53ee4c017f04491d40f024408\",\"46e6dcd7a17471788c08282c0e4b7a54d35f4046fc07c9146a11d343b1a63770\"]}]"), //nolint:lll
	Revision:      0,
	VRFProof:      dcd("02174f8ddcdaccc2f5faa58d8b36482d2cbb9f9985dffcd410cd9fdba4e08ae4046df9beea80613af0125a7aad7f2424c0370a751e4df785547392c5d484295ae832e15cf49f4d22e9bf3bb93d44388d5e"), //nolint:lll
	Neighbours: map[uint8][]byte{
		252: dcd("5ae1e3d0e0cbf8eb6e169dd431e36e75d6b603de9519d9f012adba2211486a76"),
		254: dcd("87f9f53494633bbee7fe134e70381a1ff50658308ddd84f50b08007e86624947"),
		255: dcd("f12a3959d0a800d6de737eaa4f36abf8a788fbd59a2050b7b59810000adc2b06"),
	},
	RootHash:          dcd("e1e6915b3a260b7de8c7b13b3c2a56fa1891cb07f7c81bd18cf7d3abd9414112"),
	PreviousChainHash: dcd("9042f9d84bd9e10cffb6087c71063fcabffdca31425c5f0be846ce212e41b4ea"),
	ChainHash:         dcd("c37a8c9a0f912269920be5106d176eb4cad03635801720499d4ba46598fb0dcd"),
	// Change to 'Certificates'
	Certificates: []byte("-----BEGIN CERTIFICATE-----\nMIIFjTCCBHWgAwIBAgISBILAD6JTiWePxDOjR1tmVa5lMA0GCSqGSIb3DQEBCwUA\nMDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD\nEwJSMzAeFw0yMDEyMTEwNzM2MzRaFw0yMTAzMTEwNzM2MzRaMCIxIDAeBgNVBAMT\nF2Vwb2NoLmt0LnByb3RvbnRlY2gueHl6MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\nMIIBCgKCAQEAsLHQu7JuIsuH2dZamTryuYSPxtcpK2b273PTLsRrxmK3EwhEFXCg\nnoi61iIjskAH9RjehWsDxMDS4ZnncJNlxIcoWwZOruk5++acw3g2/4zV88YJhg2z\nM11EtjjZoRkaQWx2JERhSTYRuDkLvDQtJ4BlYMZ//gNpr4nBYafraTtj9Fp23Ame\nINWYDSKon2gGX+pd89ZkiToluaYgmQZL7oYuUHNroTEWi1iGdOmCACBCxLvd84AX\n1CSCOZR3vUSVbOKmnTwX7Xf8JqNfiBnJ9/gDjIMfxjy7HkCBEwBhTnaX9zWaM220\nHX81AfsY0hY82Ys5Y6uZk6P1zp+9KJ2OnQIDAQABo4ICqzCCAqcwDgYDVR0PAQH/\nBAQDAgWgMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8E\nAjAAMB0GA1UdDgQWBBRYbBNneclBwrxuXdS5UsltvsezxDAfBgNVHSMEGDAWgBQU\nLrMXt1hWy65QCUDmH6+dixTCxjBVBggrBgEFBQcBAQRJMEcwIQYIKwYBBQUHMAGG\nFWh0dHA6Ly9yMy5vLmxlbmNyLm9yZzAiBggrBgEFBQcwAoYWaHR0cDovL3IzLmku\nbGVuY3Iub3JnLzB7BgNVHREEdDBygldjMzdhOGM5YTBmOTEyMjY5OTIwYmU1MTA2\nZDE3NmViNC5jYWQwMzYzNTgwMTcyMDQ5OWQ0YmE0NjU5OGZiMGRjZC41LjAua3Qu\ncHJvdG9udGVjaC54eXqCF2Vwb2NoLmt0LnByb3RvbnRlY2gueHl6MEwGA1UdIARF\nMEMwCAYGZ4EMAQIBMDcGCysGAQQBgt8TAQEBMCgwJgYIKwYBBQUHAgEWGmh0dHA6\nLy9jcHMubGV0c2VuY3J5cHQub3JnMIIBBAYKKwYBBAHWeQIEAgSB9QSB8gDwAHYA\nXNxDkv7mq0VEsV6a1FbmEDf71fpH3KFzlLJe5vbHDsoAAAF2UPHVzgAABAMARzBF\nAiB0cicJhu8Q5KFo8w8Vu4GjCiIGm0/B2acT6XtSNa/xXgIhAIopalMjXsFVdueS\nTzpG8b5yvgxZfKsIlfbdeJqs2C1lAHYA9lyUL9F3MCIUVBgIMJRWjuNNExkzv98M\nLyALzE7xZOMAAAF2UPHXtQAABAMARzBFAiEAlkO8p25Kzp7DincgsS4C+kCVSw6m\nNqpQfAowYvvZLlUCIDFpvanpb0lF86W5++tXG6tfdT4WvxjlpwA1LVwBKZ1YMA0G\nCSqGSIb3DQEBCwUAA4IBAQCFb1MaV7IkFmecJ8nDpWjjoWEUg4P12ggXytXnxTju\nkp+ysEQde6w2i54vGkoF5PMqZ4B7+3bVdKgWwPGljJ80RreYO98jahUodDXLAHoJ\nivvgJTMXmSkw+1e6RF+c5kBXiTtpG4evZ7Nu2kzIzXKVh8nlk0CaG5CU9kbaoScj\npfdR7s6wuTrOS+D71Xrh67lIPgRi16i1qOJsp3k+a5SUv8plymWoy98zXKqLoChV\nQqt1uNq6ZK1Hatwrfoo1tf43A9o4oaF5slVPZ8XMC7aQuuV0TA7AlTF0MeRIvi1F\nYfLm5eGbOibDYHwVmBtrONqYTB+gnKsAnbdfTPKU+8FJ\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\nMIIEZTCCA02gAwIBAgIQQAF1BIMUpMghjISpDBbN3zANBgkqhkiG9w0BAQsFADA/\nMSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\nDkRTVCBSb290IENBIFgzMB4XDTIwMTAwNzE5MjE0MFoXDTIxMDkyOTE5MjE0MFow\nMjELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUxldCdzIEVuY3J5cHQxCzAJBgNVBAMT\nAlIzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuwIVKMz2oJTTDxLs\njVWSw/iC8ZmmekKIp10mqrUrucVMsa+Oa/l1yKPXD0eUFFU1V4yeqKI5GfWCPEKp\nTm71O8Mu243AsFzzWTjn7c9p8FoLG77AlCQlh/o3cbMT5xys4Zvv2+Q7RVJFlqnB\nU840yFLuta7tj95gcOKlVKu2bQ6XpUA0ayvTvGbrZjR8+muLj1cpmfgwF126cm/7\ngcWt0oZYPRfH5wm78Sv3htzB2nFd1EbjzK0lwYi8YGd1ZrPxGPeiXOZT/zqItkel\n/xMY6pgJdz+dU/nPAeX1pnAXFK9jpP+Zs5Od3FOnBv5IhR2haa4ldbsTzFID9e1R\noYvbFQIDAQABo4IBaDCCAWQwEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8E\nBAMCAYYwSwYIKwYBBQUHAQEEPzA9MDsGCCsGAQUFBzAChi9odHRwOi8vYXBwcy5p\nZGVudHJ1c3QuY29tL3Jvb3RzL2RzdHJvb3RjYXgzLnA3YzAfBgNVHSMEGDAWgBTE\np7Gkeyxx+tvhS5B1/8QVYIWJEDBUBgNVHSAETTBLMAgGBmeBDAECATA/BgsrBgEE\nAYLfEwEBATAwMC4GCCsGAQUFBwIBFiJodHRwOi8vY3BzLnJvb3QteDEubGV0c2Vu\nY3J5cHQub3JnMDwGA1UdHwQ1MDMwMaAvoC2GK2h0dHA6Ly9jcmwuaWRlbnRydXN0\nLmNvbS9EU1RST09UQ0FYM0NSTC5jcmwwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYf\nr52LFMLGMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjANBgkqhkiG9w0B\nAQsFAAOCAQEA2UzgyfWEiDcx27sT4rP8i2tiEmxYt0l+PAK3qB8oYevO4C5z70kH\nejWEHx2taPDY/laBL21/WKZuNTYQHHPD5b1tXgHXbnL7KqC401dk5VvCadTQsvd8\nS8MXjohyc9z9/G2948kLjmE6Flh9dDYrVYA9x2O+hEPGOaEOa1eePynBgPayvUfL\nqjBstzLhWVQLGAkXXmNs+5ZnPBxzDJOLxhF2JIbeQAcH5H0tZrUlo5ZYyOqA7s9p\nO5b85o3AM/OJ+CktFBQtfvBhcJVd9wvlwPsk+uyOy2HI7mNxKKgsBTt375teA2Tw\nUdHkhVNcsAKX1H7GNNLOEADksd86wuoXvg==\n-----END CERTIFICATE-----\n"), //nolint:lll
}
