package ktclient

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/ctutil"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
)

func verifyCert(chainHash, pemEncodedCerts []byte) error {
	x509Encoded, rest := pem.Decode(pemEncodedCerts)
	cert, err := x509.ParseCertificate(x509Encoded.Bytes)
	if err != nil {
		return fmt.Errorf("cannot parse first certificate: %w", err)
	}

	// (a) Verify that the Subject Alternate Name values contain the chain hash
	hashStr, found := fmt.Sprintf("%x", chainHash), false
	for _, altName := range cert.DNSNames {
		clean := strings.ReplaceAll(altName, ".", "")
		if len(clean) > len(hashStr) && hashStr == clean[:len(hashStr)] {
			found = true
			break //nolint:nlreturn
		}
	}
	if !found {
		return fmt.Errorf("%w: 'ChainHash' not found in alt. name", ErrCert)
	}

	// (b) Verify CT signatures from second certificate against ct_logs
	signingCertPEM, _ := pem.Decode(rest) // reuse 'rest' for step (c)
	signingCert, err := x509.ParseCertificate(signingCertPEM.Bytes)
	if err != nil {
		return fmt.Errorf("cannot parse second certificate: %w", err)
	}
	if err = verifySCT(cert, signingCert); err != nil {
		return err
	}

	// (c) Verify certificate chain (leading to hardcoded LE certificate)
	leCertPEM, err := ioutil.ReadFile(absPath(_letsEncryptCertificate))
	if err != nil {
		return fmt.Errorf("LE certificate: %w", err)
	}
	intermediates, roots := x509.NewCertPool(), x509.NewCertPool()
	intermediates.AppendCertsFromPEM(rest)
	roots.AppendCertsFromPEM(leCertPEM)
	verOpts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}
	if _, err := cert.Verify(verOpts); err != nil {
		return fmt.Errorf("inconsistent certificate chain: %w", err)
	}

	return nil
}

// See RFC 6962, sections 3.1 and 3.2.
func verifySCT(cert, leCert *x509.Certificate) error {
	if len(_ctPublicKeys) == 0 {
		if err := parseCTPublicKeys(_ctLogs); err != nil {
			return err
		}
	}
	scts, err := x509util.ParseSCTsFromSCTList(&cert.SCTList)
	if err != nil {
		return fmt.Errorf("parse SCTs: %w", err)
	}
	if len(scts) == 0 {
		return fmt.Errorf("%w: no SCT found in certificate", ErrSCT)
	}

	for _, sct := range scts {
		logID := base64.StdEncoding.EncodeToString(sct.LogID.KeyID[:])
		key, ok := _ctPublicKeys[logID]
		if !ok {
			return fmt.Errorf("%w: no public key available", ErrSCT)
		}
		pk, err := ct.PublicKeyFromB64(key)
		if err != nil {
			return fmt.Errorf("%w: cannot parse public key", ErrSCT)
		}
		err = ctutil.VerifySCT(pk, []*x509.Certificate{cert, leCert}, sct, true)
		if err != nil {
			return fmt.Errorf("SCT with log ID %s: %w", logID, err)
		}
	}

	return nil
}

func parseCTPublicKeys(logsFilename string) error {
	jsonRaw, err := ioutil.ReadFile(absPath(logsFilename))
	if err != nil {
		return fmt.Errorf("parseCTPublicKeys: %w", err)
	}
	var operators struct {
		Operators []struct {
			Logs []struct {
				LogID string `json:"log_id"`
				Key   string `json:"Key"`
			}
		}
	}
	err = json.Unmarshal(jsonRaw, &operators)
	if err != nil {
		return fmt.Errorf("parseCTPublicKeys: %w", err)
	}
	_ctPublicKeys = make(map[string]string)
	for _, op := range operators.Operators {
		for _, log := range op.Logs {
			_ctPublicKeys[log.LogID] = log.Key
		}
	}
	if len(_ctPublicKeys) == 0 {
		return fmt.Errorf("%w: no CT public keys available", ErrSCT)
	}

	return nil
}

// This function returns the absolute path of the given file, relative to this
// package's root.
func absPath(f string) string {
	path := "/src/github.com/ProtonMail/pm-key-transparency-go-client/" + f

	return os.Getenv("GOPATH") + path
}
