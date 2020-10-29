package ktclient

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"time"

	ct "github.com/google/certificate-transparency-go"
	"github.com/google/certificate-transparency-go/ctutil"
	"github.com/google/certificate-transparency-go/x509"
	"github.com/google/certificate-transparency-go/x509util"
	"github.com/pkg/errors"
)

// Epoch contains all the information necessary
// to verify the epoch certificate and inclusion in key transparency.
type Epoch struct {
	EpochID           int
	PreviousChainHash string
	CertificateChain  string
	CertificateIssuer int
	TreeHash          string
	ChainHash         string
	CertificateTime   int64
}

// VerifyEpoch will verify the epoch's certificate, the CT log signature
// the chain hash consistency and the alternate name validity.
// It returns the certificate's NotBefore value or an error if one check failed.
func VerifyEpoch(
	epoch *Epoch,
	baseDomain string,
	currentUnixTime int64,
) (int64, error) {
	// (a) Parse certificates
	cert, rest, err := convertPEMEncodedCertToX509Cert([]byte(epoch.CertificateChain))
	if err != nil {
		return 0, err
	}

	// (b) Verify CT signatures from second certificate against ct_logs
	signingCertPEM, _ := pem.Decode(rest) // reuse 'rest' for step (c)
	signingCert, err := x509.ParseCertificate(signingCertPEM.Bytes)
	if err != nil {
		return 0, errors.Wrap(err, "ktclient: cannot parse cert")
	}
	if err = verifySCT(cert, signingCert); err != nil {
		return 0, err
	}

	// (c) Verify certificate chain (leading to hardcoded LE certificate)
	err = verifyCertificateChain(epoch.CertificateIssuer, cert, rest, currentUnixTime)
	if err != nil {
		return 0, err
	}

	// (d) Check that hash(previous_hash || rootHash) = chainHash,
	chainHash, err := verifyChainHash(epoch)
	if err != nil {
		return 0, err
	}

	// (e) Verify that the Subject Alternate Name values contain the chain hash
	err = verifyAlternateName(cert, chainHash, epoch.EpochID, epoch.CertificateTime, baseDomain)
	if err != nil {
		return 0, err
	}

	return cert.NotBefore.Unix(), nil
}

func verifyCertificateChain(certificateIssuer int, cert *x509.Certificate, rest []byte, currentUnixTime int64) error {
	var certPEM []byte
	switch certificateIssuer {
	case letsEncryptIssuer:
		certPEM = []byte(letsEncryptCertificate)
	case zeroSSLIssuer:
		certPEM = []byte(zeroSSLCertificate)
	default:
		return errors.Wrapf(errCert, "ktclient: invalid issuer code %d", certificateIssuer)
	}

	intermediates, roots := x509.NewCertPool(), x509.NewCertPool()
	intermediates.AppendCertsFromPEM(rest)
	roots.AppendCertsFromPEM(certPEM)
	var currentTime time.Time
	if currentUnixTime <= 0 {
		currentTime = time.Now()
	} else {
		currentTime = time.Unix(currentUnixTime, 0)
	}
	verOpts := x509.VerifyOptions{ //nolint:exhaustruct
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   currentTime,
	}
	if _, err := cert.Verify(verOpts); err != nil {
		return errors.Wrap(err, "ktclient: inconsistent certificate chain")
	}

	return nil
}

func verifyChainHash(epoch *Epoch) ([]byte, error) {
	previousChainHash, err := decodeHex(epoch.PreviousChainHash)
	if err != nil {
		return nil, errors.Wrap(err, "ktclient: invalid encoding of previous chain hash")
	}
	rootHash, err := decodeHex(epoch.TreeHash)
	if err != nil {
		return nil, errors.Wrap(err, "ktclient: invalid encoding of root hash")
	}
	chainHash, err := decodeHex(epoch.ChainHash)
	if err != nil {
		return nil, errors.Wrap(err, "ktclient: invalid encoding of chain hash")
	}
	concat := append(previousChainHash, rootHash...)
	hashFunc := sha256.New()
	hashFunc.Reset()
	_, err = hashFunc.Write(concat)
	if err != nil {
		return nil, errors.Wrap(err, "ktclient: error while hashing")
	}
	if !bytes.Equal(chainHash, hashFunc.Sum(nil)) {
		return nil, fmt.Errorf("%w: inconsistent chainHash", errIntegrity)
	}

	return chainHash, nil
}

func verifyAlternateName(
	cert *x509.Certificate,
	chainHash []byte,
	epochID int,
	certificateTime int64,
	baseDomain string,
) error {
	hashStr := fmt.Sprintf("%x", chainHash)
	expectedName := fmt.Sprintf(
		"%s.%s.%d.%d.%d.%s",
		hashStr[:32],
		hashStr[32:],
		certificateTime,
		epochID,
		nameVersion,
		baseDomain,
	)
	found := false
	for _, altName := range cert.DNSNames {
		if altName == expectedName {
			found = true

			break
		}
	}
	if !found {
		return fmt.Errorf("ktclient: %w: 'ChainHash' not found in alt. name", errCert)
	}

	return nil
}

// See RFC 6962, sections 3.1 and 3.2.
func verifySCT(cert, leCert *x509.Certificate) error {
	publicKeys, err := parseCTPublicKeys(ctLogs)
	if err != nil {
		return err
	}
	scts, err := x509util.ParseSCTsFromSCTList(&cert.SCTList)
	if err != nil {
		return errors.Wrap(err, "ktclient: parse SCTs")
	}
	if len(scts) == 0 {
		return fmt.Errorf("ktclient: %w: no SCT found in certificate", errSCT)
	}

	sctErrors := []error{}

	operators := map[string]bool{}

	for _, sct := range scts {
		logID := base64.StdEncoding.EncodeToString(sct.LogID.KeyID[:])
		key, ok := publicKeys[logID]
		if !ok {
			err := fmt.Errorf("ktclient: %w: no public key available", errSCT)
			sctErrors = append(sctErrors, err)

			continue
		}
		publicKey, err := ct.PublicKeyFromB64(key.PublicKey)
		if err != nil {
			err := fmt.Errorf("ktclient: %w: cannot parse public key: %v", errSCT, err)
			sctErrors = append(sctErrors, err)

			continue
		}
		err = ctutil.VerifySCT(publicKey, []*x509.Certificate{cert, leCert}, sct, true)
		if err != nil {
			err := errors.Wrap(err, fmt.Sprintf("ktclient: SCT with log ID %s", logID))
			sctErrors = append(sctErrors, err)

			continue
		}
		operators[key.OperatorName] = true
	}

	if len(operators) < 2 {
		combinedErr := errSCT
		for _, sctErr := range sctErrors {
			combinedErr = fmt.Errorf("%w; %v", combinedErr, sctErr)
		}

		return fmt.Errorf("ktclient: Certificate was not logged by two distinct operators; %w", combinedErr)
	}

	return nil
}

type ctPublicKey struct {
	OperatorName string
	PublicKey    string
}

func parseCTPublicKeys(logsJSON string) (map[string]ctPublicKey, error) {
	publicKeys := make(map[string]ctPublicKey)
	jsonRaw := []byte(logsJSON)
	var operators struct {
		Operators []struct {
			Name string `json:"name"`
			Logs []struct {
				LogID string `json:"log_id"` //nolint:tagliatelle
				Key   string `json:"Key"`    //nolint:tagliatelle
			}
		}
	}
	err := json.Unmarshal(jsonRaw, &operators)
	if err != nil {
		return nil, errors.Wrap(err, "ktclient: parseCTPublicKeys")
	}
	for _, op := range operators.Operators {
		for _, log := range op.Logs {
			publicKeys[log.LogID] = ctPublicKey{
				OperatorName: op.Name,
				PublicKey:    log.Key,
			}
		}
	}
	if len(publicKeys) == 0 {
		return nil, fmt.Errorf("ktclient: %w: no CT public keys available", errSCT)
	}

	return publicKeys, nil
}

func convertPEMEncodedCertToX509Cert(pemEncodedCert []byte) (*x509.Certificate, []byte, error) {
	x509Encoded, rest := pem.Decode(pemEncodedCert)
	if x509Encoded == nil {
		return nil, nil, errors.New("ktclient: cannot parse cert, decoder returned nil")
	}
	cert, err := x509.ParseCertificate(x509Encoded.Bytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "ktclient: cannot parse cert")
	}

	return cert, rest, nil
}
