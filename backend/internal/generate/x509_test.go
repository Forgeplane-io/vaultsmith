package generate

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestGenerateX509CSRProducesMatchingPKCS8AndPKCS10Artifacts(t *testing.T) {
	tests := []struct {
		name               string
		algorithm          X509Algorithm
		signatureAlgorithm x509.SignatureAlgorithm
	}{
		{name: "Ed25519", algorithm: X509AlgorithmEd25519, signatureAlgorithm: x509.PureEd25519},
		{name: "ECDSA P-256", algorithm: X509AlgorithmECDSAP256, signatureAlgorithm: x509.ECDSAWithSHA256},
		{name: "ECDSA P-384", algorithm: X509AlgorithmECDSAP384, signatureAlgorithm: x509.ECDSAWithSHA384},
		{name: "RSA-3072", algorithm: X509AlgorithmRSA3072, signatureAlgorithm: x509.SHA256WithRSA},
		{name: "RSA-4096", algorithm: X509AlgorithmRSA4096, signatureAlgorithm: x509.SHA256WithRSA},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := New().GenerateX509CSR(X509CSRParameters{
				Algorithm: test.algorithm,
				Subject:   &X509Subject{CommonName: x509String("service.synthetic.test")},
			})
			if err != nil {
				t.Fatalf("GenerateX509CSR() error = %v", err)
			}
			if result.Algorithm() != test.algorithm {
				t.Fatalf("algorithm = %q, want %q", result.Algorithm(), test.algorithm)
			}

			privateKey, privateBlock := parseX509PrivateResult(t, result.PrivateBytes())
			assertX509PrivateAlgorithm(t, privateKey, test.algorithm)
			roundTripPrivateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
			if err != nil {
				t.Fatalf("MarshalPKCS8PrivateKey(round trip) error = %v", err)
			}
			if !bytes.Equal(roundTripPrivateDER, privateBlock.Bytes) {
				t.Fatal("PKCS#8 private key is not canonical for the parsed key")
			}

			csr, csrBlock := parseX509CSRResult(t, result.CSRPEM())
			if csr.SignatureAlgorithm != test.signatureAlgorithm {
				t.Fatalf("signature algorithm = %v, want %v", csr.SignatureAlgorithm, test.signatureAlgorithm)
			}
			if err := csr.CheckSignature(); err != nil {
				t.Fatalf("CheckSignature() error = %v", err)
			}
			if !bytes.Equal(csr.Raw, csrBlock.Bytes) {
				t.Fatal("parsed CSR raw bytes do not match the PEM block")
			}

			privateSigner, ok := privateKey.(crypto.Signer)
			if !ok {
				t.Fatalf("parsed private key %T has no public key", privateKey)
			}
			privateSPKI, err := x509.MarshalPKIXPublicKey(privateSigner.Public())
			if err != nil {
				t.Fatalf("MarshalPKIXPublicKey() error = %v", err)
			}
			if !bytes.Equal(privateSPKI, csr.RawSubjectPublicKeyInfo) {
				t.Fatal("CSR public key does not match the serialized private key")
			}

			digest := sha256.Sum256(csr.RawSubjectPublicKeyInfo)
			wantFingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])
			if result.Fingerprint() != wantFingerprint || !validSHA256Fingerprint(result.Fingerprint()) {
				t.Fatalf("fingerprint = %q, want %q", result.Fingerprint(), wantFingerprint)
			}
		})
	}
}

func TestGenerateX509CSRPreservesTypedIdentities(t *testing.T) {
	tests := []struct {
		name    string
		subject *X509Subject
		sans    *X509SANs
	}{
		{
			name:    "common name only",
			subject: &X509Subject{CommonName: x509String("service.synthetic.test")},
		},
		{
			name: "SAN only",
			sans: &X509SANs{
				DNSNames:       []string{"API.Example.test", "xn--bcher-kva.example"},
				IPAddresses:    []string{"192.0.2.10", "2001:db8::10"},
				EmailAddresses: []string{"Ops@example.test", "alerts@example.test"},
				URIs: []string{
					"spiffe://example.test/workload",
					"https://example.test/caf%C3%A9",
					"urn:example:animal:ferret:nose",
					"https://[2001:db8::1]/workload",
					"example://[v1.future]/path",
					"https://user:pass@example.test:8443/path",
				},
			},
		},
		{
			name: "mixed subject and SAN",
			subject: &X509Subject{
				CommonName:         x509String("mïxed.synthetic.test"),
				SerialNumber:       x509String("node-0042"),
				Country:            []string{"US", "DE"},
				Organization:       []string{"Forgeplane", "Synthetic Lab"},
				OrganizationalUnit: []string{"Platform"},
				Locality:           []string{"Berlin"},
				Province:           []string{"Berlin"},
				StreetAddress:      []string{"Example 42"},
				PostalCode:         []string{"10115"},
			},
			sans: &X509SANs{DNSNames: []string{"node.synthetic.test"}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := New().GenerateX509CSR(X509CSRParameters{
				Algorithm: X509AlgorithmEd25519,
				Subject:   test.subject,
				SANs:      test.sans,
			})
			if err != nil {
				t.Fatalf("GenerateX509CSR() error = %v", err)
			}
			csr, _ := parseX509CSRResult(t, result.CSRPEM())
			if err := csr.CheckSignature(); err != nil {
				t.Fatalf("CheckSignature() error = %v", err)
			}
			assertX509Identities(t, csr, test.subject, test.sans)
		})
	}
}

func TestGenerateX509CSRAcceptsExactBounds(t *testing.T) {
	maximumDNSName := strings.Join([]string{
		strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 61),
	}, ".")
	maximumEmail := strings.Repeat("e", 64) + "@" + strings.Join([]string{
		strings.Repeat("f", 63), strings.Repeat("g", 63), strings.Repeat("h", 60),
	}, ".")
	maximumURI := "scheme:" + strings.Repeat("u", maximumX509URIBytes-len("scheme:"))
	dnsNames := make([]string, 0, 61)
	for index := 0; index < 60; index++ {
		dnsNames = append(dnsNames, fmt.Sprintf("host-%d.synthetic.test", index))
	}
	dnsNames = append(dnsNames, maximumDNSName)

	result, err := New().GenerateX509CSR(X509CSRParameters{
		Algorithm: X509AlgorithmEd25519,
		Subject: &X509Subject{
			CommonName:   x509String(strings.Repeat("c", maximumX509SubjectBytes)),
			Country:      []string{"AA", "BB", "CC", "DD", "EE", "FF", "GG", "HH"},
			Organization: []string{"one", "two", "three", "four", "five", "six", "seven", "eight"},
		},
		SANs: &X509SANs{
			DNSNames:       dnsNames,
			IPAddresses:    []string{"192.0.2.1"},
			EmailAddresses: []string{maximumEmail},
			URIs:           []string{maximumURI},
		},
	})
	if err != nil {
		t.Fatalf("GenerateX509CSR(exact bounds) error = %v", err)
	}
	csr, _ := parseX509CSRResult(t, result.CSRPEM())
	if len(csr.DNSNames)+len(csr.IPAddresses)+len(csr.EmailAddresses)+len(csr.URIs) != maximumX509SANs {
		t.Fatalf("CSR SAN count = %d, want %d", len(csr.DNSNames)+len(csr.IPAddresses)+len(csr.EmailAddresses)+len(csr.URIs), maximumX509SANs)
	}
	if csr.DNSNames[len(csr.DNSNames)-1] != maximumDNSName || csr.EmailAddresses[0] != maximumEmail || csr.URIs[0].String() != maximumURI {
		t.Fatal("CSR changed a maximum-length identity")
	}
}

func TestGenerateX509CSRRejectsInvalidIdentityBeforeRandomness(t *testing.T) {
	validSubject := func(value string) *X509Subject { return &X509Subject{CommonName: x509String(value)} }
	validSAN := func() *X509SANs { return &X509SANs{DNSNames: []string{"service.synthetic.test"}} }
	tests := []struct {
		name       string
		parameters X509CSRParameters
	}{
		{name: "unsupported algorithm", parameters: X509CSRParameters{Algorithm: "dsa", Subject: validSubject("service.synthetic.test")}},
		{name: "no identity", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519}},
		{name: "empty subject object", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, Subject: &X509Subject{}, SANs: validSAN()}},
		{name: "empty supplied common name", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, Subject: &X509Subject{CommonName: x509String("")}, SANs: validSAN()}},
		{name: "empty supplied serial number", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, Subject: &X509Subject{CommonName: x509String("service.synthetic.test"), SerialNumber: x509String("")}}},
		{name: "empty SAN object", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, Subject: validSubject("service.synthetic.test"), SANs: &X509SANs{}}},
		{name: "DN without common name or SAN", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, Subject: &X509Subject{Organization: []string{"Forgeplane"}}}},
		{name: "DN leading Unicode whitespace", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, Subject: validSubject("\u00a0service.synthetic.test")}},
		{name: "DN ASCII control", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, Subject: validSubject("service\x7f.synthetic.test")}},
		{name: "DN invalid UTF-8", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, Subject: validSubject(string([]byte{0xff}))}},
		{name: "DN over byte limit", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, Subject: validSubject(strings.Repeat("a", maximumX509SubjectBytes+1))}},
		{name: "empty supplied DN array", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, Subject: &X509Subject{CommonName: x509String("service.synthetic.test"), Organization: []string{}}}},
		{name: "too many DN values", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, Subject: &X509Subject{CommonName: x509String("service.synthetic.test"), Organization: sequence("org", maximumX509SubjectValues+1)}}},
		{name: "duplicate DN value", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, Subject: &X509Subject{CommonName: x509String("service.synthetic.test"), Organization: []string{"same", "same"}}}},
		{name: "invalid country", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, Subject: &X509Subject{CommonName: x509String("service.synthetic.test"), Country: []string{"de"}}}},
		{name: "DNS non-ASCII", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, SANs: &X509SANs{DNSNames: []string{"bücher.example"}}}},
		{name: "DNS empty label", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, SANs: &X509SANs{DNSNames: []string{"service..example"}}}},
		{name: "DNS wildcard is not a label", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, SANs: &X509SANs{DNSNames: []string{"*.example.test"}}}},
		{name: "email display name", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, SANs: &X509SANs{EmailAddresses: []string{"Operator <ops@example.test>"}}}},
		{name: "email non-ASCII", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, SANs: &X509SANs{EmailAddresses: []string{"öps@example.test"}}}},
		{name: "IP is not canonical", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, SANs: &X509SANs{IPAddresses: []string{"2001:DB8::1"}}}},
		{name: "scoped IP cannot be encoded in a SAN", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, SANs: &X509SANs{IPAddresses: []string{"fe80::1%eth0"}}}},
		{name: "IPv4-mapped IPv6 would be collapsed by the encoder", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, SANs: &X509SANs{IPAddresses: []string{"::ffff:192.0.2.1"}}}},
		{name: "URI is relative", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, SANs: &X509SANs{URIs: []string{"relative/path"}}}},
		{name: "URI must already be ASCII encoded", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, SANs: &X509SANs{URIs: []string{"https://example.test/café"}}}},
		{name: "URI would be normalized", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, SANs: &X509SANs{URIs: []string{"https://example.test/a b"}}}},
		{name: "opaque URI contains a space", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, SANs: &X509SANs{URIs: []string{"urn:a b"}}}},
		{name: "opaque URI contains a non-RFC delimiter", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, SANs: &X509SANs{URIs: []string{"urn:a|b"}}}},
		{name: "URI query contains invalid percent encoding", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, SANs: &X509SANs{URIs: []string{"https://example.test/?q=%zz"}}}},
		{name: "URI bracketed host is not an IP literal", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, SANs: &X509SANs{URIs: []string{"example://[not-an-ip]/path"}}}},
		{name: "URI bracketed IPv6 is malformed", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, SANs: &X509SANs{URIs: []string{"example://[2001:db8:::1]/path"}}}},
		{name: "URI IPv6 host lacks brackets", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, SANs: &X509SANs{URIs: []string{"example://::1/path"}}}},
		{name: "URI host has two port delimiters", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, SANs: &X509SANs{URIs: []string{"example://host::80/path"}}}},
		{name: "duplicate SAN", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, SANs: &X509SANs{DNSNames: []string{"same.example", "same.example"}}}},
		{name: "too many SANs", parameters: X509CSRParameters{Algorithm: X509AlgorithmEd25519, SANs: &X509SANs{DNSNames: sequence("host", maximumX509SANs+1)}}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			source := &x509CountingReader{}
			generator := New()
			generator.random = source
			result, err := generator.GenerateX509CSR(test.parameters)
			if !errors.Is(err, ErrInvalidParameters) || source.calls != 0 || !emptyX509Result(result) {
				t.Fatalf("invalid request result/error/random calls = %#v/%v/%d", result, err, source.calls)
			}
		})
	}
}

func TestGenerateX509CSRFailsClosedOnRandomnessFailure(t *testing.T) {
	sensitiveFailure := errors.New("sensitive X.509 randomness detail")
	generator := New()
	generator.random = x509ErrorReader{err: sensitiveFailure}
	result, err := generator.GenerateX509CSR(X509CSRParameters{
		Algorithm: X509AlgorithmEd25519,
		Subject:   &X509Subject{CommonName: x509String("service.synthetic.test")},
	})
	if !errors.Is(err, ErrGenerationFailed) || errors.Is(err, sensitiveFailure) || !emptyX509Result(result) {
		t.Fatalf("random failure result/error = %#v/%v", result, err)
	}
}

func parseX509PrivateResult(t *testing.T, privatePEM []byte) (any, *pem.Block) {
	t.Helper()
	if !hasExactlyOneTerminalLF(privatePEM) {
		t.Fatal("private key does not have exactly one terminal LF")
	}
	block, rest := pem.Decode(privatePEM)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(rest) != 0 {
		t.Fatalf("private PEM block = %#v, trailing bytes = %d", block, len(rest))
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey() error = %v", err)
	}
	return privateKey, block
}

func parseX509CSRResult(t *testing.T, csrPEM string) (*x509.CertificateRequest, *pem.Block) {
	t.Helper()
	if !hasExactlyOneTerminalLF([]byte(csrPEM)) {
		t.Fatal("CSR does not have exactly one terminal LF")
	}
	block, rest := pem.Decode([]byte(csrPEM))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 || len(rest) != 0 {
		t.Fatalf("CSR PEM block = %#v, trailing bytes = %d", block, len(rest))
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificateRequest() error = %v", err)
	}
	return csr, block
}

func assertX509PrivateAlgorithm(t *testing.T, privateKey any, algorithm X509Algorithm) {
	t.Helper()
	switch algorithm {
	case X509AlgorithmEd25519:
		key, ok := privateKey.(ed25519.PrivateKey)
		if !ok || len(key) != ed25519.PrivateKeySize {
			t.Fatalf("Ed25519 private key = %T", privateKey)
		}
	case X509AlgorithmECDSAP256, X509AlgorithmECDSAP384:
		key, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok || key.Curve == nil {
			t.Fatalf("ECDSA private key = %T", privateKey)
		}
		wantCurve := elliptic.P256()
		if algorithm == X509AlgorithmECDSAP384 {
			wantCurve = elliptic.P384()
		}
		if key.Curve.Params().Name != wantCurve.Params().Name {
			t.Fatalf("ECDSA curve = %q, want %q", key.Curve.Params().Name, wantCurve.Params().Name)
		}
	case X509AlgorithmRSA3072, X509AlgorithmRSA4096:
		key, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			t.Fatalf("RSA private key = %T", privateKey)
		}
		wantBits := 3072
		if algorithm == X509AlgorithmRSA4096 {
			wantBits = 4096
		}
		if key.N.BitLen() != wantBits || key.Validate() != nil {
			t.Fatalf("RSA private key is invalid or has %d bits, want %d", key.N.BitLen(), wantBits)
		}
	default:
		t.Fatalf("unhandled algorithm %q", algorithm)
	}
}

func assertX509Identities(t *testing.T, csr *x509.CertificateRequest, subject *X509Subject, sans *X509SANs) {
	t.Helper()
	if subject == nil {
		subject = &X509Subject{}
	}
	if csr.Subject.CommonName != stringValue(subject.CommonName) || csr.Subject.SerialNumber != stringValue(subject.SerialNumber) {
		t.Fatalf("CSR scalar subject = %q/%q, want %q/%q", csr.Subject.CommonName, csr.Subject.SerialNumber, stringValue(subject.CommonName), stringValue(subject.SerialNumber))
	}
	assertStringSet(t, "country", csr.Subject.Country, subject.Country)
	assertStringSet(t, "organization", csr.Subject.Organization, subject.Organization)
	assertStringSet(t, "organizational unit", csr.Subject.OrganizationalUnit, subject.OrganizationalUnit)
	assertStringSet(t, "locality", csr.Subject.Locality, subject.Locality)
	assertStringSet(t, "province", csr.Subject.Province, subject.Province)
	assertStringSet(t, "street address", csr.Subject.StreetAddress, subject.StreetAddress)
	assertStringSet(t, "postal code", csr.Subject.PostalCode, subject.PostalCode)

	if sans == nil {
		sans = &X509SANs{}
	}
	if !equalStrings(csr.DNSNames, sans.DNSNames) || !equalStrings(csr.EmailAddresses, sans.EmailAddresses) {
		t.Fatalf("CSR DNS/email SANs = %#v/%#v, want %#v/%#v", csr.DNSNames, csr.EmailAddresses, sans.DNSNames, sans.EmailAddresses)
	}
	gotIPs := make([]string, len(csr.IPAddresses))
	for index, address := range csr.IPAddresses {
		gotIPs[index] = address.String()
	}
	if !equalStrings(gotIPs, sans.IPAddresses) {
		t.Fatalf("CSR IP SANs = %#v, want %#v", gotIPs, sans.IPAddresses)
	}
	gotURIs := make([]string, len(csr.URIs))
	for index, uri := range csr.URIs {
		gotURIs[index] = uri.String()
	}
	if !equalStrings(gotURIs, sans.URIs) {
		t.Fatalf("CSR URI SANs = %#v, want %#v", gotURIs, sans.URIs)
	}

	wantExtensions := 0
	if len(sans.DNSNames)+len(sans.IPAddresses)+len(sans.EmailAddresses)+len(sans.URIs) > 0 {
		wantExtensions = 1
	}
	if len(csr.Extensions) != wantExtensions || wantExtensions == 1 && (csr.Extensions[0].Critical || csr.Extensions[0].Id.String() != "2.5.29.17") {
		t.Fatalf("CSR extensions = %#v, want only the typed SAN extension", csr.Extensions)
	}
}

func assertStringSet(t *testing.T, name string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("CSR %s values = %#v, want %#v", name, got, want)
	}
	values := make(map[string]struct{}, len(want))
	for _, value := range want {
		values[value] = struct{}{}
	}
	for _, value := range got {
		if _, ok := values[value]; !ok {
			t.Fatalf("CSR %s values = %#v, want %#v", name, got, want)
		}
	}
}

func emptyX509Result(result X509CSRResult) bool {
	return len(result.PrivateBytes()) == 0 && result.Algorithm() == "" && result.CSRPEM() == "" && result.Fingerprint() == ""
}

func sequence(prefix string, count int) []string {
	values := make([]string, count)
	for index := range values {
		values[index] = fmt.Sprintf("%s-%d.example", prefix, index)
	}
	return values
}

func x509String(value string) *string {
	return &value
}

type x509ErrorReader struct {
	err error
}

func (r x509ErrorReader) Read([]byte) (int, error) {
	return 0, r.err
}

type x509CountingReader struct {
	calls int
}

func (r *x509CountingReader) Read([]byte) (int, error) {
	r.calls++
	return 0, errors.New("unexpected X.509 randomness request")
}
