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
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"io"
	"net"
	"net/mail"
	"net/netip"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	maximumX509SubjectValues = 8
	maximumX509SubjectBytes  = 256
	maximumX509SANs          = 64
	maximumX509DNSBytes      = 253
	maximumX509EmailBytes    = 253
	maximumX509URIBytes      = 2048

	// The validated generator inputs keep emitted CSRs well below this bound.
	// The fallback parser rejects larger DER before doing any ASN.1 allocation.
	maximumGeneratedX509CSRBytes = 256 << 10
)

type validatedX509CSR struct {
	algorithm          X509Algorithm
	signatureAlgorithm x509.SignatureAlgorithm
	subject            pkix.Name
	dnsNames           []string
	ipAddresses        []net.IP
	emailAddresses     []string
	uris               []*url.URL
}

// GenerateX509CSR creates an unencrypted PKCS#8 private key and a typed
// PKCS#10 certificate request. Parameters are fully validated before any
// randomness is consumed.
func (g *Generator) GenerateX509CSR(parameters X509CSRParameters) (X509CSRResult, error) {
	validated, err := validateX509CSRParameters(parameters)
	if err != nil {
		return X509CSRResult{}, err
	}
	if g == nil || g.random == nil {
		return X509CSRResult{}, ErrGenerationFailed
	}

	generatedKey, err := generateX509PrivateKey(g.random, validated.algorithm)
	if err != nil {
		return X509CSRResult{}, ErrGenerationFailed
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(generatedKey)
	if err != nil {
		return X509CSRResult{}, ErrGenerationFailed
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	clear(privateDER)
	if len(privatePEM) == 0 {
		return X509CSRResult{}, ErrGenerationFailed
	}
	defer clear(privatePEM)

	parsedKey, err := parsePKCS8Signer(privatePEM)
	if err != nil {
		return X509CSRResult{}, ErrGenerationFailed
	}
	generatedSPKI, err := x509.MarshalPKIXPublicKey(generatedKey.Public())
	if err != nil {
		return X509CSRResult{}, ErrGenerationFailed
	}
	parsedSPKI, err := x509.MarshalPKIXPublicKey(parsedKey.Public())
	if err != nil || !bytes.Equal(generatedSPKI, parsedSPKI) {
		return X509CSRResult{}, ErrGenerationFailed
	}

	template := &x509.CertificateRequest{
		SignatureAlgorithm: validated.signatureAlgorithm,
		Subject:            validated.subject,
		DNSNames:           validated.dnsNames,
		IPAddresses:        validated.ipAddresses,
		EmailAddresses:     validated.emailAddresses,
		URIs:               validated.uris,
	}
	csrDER, err := x509.CreateCertificateRequest(g.random, template, parsedKey)
	if err != nil {
		return X509CSRResult{}, ErrGenerationFailed
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	if len(csrPEM) == 0 {
		return X509CSRResult{}, ErrGenerationFailed
	}

	parsedCSR, err := parseAndCheckCSR(csrPEM, validated, parsedSPKI)
	if err != nil {
		return X509CSRResult{}, ErrGenerationFailed
	}
	digest := sha256.Sum256(parsedCSR.RawSubjectPublicKeyInfo)
	fingerprint := "SHA256:" + base64.RawStdEncoding.EncodeToString(digest[:])

	return X509CSRResult{
		private:     newPrivateMaterial(privatePEM),
		algorithm:   validated.algorithm,
		csrPEM:      string(csrPEM),
		fingerprint: fingerprint,
	}, nil
}

func generateX509PrivateKey(randomReader io.Reader, algorithm X509Algorithm) (crypto.Signer, error) {
	switch algorithm {
	case X509AlgorithmEd25519:
		_, privateKey, err := ed25519.GenerateKey(randomReader)
		if err != nil {
			return nil, err
		}
		return privateKey, nil
	case X509AlgorithmECDSAP256:
		return ecdsa.GenerateKey(elliptic.P256(), randomReader)
	case X509AlgorithmECDSAP384:
		return ecdsa.GenerateKey(elliptic.P384(), randomReader)
	case X509AlgorithmRSA3072:
		return rsa.GenerateKey(randomReader, 3072)
	case X509AlgorithmRSA4096:
		return rsa.GenerateKey(randomReader, 4096)
	default:
		return nil, ErrInvalidParameters
	}
}

func parsePKCS8Signer(privatePEM []byte) (crypto.Signer, error) {
	block, rest := pem.Decode(privatePEM)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, ErrGenerationFailed
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, ErrGenerationFailed
	}
	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, ErrGenerationFailed
	}
	return signer, nil
}

func parseAndCheckCSR(csrPEM []byte, expected validatedX509CSR, spki []byte) (*x509.CertificateRequest, error) {
	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(block.Headers) != 0 || len(rest) != 0 {
		return nil, ErrGenerationFailed
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		if !containsIPvFutureURI(expected.uris) {
			return nil, ErrGenerationFailed
		}
		// crypto/x509 emits valid RFC 3986 IPvFuture URI SANs but its public
		// parser rejects them. Use the bounded DER parser only for this case.
		csr, err = parseCSRWithIPvFuture(block.Bytes)
		if err != nil {
			return nil, ErrGenerationFailed
		}
	}
	if csr.SignatureAlgorithm != expected.signatureAlgorithm {
		return nil, ErrGenerationFailed
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, ErrGenerationFailed
	}
	if !bytes.Equal(csr.RawSubjectPublicKeyInfo, spki) {
		return nil, ErrGenerationFailed
	}
	if !x509CSRMatches(csr, expected) {
		return nil, ErrGenerationFailed
	}
	return csr, nil
}

type rawX509CSR struct {
	Raw                asn1.RawContent
	RequestInfo        rawX509CSRRequestInfo
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

type rawX509CSRRequestInfo struct {
	Raw           asn1.RawContent
	Version       int
	Subject       asn1.RawValue
	PublicKey     rawX509CSRPublicKeyInfo
	RawAttributes []asn1.RawValue `asn1:"tag:0"`
}

type rawX509CSRPublicKeyInfo struct {
	Raw       asn1.RawContent
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

func containsIPvFutureURI(uris []*url.URL) bool {
	for _, uri := range uris {
		if uri != nil && hasIPvFutureAuthority(uri.String()) {
			return true
		}
	}
	return false
}

func parseCSRWithIPvFuture(der []byte) (*x509.CertificateRequest, error) {
	if len(der) > maximumGeneratedX509CSRBytes {
		return nil, ErrGenerationFailed
	}
	var raw rawX509CSR
	if rest, err := asn1.Unmarshal(der, &raw); err != nil || len(rest) != 0 {
		return nil, ErrGenerationFailed
	}
	if raw.RequestInfo.Version != 0 || raw.SignatureValue.BitLength == 0 || raw.SignatureValue.BitLength%8 != 0 {
		return nil, ErrGenerationFailed
	}
	signatureAlgorithm, ok := signatureAlgorithmForOID(raw.SignatureAlgorithm.Algorithm)
	if !ok || !signatureAlgorithmParametersMatch(raw.SignatureAlgorithm, signatureAlgorithm) {
		return nil, ErrGenerationFailed
	}
	publicKey, err := x509.ParsePKIXPublicKey(raw.RequestInfo.PublicKey.Raw)
	if err != nil {
		return nil, ErrGenerationFailed
	}
	var rdns pkix.RDNSequence
	if rest, err := asn1.Unmarshal(raw.RequestInfo.Subject.FullBytes, &rdns); err != nil || len(rest) != 0 {
		return nil, ErrGenerationFailed
	}
	var subject pkix.Name
	subject.FillFromRDNSequence(&rdns)
	extensions, err := parseCSRRequestedExtensions(raw.RequestInfo.RawAttributes)
	if err != nil {
		return nil, ErrGenerationFailed
	}
	dnsNames, emailAddresses, ipAddresses, uris, err := parseCSRSubjectAltNames(extensions)
	if err != nil {
		return nil, ErrGenerationFailed
	}
	rawSignatureAlgorithm, err := asn1.Marshal(raw.SignatureAlgorithm)
	if err != nil {
		return nil, ErrGenerationFailed
	}
	csr := &x509.CertificateRequest{
		Raw:                      raw.Raw,
		RawTBSCertificateRequest: raw.RequestInfo.Raw,
		RawSubjectPublicKeyInfo:  raw.RequestInfo.PublicKey.Raw,
		RawSubject:               raw.RequestInfo.Subject.FullBytes,
		RawSignatureAlgorithm:    rawSignatureAlgorithm,
		Version:                  raw.RequestInfo.Version,
		Signature:                raw.SignatureValue.RightAlign(),
		SignatureAlgorithm:       signatureAlgorithm,
		PublicKey:                publicKey,
		Subject:                  subject,
		DNSNames:                 dnsNames,
		EmailAddresses:           emailAddresses,
		IPAddresses:              ipAddresses,
		URIs:                     uris,
		Extensions:               extensions,
	}
	return csr, nil
}

func signatureAlgorithmForOID(oid asn1.ObjectIdentifier) (x509.SignatureAlgorithm, bool) {
	switch oid.String() {
	case "1.3.101.112":
		return x509.PureEd25519, true
	case "1.2.840.10045.4.3.2":
		return x509.ECDSAWithSHA256, true
	case "1.2.840.10045.4.3.3":
		return x509.ECDSAWithSHA384, true
	case "1.2.840.113549.1.1.11":
		return x509.SHA256WithRSA, true
	default:
		return 0, false
	}
}

func signatureAlgorithmParametersMatch(identifier pkix.AlgorithmIdentifier, algorithm x509.SignatureAlgorithm) bool {
	if algorithm == x509.SHA256WithRSA {
		return bytes.Equal(identifier.Parameters.FullBytes, []byte{5, 0})
	}
	return len(identifier.Parameters.FullBytes) == 0
}

func parseCSRRequestedExtensions(attributes []asn1.RawValue) ([]pkix.Extension, error) {
	type csrAttribute struct {
		ID     asn1.ObjectIdentifier
		Values []asn1.RawValue `asn1:"set"`
	}
	var extensions []pkix.Extension
	seen := make(map[string]bool)
	seenExtensionRequest := false
	for _, rawAttribute := range attributes {
		var attribute csrAttribute
		rest, err := asn1.Unmarshal(rawAttribute.FullBytes, &attribute)
		if err != nil || len(rest) != 0 || len(attribute.Values) == 0 {
			return nil, ErrGenerationFailed
		}
		if !attribute.ID.Equal(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}) {
			continue
		}
		if seenExtensionRequest || len(attribute.Values) != 1 {
			return nil, ErrGenerationFailed
		}
		seenExtensionRequest = true
		var requested []pkix.Extension
		if rest, err := asn1.Unmarshal(attribute.Values[0].FullBytes, &requested); err != nil || len(rest) != 0 {
			return nil, ErrGenerationFailed
		}
		for _, extension := range requested {
			key := extension.Id.String()
			if seen[key] {
				return nil, ErrGenerationFailed
			}
			seen[key] = true
			extensions = append(extensions, extension)
		}
	}
	return extensions, nil
}

func parseCSRSubjectAltNames(extensions []pkix.Extension) (dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL, err error) {
	var sanExtension *pkix.Extension
	for index := range extensions {
		if !extensions[index].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}) {
			continue
		}
		if sanExtension != nil {
			return nil, nil, nil, nil, ErrGenerationFailed
		}
		sanExtension = &extensions[index]
	}
	if sanExtension == nil {
		return nil, nil, nil, nil, nil
	}
	var names []asn1.RawValue
	if rest, unmarshalErr := asn1.Unmarshal(sanExtension.Value, &names); unmarshalErr != nil || len(rest) != 0 {
		return nil, nil, nil, nil, ErrGenerationFailed
	}
	for _, name := range names {
		if name.Class != 2 || name.IsCompound {
			return nil, nil, nil, nil, ErrGenerationFailed
		}
		switch name.Tag {
		case 1:
			if !isIA5String(name.Bytes) {
				return nil, nil, nil, nil, ErrGenerationFailed
			}
			emailAddresses = append(emailAddresses, string(name.Bytes))
		case 2:
			if !isIA5String(name.Bytes) {
				return nil, nil, nil, nil, ErrGenerationFailed
			}
			dnsNames = append(dnsNames, string(name.Bytes))
		case 6:
			if !isIA5String(name.Bytes) {
				return nil, nil, nil, nil, ErrGenerationFailed
			}
			uri, ok := parseAbsoluteURI(string(name.Bytes))
			if !ok {
				return nil, nil, nil, nil, ErrGenerationFailed
			}
			uris = append(uris, uri)
		case 7:
			if len(name.Bytes) != net.IPv4len && len(name.Bytes) != net.IPv6len {
				return nil, nil, nil, nil, ErrGenerationFailed
			}
			ip := net.IP(append([]byte(nil), name.Bytes...))
			if len(name.Bytes) == net.IPv6len && ip.To4() != nil {
				return nil, nil, nil, nil, ErrGenerationFailed
			}
			ipAddresses = append(ipAddresses, ip)
		default:
			return nil, nil, nil, nil, ErrGenerationFailed
		}
	}
	return dnsNames, emailAddresses, ipAddresses, uris, nil
}

func isIA5String(value []byte) bool {
	for _, character := range value {
		if character > 0x7f {
			return false
		}
	}
	return true
}

func validateX509CSRParameters(parameters X509CSRParameters) (validatedX509CSR, error) {
	validated := validatedX509CSR{algorithm: parameters.Algorithm}
	switch parameters.Algorithm {
	case X509AlgorithmEd25519:
		validated.signatureAlgorithm = x509.PureEd25519
	case X509AlgorithmECDSAP256:
		validated.signatureAlgorithm = x509.ECDSAWithSHA256
	case X509AlgorithmECDSAP384:
		validated.signatureAlgorithm = x509.ECDSAWithSHA384
	case X509AlgorithmRSA3072, X509AlgorithmRSA4096:
		validated.signatureAlgorithm = x509.SHA256WithRSA
	default:
		return validatedX509CSR{}, ErrInvalidParameters
	}

	if parameters.Subject != nil {
		subject, ok := validateX509Subject(*parameters.Subject)
		if !ok {
			return validatedX509CSR{}, ErrInvalidParameters
		}
		validated.subject = subject
	}
	if parameters.SANs != nil {
		dnsNames, ipAddresses, emailAddresses, uris, ok := validateX509SANs(*parameters.SANs)
		if !ok {
			return validatedX509CSR{}, ErrInvalidParameters
		}
		validated.dnsNames = dnsNames
		validated.ipAddresses = ipAddresses
		validated.emailAddresses = emailAddresses
		validated.uris = uris
	}

	hasCommonName := parameters.Subject != nil && parameters.Subject.CommonName != nil
	hasSAN := len(validated.dnsNames)+len(validated.ipAddresses)+len(validated.emailAddresses)+len(validated.uris) > 0
	if !hasCommonName && !hasSAN {
		return validatedX509CSR{}, ErrInvalidParameters
	}
	return validated, nil
}

func validateX509Subject(subject X509Subject) (pkix.Name, bool) {
	if subject.CommonName == nil && subject.SerialNumber == nil &&
		allStringSlicesNil(subject.Country, subject.Organization, subject.OrganizationalUnit,
			subject.Locality, subject.Province, subject.StreetAddress, subject.PostalCode) {
		return pkix.Name{}, false
	}
	if subject.CommonName != nil && !validIdentityString(*subject.CommonName, maximumX509SubjectBytes, false) {
		return pkix.Name{}, false
	}
	if subject.SerialNumber != nil && !validIdentityString(*subject.SerialNumber, maximumX509SubjectBytes, false) {
		return pkix.Name{}, false
	}
	if !validCountryValues(subject.Country) ||
		!validDNValues(subject.Organization) ||
		!validDNValues(subject.OrganizationalUnit) ||
		!validDNValues(subject.Locality) ||
		!validDNValues(subject.Province) ||
		!validDNValues(subject.StreetAddress) ||
		!validDNValues(subject.PostalCode) {
		return pkix.Name{}, false
	}

	return pkix.Name{
		CommonName:         stringValue(subject.CommonName),
		SerialNumber:       stringValue(subject.SerialNumber),
		Country:            cloneStrings(subject.Country),
		Organization:       cloneStrings(subject.Organization),
		OrganizationalUnit: cloneStrings(subject.OrganizationalUnit),
		Locality:           cloneStrings(subject.Locality),
		Province:           cloneStrings(subject.Province),
		StreetAddress:      cloneStrings(subject.StreetAddress),
		PostalCode:         cloneStrings(subject.PostalCode),
	}, true
}

func stringValue(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func validateX509SANs(sans X509SANs) ([]string, []net.IP, []string, []*url.URL, bool) {
	if allStringSlicesNil(sans.DNSNames, sans.IPAddresses, sans.EmailAddresses, sans.URIs) {
		return nil, nil, nil, nil, false
	}
	counts := []int{len(sans.DNSNames), len(sans.IPAddresses), len(sans.EmailAddresses), len(sans.URIs)}
	total := 0
	for _, count := range counts {
		if count > maximumX509SANs {
			return nil, nil, nil, nil, false
		}
		total += count
	}
	if total == 0 || total > maximumX509SANs {
		return nil, nil, nil, nil, false
	}
	if hasEmptySuppliedSlice(sans.DNSNames, sans.IPAddresses, sans.EmailAddresses, sans.URIs) {
		return nil, nil, nil, nil, false
	}

	dnsNames := make([]string, len(sans.DNSNames))
	if !validateDistinctStrings(sans.DNSNames, func(value string) bool {
		return validDNSName(value)
	}) {
		return nil, nil, nil, nil, false
	}
	copy(dnsNames, sans.DNSNames)

	ipAddresses := make([]net.IP, len(sans.IPAddresses))
	ipIndex := 0
	if !validateDistinctStrings(sans.IPAddresses, func(value string) bool {
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" || address.Is4In6() || address.String() != value {
			return false
		}
		ipAddresses[ipIndex] = net.IP(address.AsSlice())
		ipIndex++
		return true
	}) {
		return nil, nil, nil, nil, false
	}

	emailAddresses := make([]string, len(sans.EmailAddresses))
	if !validateDistinctStrings(sans.EmailAddresses, validEmailAddress) {
		return nil, nil, nil, nil, false
	}
	copy(emailAddresses, sans.EmailAddresses)

	uris := make([]*url.URL, len(sans.URIs))
	uriIndex := 0
	if !validateDistinctStrings(sans.URIs, func(value string) bool {
		parsed, ok := parseAbsoluteURI(value)
		if !ok {
			return false
		}
		uris[uriIndex] = parsed
		uriIndex++
		return true
	}) {
		return nil, nil, nil, nil, false
	}

	return dnsNames, ipAddresses, emailAddresses, uris, true
}

func validDNValues(values []string) bool {
	if values != nil && len(values) == 0 {
		return false
	}
	if len(values) > maximumX509SubjectValues {
		return false
	}
	return validateDistinctStrings(values, func(value string) bool {
		return validIdentityString(value, maximumX509SubjectBytes, false)
	})
}

func validCountryValues(values []string) bool {
	if values != nil && len(values) == 0 {
		return false
	}
	if len(values) > maximumX509SubjectValues {
		return false
	}
	return validateDistinctStrings(values, func(value string) bool {
		return len(value) == 2 && value[0] >= 'A' && value[0] <= 'Z' && value[1] >= 'A' && value[1] <= 'Z'
	})
}

func validDNSName(value string) bool {
	if !validIdentityString(value, maximumX509DNSBytes, true) {
		return false
	}
	labels := strings.Split(value, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || !isASCIILetterOrDigit(label[0]) || !isASCIILetterOrDigit(label[len(label)-1]) {
			return false
		}
		for index := 1; index < len(label)-1; index++ {
			if !isASCIILetterOrDigit(label[index]) && label[index] != '-' {
				return false
			}
		}
	}
	return true
}

func validEmailAddress(value string) bool {
	if !validIdentityString(value, maximumX509EmailBytes, true) {
		return false
	}
	address, err := mail.ParseAddress(value)
	return err == nil && address.Name == "" && address.Address == value
}

func parseAbsoluteURI(value string) (*url.URL, bool) {
	if !validIdentityString(value, maximumX509URIBytes, true) || !validAbsoluteURISyntax(value) {
		return nil, false
	}
	parsed, err := url.Parse(value)
	if err == nil && parsed.IsAbs() && parsed.String() == value {
		return parsed, true
	}
	if !hasIPvFutureAuthority(value) {
		return nil, false
	}
	colon := strings.IndexByte(value, ':')
	parsed = &url.URL{Scheme: value[:colon], Opaque: value[colon+1:]}
	if !parsed.IsAbs() || parsed.String() != value {
		return nil, false
	}
	return parsed, true
}

func hasIPvFutureAuthority(value string) bool {
	colon := strings.IndexByte(value, ':')
	if colon <= 0 {
		return false
	}
	remainder := value[colon+1:]
	if !strings.HasPrefix(remainder, "//") {
		return false
	}
	authority := remainder[2:]
	if delimiter := strings.IndexAny(authority, "/?#"); delimiter >= 0 {
		authority = authority[:delimiter]
	}
	if delimiter := strings.LastIndexByte(authority, '@'); delimiter >= 0 {
		authority = authority[delimiter+1:]
	}
	return len(authority) >= 3 && authority[0] == '[' && (authority[1] == 'v' || authority[1] == 'V')
}

func validAbsoluteURISyntax(value string) bool {
	colon := strings.IndexByte(value, ':')
	if colon <= 0 || !validURIScheme(value[:colon]) {
		return false
	}

	remainder := value[colon+1:]
	fragment := ""
	if delimiter := strings.IndexByte(remainder, '#'); delimiter >= 0 {
		fragment = remainder[delimiter+1:]
		remainder = remainder[:delimiter]
	}
	query := ""
	if delimiter := strings.IndexByte(remainder, '?'); delimiter >= 0 {
		query = remainder[delimiter+1:]
		remainder = remainder[:delimiter]
	}
	if !validURIHierPart(remainder) {
		return false
	}
	const queryOrFragmentReserved = "!$&'()*+,;=:@/?"
	return validURIComponent(query, queryOrFragmentReserved) && validURIComponent(fragment, queryOrFragmentReserved)
}

func validURIScheme(value string) bool {
	if value == "" || !isASCIIAlpha(value[0]) {
		return false
	}
	for index := 1; index < len(value); index++ {
		character := value[index]
		if !isASCIIAlpha(character) && (character < '0' || character > '9') && character != '+' && character != '-' && character != '.' {
			return false
		}
	}
	return true
}

func validURIHierPart(value string) bool {
	const pathReserved = "!$&'()*+,;=:@/"
	if strings.HasPrefix(value, "//") {
		authorityAndPath := value[2:]
		authority := authorityAndPath
		path := ""
		if delimiter := strings.IndexByte(authorityAndPath, '/'); delimiter >= 0 {
			authority = authorityAndPath[:delimiter]
			path = authorityAndPath[delimiter:]
		}
		return validURIAuthority(authority) && validURIComponent(path, pathReserved)
	}
	return validURIComponent(value, pathReserved)
}

func validURIAuthority(value string) bool {
	hostAndPort := value
	if delimiter := strings.LastIndexByte(value, '@'); delimiter >= 0 {
		const userinfoReserved = "!$&'()*+,;=:"
		if !validURIComponent(value[:delimiter], userinfoReserved) {
			return false
		}
		hostAndPort = value[delimiter+1:]
	}

	if strings.HasPrefix(hostAndPort, "[") {
		closingBracket := strings.LastIndexByte(hostAndPort, ']')
		if closingBracket < 0 || !validURIIPLiteral(hostAndPort[1:closingBracket]) {
			return false
		}
		return validURIPort(hostAndPort[closingBracket+1:])
	}
	if strings.ContainsAny(hostAndPort, "[]") {
		return false
	}

	host := hostAndPort
	port := ""
	if delimiter := strings.LastIndexByte(hostAndPort, ':'); delimiter >= 0 {
		host = hostAndPort[:delimiter]
		port = hostAndPort[delimiter:]
		if strings.ContainsRune(host, ':') {
			return false
		}
	}
	const regNameReserved = "!$&'()*+,;="
	return validURIComponent(host, regNameReserved) && validURIPort(port)
}

func validURIPort(value string) bool {
	if value == "" {
		return true
	}
	if value[0] != ':' {
		return false
	}
	for index := 1; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func validURIIPLiteral(value string) bool {
	if len(value) >= 3 && (value[0] == 'v' || value[0] == 'V') {
		delimiter := strings.IndexByte(value, '.')
		if delimiter < 2 || delimiter == len(value)-1 {
			return false
		}
		for index := 1; index < delimiter; index++ {
			if !isASCIIHex(value[index]) {
				return false
			}
		}
		const futureAddressReserved = "!$&'()*+,;=:"
		return validURIComponent(value[delimiter+1:], futureAddressReserved) && !strings.ContainsRune(value[delimiter+1:], '%')
	}
	address, err := netip.ParseAddr(value)
	return err == nil && address.Is6() && address.Zone() == ""
}

func validURIComponent(value, allowedReserved string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if isASCIIAlpha(character) || character >= '0' && character <= '9' || strings.IndexByte("-._~", character) >= 0 || strings.IndexByte(allowedReserved, character) >= 0 {
			continue
		}
		if character != '%' || index+2 >= len(value) || !isASCIIHex(value[index+1]) || !isASCIIHex(value[index+2]) {
			return false
		}
		index += 2
	}
	return true
}

func isASCIIAlpha(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func isASCIIHex(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f' || value >= 'A' && value <= 'F'
}

func validIdentityString(value string, maximumBytes int, asciiOnly bool) bool {
	if value == "" || len(value) > maximumBytes || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character <= 0x1f || character == 0x7f || (asciiOnly && character > unicode.MaxASCII) {
			return false
		}
	}
	return true
}

func validateDistinctStrings(values []string, validate func(string) bool) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !validate(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func allStringSlicesNil(values ...[]string) bool {
	for _, value := range values {
		if value != nil {
			return false
		}
	}
	return true
}

func hasEmptySuppliedSlice(values ...[]string) bool {
	for _, value := range values {
		if value != nil && len(value) == 0 {
			return true
		}
	}
	return false
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	return append([]string(nil), values...)
}

func isASCIILetterOrDigit(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}

func x509CSRMatches(csr *x509.CertificateRequest, expected validatedX509CSR) bool {
	if csr == nil || csr.Subject.CommonName != expected.subject.CommonName || csr.Subject.SerialNumber != expected.subject.SerialNumber {
		return false
	}
	if !sameStringSet(csr.Subject.Country, expected.subject.Country) ||
		!sameStringSet(csr.Subject.Organization, expected.subject.Organization) ||
		!sameStringSet(csr.Subject.OrganizationalUnit, expected.subject.OrganizationalUnit) ||
		!sameStringSet(csr.Subject.Locality, expected.subject.Locality) ||
		!sameStringSet(csr.Subject.Province, expected.subject.Province) ||
		!sameStringSet(csr.Subject.StreetAddress, expected.subject.StreetAddress) ||
		!sameStringSet(csr.Subject.PostalCode, expected.subject.PostalCode) ||
		!equalStrings(csr.DNSNames, expected.dnsNames) ||
		!equalStrings(csr.EmailAddresses, expected.emailAddresses) ||
		len(csr.IPAddresses) != len(expected.ipAddresses) ||
		len(csr.URIs) != len(expected.uris) {
		return false
	}
	for index := range csr.IPAddresses {
		if !csr.IPAddresses[index].Equal(expected.ipAddresses[index]) {
			return false
		}
	}
	for index := range csr.URIs {
		if csr.URIs[index] == nil || expected.uris[index] == nil || csr.URIs[index].String() != expected.uris[index].String() {
			return false
		}
	}
	hasSAN := len(expected.dnsNames)+len(expected.ipAddresses)+len(expected.emailAddresses)+len(expected.uris) > 0
	if !hasSAN {
		return len(csr.Extensions) == 0
	}
	if len(csr.Extensions) != 1 || csr.Extensions[0].Critical || csr.Extensions[0].Id.String() != "2.5.29.17" {
		return false
	}
	return true
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	want := make(map[string]int, len(right))
	for _, value := range right {
		want[value]++
	}
	for _, value := range left {
		if want[value] == 0 {
			return false
		}
		want[value]--
	}
	return true
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
