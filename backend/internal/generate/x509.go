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
	if err != nil || csr.SignatureAlgorithm != expected.signatureAlgorithm {
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
	if err != nil || !parsed.IsAbs() || parsed.String() != value {
		return nil, false
	}
	return parsed, true
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
