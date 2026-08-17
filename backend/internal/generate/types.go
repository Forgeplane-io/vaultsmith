package generate

import (
	"encoding/json"
)

const (
	PasswordFormat    = "password_ascii"
	TokenBase64Format = "token_base64url"
	TokenHexFormat    = "token_hex"
	SSHPrivateFormat  = "openssh_private_key"
	SSHPublicFormat   = "openssh_authorized_key"
	AgePrivateFormat  = "age_x25519_identity"
	AgePublicFormat   = "age_x25519_recipient"
	X509PrivateFormat = "pkcs8_private_key_pem"
	X509PublicFormat  = "pkcs10_csr_pem"
)

type TokenEncoding string

const (
	TokenEncodingBase64URL TokenEncoding = "base64url"
	TokenEncodingHex       TokenEncoding = "hex"
)

type SSHAlgorithm string

const (
	SSHAlgorithmEd25519   SSHAlgorithm = "ed25519"
	SSHAlgorithmECDSAP256 SSHAlgorithm = "ecdsa_p256"
	SSHAlgorithmRSA3072   SSHAlgorithm = "rsa_3072"
	SSHAlgorithmRSA4096   SSHAlgorithm = "rsa_4096"
)

type X509Algorithm string

const (
	X509AlgorithmEd25519   X509Algorithm = "ed25519"
	X509AlgorithmECDSAP256 X509Algorithm = "ecdsa_p256"
	X509AlgorithmECDSAP384 X509Algorithm = "ecdsa_p384"
	X509AlgorithmRSA3072   X509Algorithm = "rsa_3072"
	X509AlgorithmRSA4096   X509Algorithm = "rsa_4096"
)

// PasswordParameters uses nil for omission so defaults remain independent of
// every transport's decoder. No field accepts caller-provided character data.
type PasswordParameters struct {
	Length           *int
	Lowercase        *bool
	Uppercase        *bool
	Digits           *bool
	Symbols          *bool
	MinLowercase     *int
	MinUppercase     *int
	MinDigits        *int
	MinSymbols       *int
	ExcludeAmbiguous *bool
}

type EffectivePasswordParameters struct {
	Length           int
	Lowercase        bool
	Uppercase        bool
	Digits           bool
	Symbols          bool
	MinLowercase     int
	MinUppercase     int
	MinDigits        int
	MinSymbols       int
	ExcludeAmbiguous bool
}

type TokenParameters struct {
	Encoding *TokenEncoding
	Bytes    *int
}

type EffectiveTokenParameters struct {
	Encoding TokenEncoding
	Bytes    int
}

type SSHKeyPairParameters struct {
	Algorithm SSHAlgorithm
}

type X509Subject struct {
	CommonName         string
	SerialNumber       string
	Country            []string
	Organization       []string
	OrganizationalUnit []string
	Locality           []string
	Province           []string
	StreetAddress      []string
	PostalCode         []string
}

type X509SANs struct {
	DNSNames       []string
	IPAddresses    []string
	EmailAddresses []string
	URIs           []string
}

type X509CSRParameters struct {
	Algorithm X509Algorithm
	Subject   *X509Subject
	SANs      *X509SANs
}

type privateMaterial struct {
	bytes []byte
}

func newPrivateMaterial(value []byte) privateMaterial {
	return privateMaterial{bytes: append([]byte(nil), value...)}
}

func (m privateMaterial) clone() []byte {
	return append([]byte(nil), m.bytes...)
}

type PasswordResult struct {
	private    privateMaterial
	parameters EffectivePasswordParameters
}

func (r PasswordResult) PrivateBytes() []byte { return r.private.clone() }
func (r PasswordResult) EffectiveParameters() EffectivePasswordParameters {
	return r.parameters
}
func (PasswordResult) String() string   { return "generate.PasswordResult{private:[redacted]}" }
func (PasswordResult) GoString() string { return "generate.PasswordResult{private:[redacted]}" }
func (PasswordResult) MarshalJSON() ([]byte, error) {
	return nil, ErrResultSerialization
}

type TokenResult struct {
	private    privateMaterial
	parameters EffectiveTokenParameters
	format     string
}

func (r TokenResult) PrivateBytes() []byte { return r.private.clone() }
func (r TokenResult) EffectiveParameters() EffectiveTokenParameters {
	return r.parameters
}
func (r TokenResult) Format() string { return r.format }
func (TokenResult) String() string   { return "generate.TokenResult{private:[redacted]}" }
func (TokenResult) GoString() string { return "generate.TokenResult{private:[redacted]}" }
func (TokenResult) MarshalJSON() ([]byte, error) {
	return nil, ErrResultSerialization
}

type SSHKeyPairResult struct {
	private       privateMaterial
	algorithm     SSHAlgorithm
	authorizedKey string
	fingerprint   string
}

func (r SSHKeyPairResult) PrivateBytes() []byte    { return r.private.clone() }
func (r SSHKeyPairResult) Algorithm() SSHAlgorithm { return r.algorithm }
func (r SSHKeyPairResult) AuthorizedKey() string   { return r.authorizedKey }
func (r SSHKeyPairResult) Fingerprint() string     { return r.fingerprint }
func (SSHKeyPairResult) String() string {
	return "generate.SSHKeyPairResult{private:[redacted],public:[redacted]}"
}
func (SSHKeyPairResult) GoString() string {
	return "generate.SSHKeyPairResult{private:[redacted],public:[redacted]}"
}
func (SSHKeyPairResult) MarshalJSON() ([]byte, error) {
	return nil, ErrResultSerialization
}

type AgeIdentityResult struct {
	private   privateMaterial
	recipient string
}

func (r AgeIdentityResult) PrivateBytes() []byte { return r.private.clone() }
func (r AgeIdentityResult) Recipient() string    { return r.recipient }
func (AgeIdentityResult) String() string {
	return "generate.AgeIdentityResult{private:[redacted],public:[redacted]}"
}
func (AgeIdentityResult) GoString() string {
	return "generate.AgeIdentityResult{private:[redacted],public:[redacted]}"
}
func (AgeIdentityResult) MarshalJSON() ([]byte, error) {
	return nil, ErrResultSerialization
}

type X509CSRResult struct {
	private     privateMaterial
	algorithm   X509Algorithm
	csrPEM      string
	fingerprint string
}

func (r X509CSRResult) PrivateBytes() []byte     { return r.private.clone() }
func (r X509CSRResult) Algorithm() X509Algorithm { return r.algorithm }
func (r X509CSRResult) CSRPEM() string           { return r.csrPEM }
func (r X509CSRResult) Fingerprint() string      { return r.fingerprint }
func (X509CSRResult) String() string {
	return "generate.X509CSRResult{private:[redacted],public:[redacted]}"
}
func (X509CSRResult) GoString() string {
	return "generate.X509CSRResult{private:[redacted],public:[redacted]}"
}
func (X509CSRResult) MarshalJSON() ([]byte, error) {
	return nil, ErrResultSerialization
}

var (
	_ json.Marshaler = PasswordResult{}
	_ json.Marshaler = TokenResult{}
	_ json.Marshaler = SSHKeyPairResult{}
	_ json.Marshaler = AgeIdentityResult{}
	_ json.Marshaler = X509CSRResult{}
)
