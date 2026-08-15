package attestation

import (
	"bytes"
	"encoding/json"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/gowebpki/jcs"
)

const (
	// SupportedVersion is the only protocol version emitted by this package.
	SupportedVersion int64 = 1

	// MaxJCSSafeInteger is the largest integer that can be represented exactly
	// by the JSON/ECMAScript number model used by RFC 8785.
	MaxJCSSafeInteger int64 = 9007199254740991

	attestationAlgorithm = "Ed25519"
	attestationType      = "application/vaultsmith-rotation-attestation+json"
)

// Digest is a domain-separated SHA-256 digest reference in a claim.
type Digest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"digest"`
}

// Binding identifies the source context to which a rotation proof is bound.
// At least one field must be present when Binding is non-nil.
type Binding struct {
	Repository string `json:"repository,omitempty"`
	Revision   string `json:"revision,omitempty"`
	Path       string `json:"path,omitempty"`
	Selector   string `json:"selector,omitempty"`
}

// RotationClaims is the signed v1 rotation-attestation payload.
type RotationClaims struct {
	Version              int64    `json:"version"`
	Issuer               string   `json:"issuer"`
	IssuedAt             string   `json:"issuedAt"`
	Operation            string   `json:"operation"`
	SourceProfileID      string   `json:"sourceProfileId"`
	DestinationProfileID string   `json:"destinationProfileId"`
	Input                Digest   `json:"input"`
	Output               Digest   `json:"output"`
	Binding              *Binding `json:"binding,omitempty"`
}

var (
	claimsMembers = map[string]struct{}{
		"version": {}, "issuer": {}, "issuedAt": {}, "operation": {},
		"sourceProfileId": {}, "destinationProfileId": {}, "input": {},
		"output": {}, "binding": {},
	}
	digestMembers = map[string]struct{}{
		"algorithm": {}, "digest": {},
	}
	bindingMembers = map[string]struct{}{
		"repository": {}, "revision": {}, "path": {}, "selector": {},
	}
)

func validateClaims(claims RotationClaims) error {
	if claims.Version < 0 || claims.Version > MaxJCSSafeInteger {
		return errMalformed
	}
	if !validIssuer(claims.Issuer) || !validTimestamp(claims.IssuedAt) {
		return errMalformed
	}
	if claims.Operation != "rotate" {
		return errMalformed
	}
	if !config.IsValidProfileID(claims.SourceProfileID) ||
		!config.IsValidProfileID(claims.DestinationProfileID) {
		return errMalformed
	}
	if err := validateDigest(claims.Input); err != nil {
		return err
	}
	if err := validateDigest(claims.Output); err != nil {
		return err
	}
	if claims.Binding != nil {
		if err := validateBinding(*claims.Binding); err != nil {
			return err
		}
	}
	return nil
}

func validateSigningClaims(claims RotationClaims) error {
	if err := validateClaims(claims); err != nil {
		return err
	}
	if claims.Version != SupportedVersion {
		return errMalformed
	}
	return nil
}

func validateDigest(digest Digest) error {
	if digest.Algorithm != "sha-256" || !validLowerHexDigest(digest.Value) {
		return errMalformed
	}
	return nil
}

func validateBinding(binding Binding) error {
	fields := []string{binding.Repository, binding.Revision, binding.Path, binding.Selector}
	hasValue := false
	for _, field := range fields {
		if field != "" {
			hasValue = true
		}
		if field != "" && !validBoundString(field) {
			return errMalformed
		}
	}
	if !hasValue {
		return errMalformed
	}
	canonical, err := canonicalBinding(binding)
	if err != nil || len(canonical) > 4<<10 {
		return errMalformed
	}
	return nil
}

func validBoundString(value string) bool {
	if value == "" || len(value) > 1<<10 || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func validLowerHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, current := range value {
		if !((current >= '0' && current <= '9') || (current >= 'a' && current <= 'f')) {
			return false
		}
	}
	return true
}

func validTimestamp(value string) bool {
	if value == "" || !utf8.ValidString(value) || !strings.HasSuffix(value, "Z") {
		return false
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && parsed.Format(time.RFC3339Nano) == value
}

func validIssuer(value string) bool {
	if value == "" || !utf8.ValidString(value) || strings.ContainsAny(value, "?#") {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil ||
		parsed.Opaque != "" || (parsed.Path != "" && parsed.Path != "/") ||
		parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return false
	}
	return parsed.Hostname() != ""
}

func validKID(value string) bool {
	if len(value) == 0 || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for _, current := range value {
		if !(current >= 'A' && current <= 'Z') &&
			!(current >= 'a' && current <= 'z') &&
			!(current >= '0' && current <= '9') && current != '.' && current != '_' && current != '-' {
			return false
		}
	}
	return true
}

func parseClaims(data []byte) (RotationClaims, error) {
	root, err := parseStrictJSON(data)
	if err != nil || root.kind != jsonObject || !root.hasOnlyMembers(claimsMembers) {
		return RotationClaims{}, errMalformed
	}
	var claims RotationClaims
	version, ok := root.member("version")
	if !ok || version.kind != jsonNumber || !validVersionNumber(version.number) {
		return RotationClaims{}, errMalformed
	}
	parsedVersion, err := strconv.ParseInt(version.number, 10, 64)
	if err != nil {
		return RotationClaims{}, errMalformed
	}
	claims.Version = parsedVersion
	if claims.Issuer, err = requiredStringMember(root, "issuer"); err != nil {
		return RotationClaims{}, errMalformed
	}
	if claims.IssuedAt, err = requiredStringMember(root, "issuedAt"); err != nil {
		return RotationClaims{}, errMalformed
	}
	if claims.Operation, err = requiredStringMember(root, "operation"); err != nil {
		return RotationClaims{}, errMalformed
	}
	if claims.SourceProfileID, err = requiredStringMember(root, "sourceProfileId"); err != nil {
		return RotationClaims{}, errMalformed
	}
	if claims.DestinationProfileID, err = requiredStringMember(root, "destinationProfileId"); err != nil {
		return RotationClaims{}, errMalformed
	}
	input, ok := root.member("input")
	if !ok {
		return RotationClaims{}, errMalformed
	}
	if claims.Input, err = parseDigest(input); err != nil {
		return RotationClaims{}, errMalformed
	}
	output, ok := root.member("output")
	if !ok {
		return RotationClaims{}, errMalformed
	}
	if claims.Output, err = parseDigest(output); err != nil {
		return RotationClaims{}, errMalformed
	}
	if binding, ok := root.member("binding"); ok {
		parsedBinding, err := parseBinding(binding)
		if err != nil {
			return RotationClaims{}, errMalformed
		}
		claims.Binding = &parsedBinding
	}
	if err := validateClaims(claims); err != nil {
		return RotationClaims{}, errMalformed
	}
	return claims, nil
}

func validVersionNumber(number string) bool {
	if number == "" || number[0] == '-' || strings.ContainsAny(number, ".eE") {
		return false
	}
	return number == "0" || (number[0] >= '1' && number[0] <= '9' && strings.Trim(number, "0123456789") == "")
}

func requiredStringMember(object jsonValue, name string) (string, error) {
	member, ok := object.member(name)
	if !ok || member.kind != jsonString {
		return "", errMalformed
	}
	return member.string, nil
}

func parseDigest(value jsonValue) (Digest, error) {
	if value.kind != jsonObject || !value.hasOnlyMembers(digestMembers) {
		return Digest{}, errMalformed
	}
	algorithm, err := requiredStringMember(value, "algorithm")
	if err != nil {
		return Digest{}, err
	}
	digest, err := requiredStringMember(value, "digest")
	if err != nil {
		return Digest{}, err
	}
	result := Digest{Algorithm: algorithm, Value: digest}
	if err := validateDigest(result); err != nil {
		return Digest{}, err
	}
	return result, nil
}

func parseBinding(value jsonValue) (Binding, error) {
	if value.kind != jsonObject || !value.hasOnlyMembers(bindingMembers) {
		return Binding{}, errMalformed
	}
	var binding Binding
	var err error
	if member, ok := value.member("repository"); ok {
		if member.kind != jsonString {
			return Binding{}, errMalformed
		}
		binding.Repository = member.string
	}
	if member, ok := value.member("revision"); ok {
		if member.kind != jsonString {
			return Binding{}, errMalformed
		}
		binding.Revision = member.string
	}
	if member, ok := value.member("path"); ok {
		if member.kind != jsonString {
			return Binding{}, errMalformed
		}
		binding.Path = member.string
	}
	if member, ok := value.member("selector"); ok {
		if member.kind != jsonString {
			return Binding{}, errMalformed
		}
		binding.Selector = member.string
	}
	if err = validateBinding(binding); err != nil {
		return Binding{}, err
	}
	return binding, nil
}

func canonicalClaims(claims RotationClaims) ([]byte, error) {
	if err := validateClaims(claims); err != nil {
		return nil, errMalformed
	}
	raw, err := json.Marshal(claims)
	if err != nil {
		return nil, errMalformed
	}
	canonical, err := jcs.Transform(raw)
	if err != nil {
		return nil, errMalformed
	}
	return canonical, nil
}

func parseCanonicalClaims(data []byte) (RotationClaims, error) {
	claims, err := parseClaims(data)
	if err != nil {
		return RotationClaims{}, errMalformed
	}
	canonical, err := jcs.Transform(data)
	if err != nil || !bytes.Equal(canonical, data) {
		return RotationClaims{}, errMalformed
	}
	return claims, nil
}

func canonicalBinding(binding Binding) ([]byte, error) {
	if err := validateBindingFieldsOnly(binding); err != nil {
		return nil, errMalformed
	}
	raw, err := json.Marshal(binding)
	if err != nil {
		return nil, errMalformed
	}
	return jcs.Transform(raw)
}

func validateBindingFieldsOnly(binding Binding) error {
	fields := []string{binding.Repository, binding.Revision, binding.Path, binding.Selector}
	for _, field := range fields {
		if field != "" && !validBoundString(field) {
			return errMalformed
		}
	}
	if binding.Repository == "" && binding.Revision == "" && binding.Path == "" && binding.Selector == "" {
		return errMalformed
	}
	return nil
}
