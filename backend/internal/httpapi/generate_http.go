package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"unicode/utf8"

	"github.com/forgeplane-io/vaultsmith/backend/internal/apimodels"
	"github.com/forgeplane-io/vaultsmith/backend/internal/caller"
	"github.com/forgeplane-io/vaultsmith/backend/internal/generate"
	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
)

func (h *Handler) serveGenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		writeError(w, http.StatusUnsupportedMediaType, "invalid_request", "content type must be application/json")
		return
	}
	if !supportsIdentityContentEncoding(r.Header) {
		writeError(w, http.StatusUnsupportedMediaType, "invalid_request", "media type is not supported")
		return
	}
	if hasIdempotencyKey(r.Header) {
		writeError(w, http.StatusBadRequest, "invalid_request", "request is invalid")
		return
	}
	if h.service == nil {
		writeError(w, http.StatusServiceUnavailable, "not_ready", "service is not ready")
		return
	}

	actor, ok, status, code := h.requestCaller(r)
	if !ok {
		writeAuthError(w, status, code)
		return
	}
	if err := h.service.PreflightGenerate(r.Context(), actor); err != nil {
		if actor.Kind() == caller.KindBearer && vaultservice.HasCode(err, vaultservice.CodeForbidden) {
			writeBearerChallenge(w, http.StatusForbidden, "insufficient_scope", vaultservice.ScopeEncrypt, protectedResourceMetadataURL(h.authConfig))
		} else {
			writeServiceError(w, err)
		}
		return
	}

	lease, err := h.service.Admission().TryAcquire(r.Context())
	if err != nil {
		switch {
		case errors.Is(err, vaultservice.ErrAdmissionSaturated):
			writeGenerateAdmissionSaturated(w, h.service.Admission())
		case isContextError(err):
			writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "service is temporarily unavailable")
		default:
			writeServiceError(w, err)
		}
		return
	}
	defer lease.Release()
	leaseContext := lease.Context(r.Context())

	command, err := decodeGenerateCommand(w, r)
	if err != nil {
		switch {
		case errors.Is(err, errBodyTooLarge):
			writeError(w, http.StatusRequestEntityTooLarge, "invalid_request", "request is too large")
		case isContextError(err):
			writeError(w, http.StatusServiceUnavailable, "temporarily_unavailable", "service is temporarily unavailable")
		default:
			writeError(w, http.StatusBadRequest, "invalid_request", "request is invalid")
		}
		return
	}

	result, err := h.service.Generate(leaseContext, actor, command)
	if err != nil {
		writeServiceError(w, err)
		return
	}
	response, err := mapGenerateResponse(result)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "operation_failed", "vault operation failed")
		return
	}
	raw, err := json.Marshal(response)
	if err != nil || !json.Valid(raw) {
		writeError(w, http.StatusUnprocessableEntity, "operation_failed", "vault operation failed")
		return
	}
	w.Header().Del("Content-Encoding")
	w.Header().Del("ETag")
	writeRawJSON(w, http.StatusOK, raw)
}

func hasIdempotencyKey(header http.Header) bool {
	return len(header.Values("Idempotency-Key")) != 0
}

func decodeGenerateCommand(w http.ResponseWriter, r *http.Request) (vaultservice.GenerateCommand, error) {
	r.Body = http.MaxBytesReader(w, r.Body, MaxGenerateRequestBodyBytes)
	defer r.Body.Close()
	raw, err := readRequestBody(r.Context(), r.Body)
	if err != nil {
		var maxBytesError *http.MaxBytesError
		if errors.As(err, &maxBytesError) {
			return vaultservice.GenerateCommand{}, errBodyTooLarge
		}
		return vaultservice.GenerateCommand{}, err
	}
	if contextErr := r.Context().Err(); contextErr != nil {
		return vaultservice.GenerateCommand{}, contextErr
	}
	if len(raw) == 0 || !utf8.Valid(raw) {
		return vaultservice.GenerateCommand{}, errors.New("request is not valid UTF-8")
	}
	return parseGenerateCommand(raw)
}

func parseGenerateCommand(raw []byte) (vaultservice.GenerateCommand, error) {
	fields, err := decodeStrictObject(raw, map[string]struct{}{
		"kind": {}, "profileId": {}, "parameters": {},
	})
	if err != nil {
		return vaultservice.GenerateCommand{}, err
	}
	for _, required := range []string{"kind", "profileId", "parameters"} {
		if _, ok := fields[required]; !ok {
			return vaultservice.GenerateCommand{}, errors.New("required request field is missing")
		}
	}
	kind, err := decodeGenerateString(fields["kind"])
	if err != nil {
		return vaultservice.GenerateCommand{}, err
	}
	profileID, err := decodeGenerateString(fields["profileId"])
	if err != nil {
		return vaultservice.GenerateCommand{}, err
	}
	if isJSONNull(fields["parameters"]) {
		return vaultservice.GenerateCommand{}, errors.New("parameters must be an object")
	}

	command := vaultservice.GenerateCommand{ProfileID: profileID, Kind: vaultservice.GenerateKind(kind)}
	switch command.Kind {
	case vaultservice.GenerateKindPassword:
		parameters, err := parsePasswordParameters(fields["parameters"])
		if err != nil {
			return vaultservice.GenerateCommand{}, err
		}
		command.Password = &parameters
	case vaultservice.GenerateKindToken:
		parameters, err := parseTokenParameters(fields["parameters"])
		if err != nil {
			return vaultservice.GenerateCommand{}, err
		}
		command.Token = &parameters
	case vaultservice.GenerateKindSSHKeyPair:
		parameters, err := parseSSHKeyPairParameters(fields["parameters"])
		if err != nil {
			return vaultservice.GenerateCommand{}, err
		}
		command.SSHKeyPair = &parameters
	case vaultservice.GenerateKindAgeIdentity:
		if _, err := decodeStrictObject(fields["parameters"], map[string]struct{}{}); err != nil {
			return vaultservice.GenerateCommand{}, err
		}
		command.AgeIdentity = &vaultservice.AgeIdentityParameters{}
	case vaultservice.GenerateKindX509CSR:
		parameters, err := parseX509CSRParameters(fields["parameters"])
		if err != nil {
			return vaultservice.GenerateCommand{}, err
		}
		command.X509CSR = &parameters
	default:
		return vaultservice.GenerateCommand{}, errors.New("generation kind is invalid")
	}
	return command, nil
}

func parsePasswordParameters(raw json.RawMessage) (generate.PasswordParameters, error) {
	fields, err := decodeStrictObject(raw, map[string]struct{}{
		"length": {}, "lowercase": {}, "uppercase": {}, "digits": {}, "symbols": {},
		"minLowercase": {}, "minUppercase": {}, "minDigits": {}, "minSymbols": {},
		"excludeAmbiguous": {},
	})
	if err != nil {
		return generate.PasswordParameters{}, err
	}
	parameters := generate.PasswordParameters{}
	for name, target := range map[string]**int{
		"length": &parameters.Length, "minLowercase": &parameters.MinLowercase,
		"minUppercase": &parameters.MinUppercase, "minDigits": &parameters.MinDigits,
		"minSymbols": &parameters.MinSymbols,
	} {
		if value, ok := fields[name]; ok {
			decoded, err := decodeJSONInt(value)
			if err != nil {
				return generate.PasswordParameters{}, err
			}
			*target = &decoded
		}
	}
	for name, target := range map[string]**bool{
		"lowercase": &parameters.Lowercase, "uppercase": &parameters.Uppercase,
		"digits": &parameters.Digits, "symbols": &parameters.Symbols,
		"excludeAmbiguous": &parameters.ExcludeAmbiguous,
	} {
		if value, ok := fields[name]; ok {
			decoded, err := decodeJSONBool(value)
			if err != nil {
				return generate.PasswordParameters{}, err
			}
			*target = &decoded
		}
	}
	return parameters, nil
}

func parseTokenParameters(raw json.RawMessage) (generate.TokenParameters, error) {
	fields, err := decodeStrictObject(raw, map[string]struct{}{"encoding": {}, "bytes": {}})
	if err != nil {
		return generate.TokenParameters{}, err
	}
	parameters := generate.TokenParameters{}
	if rawEncoding, ok := fields["encoding"]; ok {
		encoding, err := decodeGenerateString(rawEncoding)
		if err != nil {
			return generate.TokenParameters{}, err
		}
		value := generate.TokenEncoding(encoding)
		parameters.Encoding = &value
	}
	if rawBytes, ok := fields["bytes"]; ok {
		value, err := decodeJSONInt(rawBytes)
		if err != nil {
			return generate.TokenParameters{}, err
		}
		parameters.Bytes = &value
	}
	return parameters, nil
}

func parseSSHKeyPairParameters(raw json.RawMessage) (generate.SSHKeyPairParameters, error) {
	fields, err := decodeStrictObject(raw, map[string]struct{}{"algorithm": {}})
	if err != nil {
		return generate.SSHKeyPairParameters{}, err
	}
	rawAlgorithm, ok := fields["algorithm"]
	if !ok {
		return generate.SSHKeyPairParameters{}, errors.New("algorithm is required")
	}
	algorithm, err := decodeGenerateString(rawAlgorithm)
	if err != nil {
		return generate.SSHKeyPairParameters{}, err
	}
	return generate.SSHKeyPairParameters{Algorithm: generate.SSHAlgorithm(algorithm)}, nil
}

func parseX509CSRParameters(raw json.RawMessage) (generate.X509CSRParameters, error) {
	fields, err := decodeStrictObject(raw, map[string]struct{}{"algorithm": {}, "subject": {}, "sans": {}})
	if err != nil {
		return generate.X509CSRParameters{}, err
	}
	rawAlgorithm, ok := fields["algorithm"]
	if !ok {
		return generate.X509CSRParameters{}, errors.New("algorithm is required")
	}
	algorithm, err := decodeGenerateString(rawAlgorithm)
	if err != nil {
		return generate.X509CSRParameters{}, err
	}
	parameters := generate.X509CSRParameters{Algorithm: generate.X509Algorithm(algorithm)}
	if rawSubject, ok := fields["subject"]; ok {
		subject, err := parseX509Subject(rawSubject)
		if err != nil {
			return generate.X509CSRParameters{}, err
		}
		parameters.Subject = &subject
	}
	if rawSANs, ok := fields["sans"]; ok {
		sans, err := parseX509SANs(rawSANs)
		if err != nil {
			return generate.X509CSRParameters{}, err
		}
		parameters.SANs = &sans
	}
	return parameters, nil
}

func parseX509Subject(raw json.RawMessage) (generate.X509Subject, error) {
	if isJSONNull(raw) {
		return generate.X509Subject{}, errors.New("subject must be an object")
	}
	fields, err := decodeStrictObject(raw, map[string]struct{}{
		"commonName": {}, "serialNumber": {}, "country": {}, "organization": {},
		"organizationalUnit": {}, "locality": {}, "province": {}, "streetAddress": {},
		"postalCode": {},
	})
	if err != nil {
		return generate.X509Subject{}, err
	}
	if len(fields) == 0 {
		return generate.X509Subject{}, errors.New("subject must not be empty")
	}
	subject := generate.X509Subject{}
	for name, target := range map[string]**string{
		"commonName": &subject.CommonName, "serialNumber": &subject.SerialNumber,
	} {
		if value, ok := fields[name]; ok {
			decoded, err := decodeGenerateString(value)
			if err != nil {
				return generate.X509Subject{}, err
			}
			*target = &decoded
		}
	}
	for name, target := range map[string]*[]string{
		"country": &subject.Country, "organization": &subject.Organization,
		"organizationalUnit": &subject.OrganizationalUnit, "locality": &subject.Locality,
		"province": &subject.Province, "streetAddress": &subject.StreetAddress,
		"postalCode": &subject.PostalCode,
	} {
		if value, ok := fields[name]; ok {
			decoded, err := decodeJSONStringArray(value)
			if err != nil {
				return generate.X509Subject{}, err
			}
			*target = decoded
		}
	}
	return subject, nil
}

func parseX509SANs(raw json.RawMessage) (generate.X509SANs, error) {
	if isJSONNull(raw) {
		return generate.X509SANs{}, errors.New("sans must be an object")
	}
	fields, err := decodeStrictObject(raw, map[string]struct{}{
		"dnsNames": {}, "ipAddresses": {}, "emailAddresses": {}, "uris": {},
	})
	if err != nil {
		return generate.X509SANs{}, err
	}
	if len(fields) == 0 {
		return generate.X509SANs{}, errors.New("sans must not be empty")
	}
	sans := generate.X509SANs{}
	for name, target := range map[string]*[]string{
		"dnsNames": &sans.DNSNames, "ipAddresses": &sans.IPAddresses,
		"emailAddresses": &sans.EmailAddresses, "uris": &sans.URIs,
	} {
		if value, ok := fields[name]; ok {
			decoded, err := decodeJSONStringArray(value)
			if err != nil {
				return generate.X509SANs{}, err
			}
			*target = decoded
		}
	}
	return sans, nil
}

func decodeJSONInt(raw json.RawMessage) (int, error) {
	if isJSONNull(raw) {
		return 0, errors.New("request field must be an integer")
	}
	var value int
	if err := json.Unmarshal(raw, &value); err != nil {
		return 0, errors.New("request field must be an integer")
	}
	return value, nil
}

func decodeJSONBool(raw json.RawMessage) (bool, error) {
	if isJSONNull(raw) {
		return false, errors.New("request field must be a boolean")
	}
	var value bool
	if err := json.Unmarshal(raw, &value); err != nil {
		return false, errors.New("request field must be a boolean")
	}
	return value, nil
}

func decodeJSONStringArray(raw json.RawMessage) ([]string, error) {
	if isJSONNull(raw) {
		return nil, errors.New("request field must be an array")
	}
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil || items == nil {
		return nil, errors.New("request field must be an array")
	}
	values := make([]string, len(items))
	for index, item := range items {
		value, err := decodeGenerateString(item)
		if err != nil {
			return nil, errors.New("request array item must be a string")
		}
		values[index] = value
	}
	return values, nil
}

func isJSONNull(raw json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(raw), []byte("null"))
}

// encoding/json accepts lone UTF-16 surrogate escapes and replaces them with
// U+FFFD. Generate identity values must never be silently rewritten, so reject
// an unpaired escape before decoding while still accepting valid pairs and a
// caller's literal backslash-u text.
func decodeGenerateString(raw json.RawMessage) (string, error) {
	if !hasValidJSONSurrogatePairs(bytes.TrimSpace(raw)) {
		return "", errors.New("request string contains an unpaired surrogate")
	}
	return decodeOperationString(raw)
}

func hasValidJSONSurrogatePairs(raw []byte) bool {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		// The ordinary string decoder owns non-string and malformed JSON errors.
		return true
	}
	for index := 1; index < len(raw)-1; {
		if raw[index] != '\\' {
			index++
			continue
		}
		index++
		if index >= len(raw)-1 {
			return true
		}
		if raw[index] != 'u' {
			// Skip the escaped byte. This also ensures that \\u text is not
			// mistaken for a Unicode escape.
			index++
			continue
		}
		if index+4 >= len(raw)-1 {
			return true
		}
		codePoint, ok := decodeJSONHexQuad(raw[index+1 : index+5])
		if !ok {
			return true
		}
		index += 5
		switch {
		case codePoint >= 0xd800 && codePoint <= 0xdbff:
			if index+5 >= len(raw)-1 || raw[index] != '\\' || raw[index+1] != 'u' {
				return false
			}
			low, ok := decodeJSONHexQuad(raw[index+2 : index+6])
			if !ok || low < 0xdc00 || low > 0xdfff {
				return false
			}
			index += 6
		case codePoint >= 0xdc00 && codePoint <= 0xdfff:
			return false
		}
	}
	return true
}

func decodeJSONHexQuad(raw []byte) (uint16, bool) {
	if len(raw) != 4 {
		return 0, false
	}
	var value uint16
	for _, character := range raw {
		value <<= 4
		switch {
		case character >= '0' && character <= '9':
			value |= uint16(character - '0')
		case character >= 'a' && character <= 'f':
			value |= uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			value |= uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func mapGenerateResponse(result vaultservice.GenerateResult) (apimodels.GenerateResponse, error) {
	var response apimodels.GenerateResponse
	if result == nil {
		return response, errors.New("generation result is missing")
	}

	switch generated := result.(type) {
	case vaultservice.GeneratedPasswordResult:
		format := apimodels.GeneratePasswordSecretFormat(generated.Secret.Format)
		if !format.Valid() || generated.ProfileID == "" || generated.Secret.VaultText == "" {
			return response, errors.New("password result is invalid")
		}
		effective := generated.EffectiveParameters
		err := response.FromGeneratePasswordResponse(apimodels.GeneratePasswordResponse{
			Kind:      apimodels.GeneratePasswordResponseKindPassword,
			ProfileId: generated.ProfileID,
			EffectiveParameters: apimodels.GeneratePasswordEffectiveParameters{
				Length: effective.Length, Lowercase: effective.Lowercase, Uppercase: effective.Uppercase,
				Digits: effective.Digits, Symbols: effective.Symbols,
				MinLowercase: effective.MinLowercase, MinUppercase: effective.MinUppercase,
				MinDigits: effective.MinDigits, MinSymbols: effective.MinSymbols,
				ExcludeAmbiguous: effective.ExcludeAmbiguous,
			},
			Secret: apimodels.GeneratePasswordSecret{Format: format, VaultText: generated.Secret.VaultText},
		})
		return response, err

	case vaultservice.GeneratedTokenResult:
		encoding := apimodels.GenerateTokenEffectiveParametersEncoding(generated.EffectiveParameters.Encoding)
		format := apimodels.GenerateTokenSecretFormat(generated.Secret.Format)
		if !encoding.Valid() || !format.Valid() || generated.ProfileID == "" || generated.Secret.VaultText == "" {
			return response, errors.New("token result is invalid")
		}
		if (encoding == apimodels.GenerateTokenEffectiveParametersEncodingBase64url && format != apimodels.TokenBase64url) ||
			(encoding == apimodels.GenerateTokenEffectiveParametersEncodingHex && format != apimodels.TokenHex) {
			return response, errors.New("token result format is invalid")
		}
		err := response.FromGenerateTokenResponse(apimodels.GenerateTokenResponse{
			Kind:      apimodels.GenerateTokenResponseKindToken,
			ProfileId: generated.ProfileID,
			EffectiveParameters: apimodels.GenerateTokenEffectiveParameters{
				Encoding: encoding,
				Bytes:    generated.EffectiveParameters.Bytes,
			},
			Secret: apimodels.GenerateTokenSecret{Format: format, VaultText: generated.Secret.VaultText},
		})
		return response, err

	case vaultservice.GeneratedSSHKeyPairResult:
		algorithm := apimodels.GenerateSSHKeyAlgorithm(generated.Algorithm)
		secretFormat := apimodels.GenerateSSHKeyPairSecretFormat(generated.Secret.Format)
		publicFormat := apimodels.GenerateSSHKeyPairPublicFormat(generated.Public.Format)
		if !algorithm.Valid() || !secretFormat.Valid() || !publicFormat.Valid() ||
			generated.ProfileID == "" || generated.Secret.VaultText == "" || generated.Public.AuthorizedKey == "" || generated.Public.Fingerprint == "" {
			return response, errors.New("SSH result is invalid")
		}
		err := response.FromGenerateSSHKeyPairResponse(apimodels.GenerateSSHKeyPairResponse{
			Kind:                apimodels.GenerateSSHKeyPairResponseKindSshKeypair,
			ProfileId:           generated.ProfileID,
			EffectiveParameters: apimodels.GenerateSSHKeyPairEffectiveParameters{Algorithm: algorithm},
			Secret:              apimodels.GenerateSSHKeyPairSecret{Format: secretFormat, VaultText: generated.Secret.VaultText},
			Public: apimodels.GenerateSSHKeyPairPublic{
				Format: publicFormat, AuthorizedKey: generated.Public.AuthorizedKey, Fingerprint: generated.Public.Fingerprint,
			},
		})
		return response, err

	case vaultservice.GeneratedAgeIdentityResult:
		algorithm := apimodels.GenerateAgeIdentityEffectiveParametersAlgorithm(generated.Algorithm)
		secretFormat := apimodels.GenerateAgeIdentitySecretFormat(generated.Secret.Format)
		publicFormat := apimodels.GenerateAgeIdentityPublicFormat(generated.Public.Format)
		if !algorithm.Valid() || !secretFormat.Valid() || !publicFormat.Valid() ||
			generated.ProfileID == "" || generated.Secret.VaultText == "" || generated.Public.Recipient == "" {
			return response, errors.New("age result is invalid")
		}
		err := response.FromGenerateAgeIdentityResponse(apimodels.GenerateAgeIdentityResponse{
			Kind:                apimodels.GenerateAgeIdentityResponseKindAgeIdentity,
			ProfileId:           generated.ProfileID,
			EffectiveParameters: apimodels.GenerateAgeIdentityEffectiveParameters{Algorithm: algorithm},
			Secret:              apimodels.GenerateAgeIdentitySecret{Format: secretFormat, VaultText: generated.Secret.VaultText},
			Public:              apimodels.GenerateAgeIdentityPublic{Format: publicFormat, Recipient: generated.Public.Recipient},
		})
		return response, err

	case vaultservice.GeneratedX509CSRResult:
		algorithm := apimodels.GenerateX509KeyAlgorithm(generated.Algorithm)
		secretFormat := apimodels.GenerateX509CSRSecretFormat(generated.Secret.Format)
		publicFormat := apimodels.GenerateX509CSRPublicFormat(generated.Public.Format)
		if !algorithm.Valid() || !secretFormat.Valid() || !publicFormat.Valid() ||
			generated.ProfileID == "" || generated.Secret.VaultText == "" || generated.Public.CSRPEM == "" || generated.Public.Fingerprint == "" {
			return response, errors.New("X.509 result is invalid")
		}
		err := response.FromGenerateX509CSRResponse(apimodels.GenerateX509CSRResponse{
			Kind:                apimodels.GenerateX509CSRResponseKindX509Csr,
			ProfileId:           generated.ProfileID,
			EffectiveParameters: apimodels.GenerateX509CSREffectiveParameters{Algorithm: algorithm},
			Secret:              apimodels.GenerateX509CSRSecret{Format: secretFormat, VaultText: generated.Secret.VaultText},
			Public: apimodels.GenerateX509CSRPublic{
				Format: publicFormat, CsrPem: generated.Public.CSRPEM, Fingerprint: generated.Public.Fingerprint,
			},
		})
		return response, err
	default:
		return response, errors.New("generation result variant is invalid")
	}
}
