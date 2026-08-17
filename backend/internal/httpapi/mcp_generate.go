package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/forgeplane-io/vaultsmith/backend/internal/caller"
	"github.com/forgeplane-io/vaultsmith/backend/internal/vaultservice"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const mcpGenerateResultText = "Generated material is available in structuredContent."

func isMCPGenerateTool(name string) bool {
	switch name {
	case "generate_password", "generate_token", "generate_ssh_keypair", "generate_age_identity", "generate_x509_csr":
		return true
	default:
		return false
	}
}

func mcpGenerateTools() []*mcp.Tool {
	return []*mcp.Tool{
		{
			Name:         "generate_password",
			Description:  "Generate a bounded password and return only its sealed Vault form.",
			Annotations:  mcpGenerateAnnotations(),
			InputSchema:  mcpGeneratePasswordInputSchema(),
			OutputSchema: mcpGeneratePasswordOutputSchema(),
		},
		{
			Name:         "generate_token",
			Description:  "Generate a random token and return only its sealed Vault form.",
			Annotations:  mcpGenerateAnnotations(),
			InputSchema:  mcpGenerateTokenInputSchema(),
			OutputSchema: mcpGenerateTokenOutputSchema(),
		},
		{
			Name:         "generate_ssh_keypair",
			Description:  "Generate an SSH keypair and return the sealed private key with its public companion.",
			Annotations:  mcpGenerateAnnotations(),
			InputSchema:  mcpGenerateSSHInputSchema(),
			OutputSchema: mcpGenerateSSHOutputSchema(),
		},
		{
			Name:         "generate_age_identity",
			Description:  "Generate an age X25519 identity and return the sealed identity with its recipient.",
			Annotations:  mcpGenerateAnnotations(),
			InputSchema:  mcpGenerateAgeInputSchema(),
			OutputSchema: mcpGenerateAgeOutputSchema(),
		},
		{
			Name:         "generate_x509_csr",
			Description:  "Generate an X.509 private key and PKCS#10 CSR, returning the sealed key and public CSR.",
			Annotations:  mcpGenerateAnnotations(),
			InputSchema:  mcpGenerateX509InputSchema(),
			OutputSchema: mcpGenerateX509OutputSchema(),
		},
	}
}

func mcpGenerateAnnotations() *mcp.ToolAnnotations {
	value := false
	return &mcp.ToolAnnotations{
		ReadOnlyHint:    false,
		DestructiveHint: &value,
		IdempotentHint:  false,
		OpenWorldHint:   &value,
	}
}

func decodeMCPGenerateCommand(name string, raw json.RawMessage) (vaultservice.GenerateCommand, error) {
	allowed, kind := mcpGenerateArgumentShape(name)
	if allowed == nil {
		return vaultservice.GenerateCommand{}, errors.New("generation tool is invalid")
	}
	fields, err := decodeStrictObject(raw, allowed)
	if err != nil {
		return vaultservice.GenerateCommand{}, err
	}
	rawProfileID, ok := fields["profileId"]
	if !ok {
		return vaultservice.GenerateCommand{}, errors.New("profileId is required")
	}
	profileID, err := decodeGenerateString(rawProfileID)
	if err != nil {
		return vaultservice.GenerateCommand{}, err
	}
	delete(fields, "profileId")
	parameters, err := json.Marshal(fields)
	if err != nil {
		return vaultservice.GenerateCommand{}, errors.New("tool arguments are invalid")
	}

	command := vaultservice.GenerateCommand{ProfileID: profileID, Kind: kind}
	switch kind {
	case vaultservice.GenerateKindPassword:
		decoded, err := parsePasswordParameters(parameters)
		if err != nil {
			return vaultservice.GenerateCommand{}, err
		}
		command.Password = &decoded
	case vaultservice.GenerateKindToken:
		decoded, err := parseTokenParameters(parameters)
		if err != nil {
			return vaultservice.GenerateCommand{}, err
		}
		command.Token = &decoded
	case vaultservice.GenerateKindSSHKeyPair:
		decoded, err := parseSSHKeyPairParameters(parameters)
		if err != nil {
			return vaultservice.GenerateCommand{}, err
		}
		command.SSHKeyPair = &decoded
	case vaultservice.GenerateKindAgeIdentity:
		command.AgeIdentity = &vaultservice.AgeIdentityParameters{}
	case vaultservice.GenerateKindX509CSR:
		decoded, err := parseX509CSRParameters(parameters)
		if err != nil {
			return vaultservice.GenerateCommand{}, err
		}
		command.X509CSR = &decoded
	default:
		return vaultservice.GenerateCommand{}, errors.New("generation tool is invalid")
	}
	return command, nil
}

func mcpGenerateArgumentShape(name string) (map[string]struct{}, vaultservice.GenerateKind) {
	switch name {
	case "generate_password":
		return map[string]struct{}{
			"profileId": {}, "length": {}, "lowercase": {}, "uppercase": {}, "digits": {}, "symbols": {},
			"minLowercase": {}, "minUppercase": {}, "minDigits": {}, "minSymbols": {}, "excludeAmbiguous": {},
		}, vaultservice.GenerateKindPassword
	case "generate_token":
		return map[string]struct{}{"profileId": {}, "encoding": {}, "bytes": {}}, vaultservice.GenerateKindToken
	case "generate_ssh_keypair":
		return map[string]struct{}{"profileId": {}, "algorithm": {}}, vaultservice.GenerateKindSSHKeyPair
	case "generate_age_identity":
		return map[string]struct{}{"profileId": {}}, vaultservice.GenerateKindAgeIdentity
	case "generate_x509_csr":
		return map[string]struct{}{"profileId": {}, "algorithm": {}, "subject": {}, "sans": {}}, vaultservice.GenerateKindX509CSR
	default:
		return nil, ""
	}
}

func (h *Handler) serveMCPGenerateTool(w http.ResponseWriter, id json.RawMessage, actor caller.Caller, leaseContext context.Context, name string, rawArguments json.RawMessage) {
	command, err := decodeMCPGenerateCommand(name, rawArguments)
	if err != nil {
		mcpWriteToolError(w, id, mcpTextInvalidToolArguments)
		return
	}
	result, err := h.service.Generate(leaseContext, actor, command)
	if err != nil {
		if mcpServiceUnavailable(err) {
			mcpWriteServiceUnavailable(w, err)
			return
		}
		if actor.Kind() != caller.KindAnonymous && vaultservice.IsPolicyDenied(err) {
			writeError(w, http.StatusForbidden, "forbidden", "operation is not permitted")
			return
		}
		mcpWriteToolError(w, id, mcpTextToolFailure)
		return
	}
	response, err := mapGenerateResponse(result)
	if err != nil {
		mcpWriteToolError(w, id, mcpTextToolFailure)
		return
	}
	encoded, err := json.Marshal(response)
	if err != nil || !json.Valid(encoded) {
		mcpWriteToolError(w, id, mcpTextToolFailure)
		return
	}
	mcpWriteResult(w, id, mcpGenerateCallResult(response))
}

func mcpGenerateCallResult(structured any) mcpCallToolResult {
	return mcpCallToolResult{
		Meta:              mcpResultMeta(),
		ResultType:        "complete",
		TTLMs:             0,
		CacheScope:        "private",
		Content:           []mcp.Content{&mcp.TextContent{Text: mcpGenerateResultText}},
		StructuredContent: structured,
		IsError:           false,
	}
}

func mcpGeneratePasswordInputSchema() map[string]any {
	properties := mcpPasswordParameterProperties()
	properties["profileId"] = mcpGenerateProfileIDSchema()
	schema := mcpGenerateRootObjectSchema([]string{"profileId"}, properties)
	schema["x-semanticConstraints"] = mcpPasswordSemanticConstraints()
	return schema
}

func mcpGenerateTokenInputSchema() map[string]any {
	properties := mcpTokenParameterProperties()
	properties["profileId"] = mcpGenerateProfileIDSchema()
	return mcpGenerateRootObjectSchema([]string{"profileId"}, properties)
}

func mcpGenerateSSHInputSchema() map[string]any {
	return mcpGenerateRootObjectSchema([]string{"profileId", "algorithm"}, map[string]any{
		"profileId": mcpGenerateProfileIDSchema(),
		"algorithm": mcpSSHAlgorithmSchema(),
	})
}

func mcpGenerateAgeInputSchema() map[string]any {
	return mcpGenerateRootObjectSchema([]string{"profileId"}, map[string]any{
		"profileId": mcpGenerateProfileIDSchema(),
	})
}

func mcpGenerateX509InputSchema() map[string]any {
	schema := mcpGenerateRootObjectSchema([]string{"profileId", "algorithm"}, map[string]any{
		"profileId": mcpGenerateProfileIDSchema(),
		"algorithm": mcpX509AlgorithmSchema(),
		"subject":   mcpX509SubjectSchema(),
		"sans":      mcpX509SANsSchema(),
	})
	schema["x-requiresOneOf"] = []string{"subject.commonName", "at least one item in any sans array"}
	return schema
}

func mcpGeneratePasswordOutputSchema() map[string]any {
	effective := mcpGenerateClosedObjectSchema([]string{
		"length", "lowercase", "uppercase", "digits", "symbols",
		"minLowercase", "minUppercase", "minDigits", "minSymbols", "excludeAmbiguous",
	}, mcpPasswordParameterProperties())
	return mcpGenerateRootObjectSchema([]string{"kind", "profileId", "effectiveParameters", "secret"}, map[string]any{
		"kind":                map[string]any{"const": "password"},
		"profileId":           mcpGenerateProfileIDSchema(),
		"effectiveParameters": effective,
		"secret":              mcpGenerateSecretSchema(map[string]any{"const": "password_ascii"}),
	})
}

func mcpGenerateTokenOutputSchema() map[string]any {
	effective := mcpGenerateClosedObjectSchema([]string{"encoding", "bytes"}, mcpTokenParameterProperties())
	schema := mcpGenerateRootObjectSchema([]string{"kind", "profileId", "effectiveParameters", "secret"}, map[string]any{
		"kind":                map[string]any{"const": "token"},
		"profileId":           mcpGenerateProfileIDSchema(),
		"effectiveParameters": effective,
		"secret": mcpGenerateSecretSchema(map[string]any{
			"type": "string", "enum": []string{"token_base64url", "token_hex"},
		}),
	})
	schema["x-secretFormatByEncoding"] = map[string]string{"base64url": "token_base64url", "hex": "token_hex"}
	return schema
}

func mcpGenerateSSHOutputSchema() map[string]any {
	return mcpGenerateRootObjectSchema([]string{"kind", "profileId", "effectiveParameters", "secret", "public"}, map[string]any{
		"kind":      map[string]any{"const": "ssh_keypair"},
		"profileId": mcpGenerateProfileIDSchema(),
		"effectiveParameters": mcpGenerateClosedObjectSchema([]string{"algorithm"}, map[string]any{
			"algorithm": mcpSSHAlgorithmSchema(),
		}),
		"secret": mcpGenerateSecretSchema(map[string]any{"const": "openssh_private_key"}),
		"public": mcpGenerateClosedObjectSchema([]string{"format", "authorizedKey", "fingerprint"}, map[string]any{
			"format":        map[string]any{"const": "openssh_authorized_key"},
			"authorizedKey": map[string]any{"type": "string", "minLength": 1},
			"fingerprint":   mcpGenerateFingerprintSchema(),
		}),
	})
}

func mcpGenerateAgeOutputSchema() map[string]any {
	return mcpGenerateRootObjectSchema([]string{"kind", "profileId", "effectiveParameters", "secret", "public"}, map[string]any{
		"kind":      map[string]any{"const": "age_identity"},
		"profileId": mcpGenerateProfileIDSchema(),
		"effectiveParameters": mcpGenerateClosedObjectSchema([]string{"algorithm"}, map[string]any{
			"algorithm": map[string]any{"const": "x25519"},
		}),
		"secret": mcpGenerateSecretSchema(map[string]any{"const": "age_x25519_identity"}),
		"public": mcpGenerateClosedObjectSchema([]string{"format", "recipient"}, map[string]any{
			"format":    map[string]any{"const": "age_x25519_recipient"},
			"recipient": map[string]any{"type": "string", "pattern": "^age1[0-9a-z]+$"},
		}),
	})
}

func mcpGenerateX509OutputSchema() map[string]any {
	return mcpGenerateRootObjectSchema([]string{"kind", "profileId", "effectiveParameters", "secret", "public"}, map[string]any{
		"kind":      map[string]any{"const": "x509_csr"},
		"profileId": mcpGenerateProfileIDSchema(),
		"effectiveParameters": mcpGenerateClosedObjectSchema([]string{"algorithm"}, map[string]any{
			"algorithm": mcpX509AlgorithmSchema(),
		}),
		"secret": mcpGenerateSecretSchema(map[string]any{"const": "pkcs8_private_key_pem"}),
		"public": mcpGenerateClosedObjectSchema([]string{"format", "csrPem", "fingerprint"}, map[string]any{
			"format": map[string]any{"const": "pkcs10_csr_pem"},
			"csrPem": map[string]any{
				"type": "string", "minLength": 1, "x-format": "CERTIFICATE REQUEST PEM with exactly one terminal LF",
			},
			"fingerprint": mcpGenerateFingerprintSchema(),
		}),
	})
}

func mcpGenerateRootObjectSchema(required []string, properties map[string]any) map[string]any {
	schema := mcpGenerateClosedObjectSchema(required, properties)
	schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
	return schema
}

func mcpGenerateClosedObjectSchema(required []string, properties map[string]any) map[string]any {
	if required == nil {
		required = []string{}
	}
	if properties == nil {
		properties = map[string]any{}
	}
	return map[string]any{
		"type":                 "object",
		"additionalProperties": false,
		"required":             required,
		"properties":           properties,
	}
}

func mcpGenerateProfileIDSchema() map[string]any {
	return map[string]any{
		"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,63}$", "minLength": 1, "maxLength": 64,
	}
}

func mcpPasswordParameterProperties() map[string]any {
	return map[string]any{
		"length":           map[string]any{"type": "integer", "minimum": 22, "maximum": 128, "default": 32},
		"lowercase":        map[string]any{"type": "boolean", "default": true},
		"uppercase":        map[string]any{"type": "boolean", "default": true},
		"digits":           map[string]any{"type": "boolean", "default": true},
		"symbols":          map[string]any{"type": "boolean", "default": false},
		"minLowercase":     map[string]any{"type": "integer", "minimum": 0, "maximum": 32, "x-default": "1 when effective lowercase is true; otherwise 0"},
		"minUppercase":     map[string]any{"type": "integer", "minimum": 0, "maximum": 32, "x-default": "1 when effective uppercase is true; otherwise 0"},
		"minDigits":        map[string]any{"type": "integer", "minimum": 0, "maximum": 32, "x-default": "1 when effective digits is true; otherwise 0"},
		"minSymbols":       map[string]any{"type": "integer", "minimum": 0, "maximum": 32, "x-default": "1 when effective symbols is true; otherwise 0"},
		"excludeAmbiguous": map[string]any{"type": "boolean", "default": false},
	}
}

func mcpPasswordSemanticConstraints() []string {
	return []string{
		"At least one class is enabled",
		"A non-zero minimum requires its corresponding class",
		"The sum of effective minima does not exceed length",
		"The exact accepted-set cardinality N is at least 2^128",
	}
}

func mcpTokenParameterProperties() map[string]any {
	return map[string]any{
		"encoding": map[string]any{"type": "string", "enum": []string{"base64url", "hex"}, "default": "base64url"},
		"bytes":    map[string]any{"type": "integer", "minimum": 16, "maximum": 64, "default": 32},
	}
}

func mcpSSHAlgorithmSchema() map[string]any {
	return map[string]any{"type": "string", "enum": []string{"ed25519", "ecdsa_p256", "rsa_3072", "rsa_4096"}}
}

func mcpX509AlgorithmSchema() map[string]any {
	return map[string]any{"type": "string", "enum": []string{"ed25519", "ecdsa_p256", "ecdsa_p384", "rsa_3072", "rsa_4096"}}
}

func mcpX509SubjectSchema() map[string]any {
	schema := mcpGenerateClosedObjectSchema(nil, map[string]any{
		"commonName":         mcpX509DNValueSchema(),
		"serialNumber":       mcpX509DNValueSchema(),
		"country":            mcpX509CountryArraySchema(),
		"organization":       mcpX509DNArraySchema(),
		"organizationalUnit": mcpX509DNArraySchema(),
		"locality":           mcpX509DNArraySchema(),
		"province":           mcpX509DNArraySchema(),
		"streetAddress":      mcpX509DNArraySchema(),
		"postalCode":         mcpX509DNArraySchema(),
	})
	schema["minProperties"] = 1
	return schema
}

func mcpX509SANsSchema() map[string]any {
	dnsNames := mcpX509DNSOrEmailArraySchema()
	dnsNames["x-format"] = "ASCII DNS A-labels"
	emailAddresses := mcpX509DNSOrEmailArraySchema()
	emailAddresses["x-format"] = "addr-spec without display name"
	schema := mcpGenerateClosedObjectSchema(nil, map[string]any{
		"dnsNames":       dnsNames,
		"ipAddresses":    mcpX509IPArraySchema(),
		"emailAddresses": emailAddresses,
		"uris":           mcpX509URIArraySchema(),
	})
	schema["minProperties"] = 1
	schema["x-totalItemsMaximum"] = 64
	return schema
}

func mcpX509DNValueSchema() map[string]any {
	return map[string]any{
		"type": "string", "minLength": 1, "x-maxUtf8Bytes": 256,
		"x-leadingOrTrailingUnicodeWhitespace": "reject", "x-nulOrAsciiControl": "reject",
	}
}

func mcpX509DNArraySchema() map[string]any {
	return map[string]any{
		"type": "array", "minItems": 1, "maxItems": 8, "uniqueItems": true, "items": mcpX509DNValueSchema(),
	}
}

func mcpX509CountryArraySchema() map[string]any {
	return map[string]any{
		"type": "array", "minItems": 1, "maxItems": 8, "uniqueItems": true,
		"items": map[string]any{"type": "string", "pattern": "^[A-Z]{2}$"},
	}
}

func mcpX509DNSOrEmailArraySchema() map[string]any {
	return map[string]any{
		"type": "array", "minItems": 1, "maxItems": 64, "uniqueItems": true,
		"items": map[string]any{
			"type": "string", "minLength": 1, "x-asciiOnly": true, "x-maxAsciiBytes": 253,
			"x-leadingOrTrailingUnicodeWhitespace": "reject", "x-nulOrAsciiControl": "reject",
		},
	}
}

func mcpX509IPArraySchema() map[string]any {
	return map[string]any{
		"type": "array", "minItems": 1, "maxItems": 64, "uniqueItems": true,
		"items": map[string]any{
			"type": "string", "minLength": 1,
			"x-format": "canonical unscoped IPv4 or IPv6 text, excluding IPv4-mapped IPv6",
		},
	}
}

func mcpX509URIArraySchema() map[string]any {
	return map[string]any{
		"type": "array", "minItems": 1, "maxItems": 64, "uniqueItems": true,
		"items": map[string]any{
			"type": "string", "minLength": 1, "x-asciiOnly": true, "x-maxAsciiBytes": 2048,
			"x-format":                             "RFC 3986 ASCII absolute URI with scheme",
			"x-leadingOrTrailingUnicodeWhitespace": "reject", "x-nulOrAsciiControl": "reject",
		},
	}
}

func mcpGenerateSecretSchema(format map[string]any) map[string]any {
	return mcpGenerateClosedObjectSchema([]string{"format", "vaultText"}, map[string]any{
		"format":    format,
		"vaultText": map[string]any{"type": "string", "minLength": 1},
	})
}

func mcpGenerateFingerprintSchema() map[string]any {
	return map[string]any{"type": "string", "pattern": "^SHA256:[A-Za-z0-9+/]+$"}
}
