package vaultservice

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"unicode/utf8"

	"github.com/forgeplane-io/vaultsmith/backend/internal/ansiblevault"
	"github.com/forgeplane-io/vaultsmith/backend/internal/caller"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
	"github.com/forgeplane-io/vaultsmith/backend/internal/generate"
)

type GenerateKind string

const (
	GenerateKindPassword    GenerateKind = "password"
	GenerateKindToken       GenerateKind = "token"
	GenerateKindSSHKeyPair  GenerateKind = "ssh_keypair"
	GenerateKindAgeIdentity GenerateKind = "age_identity"
	GenerateKindX509CSR     GenerateKind = "x509_csr"
)

// MaterialGenerator is the transport-independent generation seam. Production
// construction installs generate.New; only internal service options can
// replace it for failure and ordering tests.
type MaterialGenerator interface {
	GeneratePassword(generate.PasswordParameters) (generate.PasswordResult, error)
	GenerateToken(generate.TokenParameters) (generate.TokenResult, error)
	GenerateSSHKeyPair(generate.SSHKeyPairParameters) (generate.SSHKeyPairResult, error)
	GenerateAgeIdentity() (generate.AgeIdentityResult, error)
	GenerateX509CSR(generate.X509CSRParameters) (generate.X509CSRResult, error)
}

// AgeIdentityParameters exists so every command variant has an explicit,
// non-nil parameter object. The type intentionally has no fields.
type AgeIdentityParameters struct{}

// GenerateCommand is a closed in-process discriminated union. Transports must
// set exactly the parameter pointer selected by Kind. Only the destination
// profile and kind are inspected before profile authorization; variant shape
// and generator parameters are checked afterwards.
type GenerateCommand struct {
	ProfileID string
	Kind      GenerateKind

	Password    *generate.PasswordParameters
	Token       *generate.TokenParameters
	SSHKeyPair  *generate.SSHKeyPairParameters
	AgeIdentity *AgeIdentityParameters
	X509CSR     *generate.X509CSRParameters
}

type GeneratedSecret struct {
	Format    string
	VaultText string
}

type GeneratedSSHPublic struct {
	Format        string
	AuthorizedKey string
	Fingerprint   string
}

type GeneratedAgePublic struct {
	Format    string
	Recipient string
}

type GeneratedX509Public struct {
	Format      string
	CSRPEM      string
	Fingerprint string
}

// GenerateResult is the closed service result union. Its implementations
// contain only profile-encrypted Vault text, effective non-secret parameters,
// and the public companion allowed for that material kind.
type GenerateResult interface {
	MaterialKind() GenerateKind
	DestinationProfileID() string
	SealedSecret() GeneratedSecret
	isGenerateResult()
}

type GeneratedPasswordResult struct {
	ProfileID           string
	EffectiveParameters generate.EffectivePasswordParameters
	Secret              GeneratedSecret
}

func (GeneratedPasswordResult) MaterialKind() GenerateKind { return GenerateKindPassword }
func (r GeneratedPasswordResult) DestinationProfileID() string {
	return r.ProfileID
}
func (r GeneratedPasswordResult) SealedSecret() GeneratedSecret { return r.Secret }
func (GeneratedPasswordResult) isGenerateResult()               {}

type GeneratedTokenResult struct {
	ProfileID           string
	EffectiveParameters generate.EffectiveTokenParameters
	Secret              GeneratedSecret
}

func (GeneratedTokenResult) MaterialKind() GenerateKind { return GenerateKindToken }
func (r GeneratedTokenResult) DestinationProfileID() string {
	return r.ProfileID
}
func (r GeneratedTokenResult) SealedSecret() GeneratedSecret { return r.Secret }
func (GeneratedTokenResult) isGenerateResult()               {}

type GeneratedSSHKeyPairResult struct {
	ProfileID string
	Algorithm generate.SSHAlgorithm
	Secret    GeneratedSecret
	Public    GeneratedSSHPublic
}

func (GeneratedSSHKeyPairResult) MaterialKind() GenerateKind { return GenerateKindSSHKeyPair }
func (r GeneratedSSHKeyPairResult) DestinationProfileID() string {
	return r.ProfileID
}
func (r GeneratedSSHKeyPairResult) SealedSecret() GeneratedSecret { return r.Secret }
func (GeneratedSSHKeyPairResult) isGenerateResult()               {}

type GeneratedAgeIdentityResult struct {
	ProfileID string
	Algorithm string
	Secret    GeneratedSecret
	Public    GeneratedAgePublic
}

func (GeneratedAgeIdentityResult) MaterialKind() GenerateKind { return GenerateKindAgeIdentity }
func (r GeneratedAgeIdentityResult) DestinationProfileID() string {
	return r.ProfileID
}
func (r GeneratedAgeIdentityResult) SealedSecret() GeneratedSecret { return r.Secret }
func (GeneratedAgeIdentityResult) isGenerateResult()               {}

type GeneratedX509CSRResult struct {
	ProfileID string
	Algorithm generate.X509Algorithm
	Secret    GeneratedSecret
	Public    GeneratedX509Public
}

func (GeneratedX509CSRResult) MaterialKind() GenerateKind { return GenerateKindX509CSR }
func (r GeneratedX509CSRResult) DestinationProfileID() string {
	return r.ProfileID
}
func (r GeneratedX509CSRResult) SealedSecret() GeneratedSecret { return r.Secret }
func (GeneratedX509CSRResult) isGenerateResult()               {}

// PreflightGenerate is the bodyless service and fixed-scope check shared by
// REST and MCP. It deliberately does not resolve a profile or inspect request
// parameters.
func (s *Service) PreflightGenerate(ctx context.Context, actor caller.Caller) error {
	if err := s.Preflight(ctx, actor, OperationEncrypt); err != nil {
		return err
	}
	if !s.Ready() || s.generator == nil {
		return notReady("service is not ready")
	}
	return nil
}

// Generate creates one private value and immediately seals its exact
// serialization with the already-bound destination profile. The operation
// requires the same live, context-bound admission lease as PreparedOperation.
func (s *Service) Generate(ctx context.Context, actor caller.Caller, command GenerateCommand) (GenerateResult, error) {
	if err := s.PreflightGenerate(ctx, actor); err != nil {
		return nil, err
	}

	lease := leaseFromContext(ctx)
	if err := leaseBoundContextError(ctx, lease); err != nil {
		return nil, err
	}
	if lease == nil || !lease.liveForContext(ctx, s.admission) {
		return nil, notReady("operation admission is not ready")
	}
	executionContext := lease.executionContext()
	if executionContext == nil {
		return nil, notReady("operation admission is not ready")
	}
	if err := leaseBoundContextError(executionContext, lease); err != nil {
		return nil, err
	}
	if !lease.holdForContext(ctx, s.admission) {
		if err := leaseBoundContextError(ctx, lease); err != nil {
			return nil, err
		}
		return nil, notReady("operation admission is not ready")
	}
	defer lease.releaseHold()

	operationContext, releaseOperationContext := mergeCancellationContexts(executionContext, ctx)
	defer releaseOperationContext()
	if err := leaseMergedContextError(ctx, operationContext, lease); err != nil {
		return nil, err
	}
	if err := validateGenerateIdentity(command); err != nil {
		return nil, err
	}

	authorizationErr := s.authorize(operationContext, actor, Command{
		Operation: OperationEncrypt,
		ProfileID: command.ProfileID,
	})
	if err := leaseMergedContextError(ctx, operationContext, lease); err != nil {
		return nil, err
	}
	if authorizationErr != nil {
		return nil, authorizationErr
	}

	entry, ok := s.byID[command.ProfileID]
	if !ok {
		return nil, profileAccessError(actor)
	}
	if entry.executor == nil {
		return nil, notReady("service is not ready")
	}
	if err := validateGenerateVariant(command); err != nil {
		return nil, err
	}
	if err := leaseMergedContextError(ctx, operationContext, lease); err != nil {
		return nil, err
	}

	material, generationErr := s.generateMaterial(command)
	if err := leaseMergedContextError(ctx, operationContext, lease); err != nil {
		clear(material.private)
		return nil, err
	}
	if generationErr != nil {
		clear(material.private)
		return nil, mapGenerationError(generationErr)
	}
	defer clear(material.private)
	if len(material.private) == 0 || len(material.private) > MaxPlaintextBytes || !utf8.Valid(material.private) || material.result == nil {
		return nil, operationFailed()
	}

	vaultText, err := entry.executor.Encrypt(operationContext, string(material.private))
	if contextErr := leaseMergedContextError(ctx, operationContext, lease); contextErr != nil {
		return nil, contextErr
	}
	if err != nil {
		return nil, operationFailed()
	}
	validVaultText := validGeneratedVaultText(vaultText, command.ProfileID)
	if contextErr := leaseMergedContextError(ctx, operationContext, lease); contextErr != nil {
		return nil, contextErr
	}
	if !validVaultText {
		return nil, operationFailed()
	}

	result := material.result(vaultText)
	if result == nil || result.MaterialKind() != command.Kind || result.DestinationProfileID() != command.ProfileID {
		return nil, operationFailed()
	}
	secret := result.SealedSecret()
	if secret.VaultText != vaultText || secret.Format == "" {
		return nil, operationFailed()
	}
	if contextErr := leaseMergedContextError(ctx, operationContext, lease); contextErr != nil {
		return nil, contextErr
	}
	return result, nil
}

func validateGenerateIdentity(command GenerateCommand) error {
	if !config.IsValidProfileID(command.ProfileID) {
		return invalidRequest("profile ID is invalid")
	}
	switch command.Kind {
	case GenerateKindPassword, GenerateKindToken, GenerateKindSSHKeyPair, GenerateKindAgeIdentity, GenerateKindX509CSR:
		return nil
	default:
		return invalidRequest("generation kind is invalid")
	}
}

func validateGenerateVariant(command GenerateCommand) error {
	present := 0
	for _, supplied := range []bool{
		command.Password != nil,
		command.Token != nil,
		command.SSHKeyPair != nil,
		command.AgeIdentity != nil,
		command.X509CSR != nil,
	} {
		if supplied {
			present++
		}
	}
	if present != 1 {
		return invalidRequest("generation parameters are invalid")
	}

	valid := false
	switch command.Kind {
	case GenerateKindPassword:
		valid = command.Password != nil
	case GenerateKindToken:
		valid = command.Token != nil
	case GenerateKindSSHKeyPair:
		valid = command.SSHKeyPair != nil
	case GenerateKindAgeIdentity:
		valid = command.AgeIdentity != nil
	case GenerateKindX509CSR:
		valid = command.X509CSR != nil
	}
	if !valid {
		return invalidRequest("generation parameters are invalid")
	}
	return nil
}

type generatedMaterial struct {
	private []byte
	result  func(string) GenerateResult
}

func (s *Service) generateMaterial(command GenerateCommand) (generatedMaterial, error) {
	switch command.Kind {
	case GenerateKindPassword:
		generated, err := s.generator.GeneratePassword(*command.Password)
		if err != nil {
			return generatedMaterial{}, err
		}
		parameters := generated.EffectiveParameters()
		return generatedMaterial{
			private: generated.PrivateBytes(),
			result: func(vaultText string) GenerateResult {
				return GeneratedPasswordResult{
					ProfileID:           command.ProfileID,
					EffectiveParameters: parameters,
					Secret: GeneratedSecret{
						Format:    generate.PasswordFormat,
						VaultText: vaultText,
					},
				}
			},
		}, nil
	case GenerateKindToken:
		generated, err := s.generator.GenerateToken(*command.Token)
		if err != nil {
			return generatedMaterial{}, err
		}
		parameters := generated.EffectiveParameters()
		format := generated.Format()
		if (parameters.Encoding == generate.TokenEncodingBase64URL && format != generate.TokenBase64Format) ||
			(parameters.Encoding == generate.TokenEncodingHex && format != generate.TokenHexFormat) {
			return generatedMaterial{}, generate.ErrGenerationFailed
		}
		return generatedMaterial{
			private: generated.PrivateBytes(),
			result: func(vaultText string) GenerateResult {
				return GeneratedTokenResult{
					ProfileID:           command.ProfileID,
					EffectiveParameters: parameters,
					Secret:              GeneratedSecret{Format: format, VaultText: vaultText},
				}
			},
		}, nil
	case GenerateKindSSHKeyPair:
		generated, err := s.generator.GenerateSSHKeyPair(*command.SSHKeyPair)
		if err != nil {
			return generatedMaterial{}, err
		}
		algorithm := generated.Algorithm()
		authorizedKey := generated.AuthorizedKey()
		fingerprint := generated.Fingerprint()
		if algorithm != command.SSHKeyPair.Algorithm || !validPublicText(authorizedKey) || !validPublicText(fingerprint) {
			return generatedMaterial{}, generate.ErrGenerationFailed
		}
		return generatedMaterial{
			private: generated.PrivateBytes(),
			result: func(vaultText string) GenerateResult {
				return GeneratedSSHKeyPairResult{
					ProfileID: command.ProfileID,
					Algorithm: algorithm,
					Secret: GeneratedSecret{
						Format:    generate.SSHPrivateFormat,
						VaultText: vaultText,
					},
					Public: GeneratedSSHPublic{
						Format:        generate.SSHPublicFormat,
						AuthorizedKey: authorizedKey,
						Fingerprint:   fingerprint,
					},
				}
			},
		}, nil
	case GenerateKindAgeIdentity:
		generated, err := s.generator.GenerateAgeIdentity()
		if err != nil {
			return generatedMaterial{}, err
		}
		recipient := generated.Recipient()
		if !validPublicText(recipient) {
			return generatedMaterial{}, generate.ErrGenerationFailed
		}
		return generatedMaterial{
			private: generated.PrivateBytes(),
			result: func(vaultText string) GenerateResult {
				return GeneratedAgeIdentityResult{
					ProfileID: command.ProfileID,
					Algorithm: "x25519",
					Secret: GeneratedSecret{
						Format:    generate.AgePrivateFormat,
						VaultText: vaultText,
					},
					Public: GeneratedAgePublic{
						Format:    generate.AgePublicFormat,
						Recipient: recipient,
					},
				}
			},
		}, nil
	case GenerateKindX509CSR:
		generated, err := s.generator.GenerateX509CSR(*command.X509CSR)
		if err != nil {
			return generatedMaterial{}, err
		}
		algorithm := generated.Algorithm()
		csrPEM := generated.CSRPEM()
		fingerprint := generated.Fingerprint()
		if algorithm != command.X509CSR.Algorithm || !validPublicText(csrPEM) || !validPublicText(fingerprint) {
			return generatedMaterial{}, generate.ErrGenerationFailed
		}
		return generatedMaterial{
			private: generated.PrivateBytes(),
			result: func(vaultText string) GenerateResult {
				return GeneratedX509CSRResult{
					ProfileID: command.ProfileID,
					Algorithm: algorithm,
					Secret: GeneratedSecret{
						Format:    generate.X509PrivateFormat,
						VaultText: vaultText,
					},
					Public: GeneratedX509Public{
						Format:      generate.X509PublicFormat,
						CSRPEM:      csrPEM,
						Fingerprint: fingerprint,
					},
				}
			},
		}, nil
	default:
		return generatedMaterial{}, generate.ErrInvalidParameters
	}
}

func mapGenerationError(err error) error {
	if errors.Is(err, generate.ErrInvalidParameters) {
		return invalidRequest("generation parameters are invalid")
	}
	return operationFailed()
}

func validGeneratedVaultText(vaultText, profileID string) bool {
	expectedHeader := ansiblevault.Header12Prefix + ";" + profileID + "\n"
	if !strings.HasPrefix(vaultText, expectedHeader) {
		return false
	}
	canonical, err := ansiblevault.CanonicalEnvelope(vaultText)
	return err == nil && bytes.Equal(canonical, []byte(vaultText))
}

func validPublicText(value string) bool {
	return value != "" && utf8.ValidString(value) && !strings.ContainsRune(value, '\x00')
}
