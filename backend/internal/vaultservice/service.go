package vaultservice

import (
	"context"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"github.com/forgeplane-io/vaultsmith/backend/internal/ansiblevault"
	"github.com/forgeplane-io/vaultsmith/backend/internal/authz"
	"github.com/forgeplane-io/vaultsmith/backend/internal/caller"
	"github.com/forgeplane-io/vaultsmith/backend/internal/config"
)

const (
	MaxPlaintextBytes = ansiblevault.MaxPlaintextBytes
	MaxVaultTextBytes = 5 << 20

	ScopeProfileRead = "vaultsmith.profile.read"
	ScopeEncrypt     = "vaultsmith.encrypt"
	ScopeDecrypt     = "vaultsmith.decrypt"
	ScopeRotate      = "vaultsmith.rotate"
)

type Operation string

const (
	OperationEncrypt Operation = "encrypt"
	OperationDecrypt Operation = "decrypt"
	OperationRotate  Operation = "rotate"
)

type Profile struct {
	ID           string
	Label        string
	Capabilities ProfileCapabilities
}

type ProfileCapabilities struct {
	Encrypt           bool
	Decrypt           bool
	RotateSource      bool
	RotateDestination bool
}

type Command struct {
	Operation            Operation
	ProfileID            string
	SourceProfileID      string
	DestinationProfileID string
	Value                string
}

// ProfileExecutor is bound to one resolved profile. It never accepts a profile
// identifier, so PreparedOperation.Run cannot perform another profile lookup.
type ProfileExecutor interface {
	Encrypt(context.Context, string) (string, error)
	Decrypt(context.Context, string) (string, error)
}

// Executor resolves profile-bound executors while the service catalog is built.
type Executor interface {
	ForProfile(string) (ProfileExecutor, error)
}

type Authorizer interface {
	Evaluate(caller.Caller, []authz.Check) ([]bool, error)
}

type catalogEntry struct {
	profile  Profile
	executor ProfileExecutor
}

type Service struct {
	profiles   []catalogEntry
	byID       map[string]catalogEntry
	authorizer Authorizer
	admission  *Admission
	ready      bool
}

type PreparedOperation struct {
	service     *Service
	lease       *Lease
	context     context.Context
	actor       caller.Caller
	operation   Operation
	value       string
	source      ProfileExecutor
	destination ProfileExecutor
	started     *atomic.Bool
}

func New(profiles []Profile, executor Executor, authorizer Authorizer, admission *Admission) *Service {
	if admission == nil {
		admission = NewRuntimeAdmission()
	}
	entries := make([]catalogEntry, 0, len(profiles))
	byID := make(map[string]catalogEntry, len(profiles))
	ready := len(profiles) > 0 && executor != nil && admission != nil
	for _, input := range profiles {
		profile := Profile{ID: input.ID, Label: input.Label}
		if !config.IsValidProfileID(profile.ID) || strings.TrimSpace(profile.Label) == "" {
			ready = false
		}
		if _, duplicate := byID[profile.ID]; duplicate {
			ready = false
		}
		var bound ProfileExecutor
		if executor != nil {
			resolved, err := executor.ForProfile(profile.ID)
			if err == nil {
				bound = resolved
			}
		}
		if bound == nil {
			ready = false
		}
		entry := catalogEntry{profile: profile, executor: bound}
		entries = append(entries, entry)
		byID[profile.ID] = entry
	}
	return &Service{
		profiles:   entries,
		byID:       byID,
		authorizer: authorizer,
		admission:  admission,
		ready:      ready,
	}
}

func (s *Service) Ready() bool {
	return s != nil && s.ready
}

func (s *Service) Admission() *Admission {
	if s == nil {
		return nil
	}
	return s.admission
}

func (s *Service) ListProfiles(ctx context.Context, actor caller.Caller) ([]Profile, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if !s.Ready() {
		return nil, notReady("service is not ready")
	}
	switch actor.Kind() {
	case caller.KindAnonymous:
		profiles := make([]Profile, len(s.profiles))
		for index, entry := range s.profiles {
			if err := contextError(ctx); err != nil {
				return nil, err
			}
			profile := entry.profile
			profile.Capabilities = ProfileCapabilities{Encrypt: true, Decrypt: true, RotateSource: true, RotateDestination: true}
			profiles[index] = profile
		}
		return profiles, nil
	case caller.KindBearer:
		if !actor.HasScope(ScopeProfileRead) {
			return nil, forbidden()
		}
	case caller.KindSession:
	default:
		return nil, notReady("caller is not ready")
	}
	if s.authorizer == nil {
		return nil, notReady("authorization is not ready")
	}

	checks := make([]authz.Check, 1, 1+len(s.profiles)*2)
	checks[0] = authz.Check{Action: authz.ActionListProfiles, Resource: authz.ResourceProfiles}
	for _, entry := range s.profiles {
		resource := authz.ProfileResource(entry.profile.ID)
		checks = append(checks,
			authz.Check{Action: authz.ActionEncrypt, Resource: resource},
			authz.Check{Action: authz.ActionDecrypt, Resource: resource},
		)
	}
	allowed, err := s.authorizer.Evaluate(actor, checks)
	if contextErr := contextError(ctx); contextErr != nil {
		return nil, contextErr
	}
	if err != nil || len(allowed) != len(checks) {
		return nil, notReady("authorization is not ready")
	}
	if !allowed[0] {
		return []Profile{}, nil
	}

	profiles := make([]Profile, 0, len(s.profiles))
	for index, entry := range s.profiles {
		if err := contextError(ctx); err != nil {
			return nil, err
		}
		encryptAllowed := allowed[1+index*2]
		decryptAllowed := allowed[2+index*2]
		capabilities := ProfileCapabilities{
			Encrypt:           encryptAllowed,
			Decrypt:           decryptAllowed,
			RotateSource:      decryptAllowed,
			RotateDestination: encryptAllowed,
		}
		if actor.Kind() == caller.KindBearer {
			capabilities.Encrypt = capabilities.Encrypt && actor.HasScope(ScopeEncrypt)
			capabilities.Decrypt = capabilities.Decrypt && actor.HasScope(ScopeDecrypt)
			capabilities.RotateSource = capabilities.RotateSource && actor.HasScope(ScopeRotate)
			capabilities.RotateDestination = capabilities.RotateDestination && actor.HasScope(ScopeRotate)
		}
		if capabilities.any() {
			profile := entry.profile
			profile.Capabilities = capabilities
			profiles = append(profiles, profile)
		}
	}
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	return profiles, nil
}

func (s *Service) Prepare(ctx context.Context, actor caller.Caller, command Command, lease *Lease) (*PreparedOperation, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if !s.Ready() {
		return nil, notReady("service is not ready")
	}
	if err := leaseBoundContextError(ctx, lease); err != nil {
		return nil, err
	}
	if !lease.liveForContext(ctx, s.admission) {
		return nil, notReady("operation admission is not ready")
	}
	executionContext := lease.executionContext()
	if executionContext == nil {
		return nil, notReady("operation admission is not ready")
	}
	if err := leaseBoundContextError(executionContext, lease); err != nil {
		return nil, err
	}
	prepareContext, releasePrepareContext := mergeCancellationContexts(executionContext, ctx)
	defer releasePrepareContext()
	if err := leaseMergedContextError(ctx, prepareContext, lease); err != nil {
		return nil, err
	}
	switch actor.Kind() {
	case caller.KindAnonymous, caller.KindSession, caller.KindBearer:
	default:
		return nil, notReady("caller is not ready")
	}
	shapeErr := validateCommandShape(command)
	if err := leaseMergedContextError(ctx, prepareContext, lease); err != nil {
		return nil, err
	}
	if shapeErr != nil {
		return nil, shapeErr
	}
	authorizationErr := s.authorize(prepareContext, actor, command)
	if err := leaseMergedContextError(ctx, prepareContext, lease); err != nil {
		return nil, err
	}
	if authorizationErr != nil {
		return nil, authorizationErr
	}
	resolved, resolutionErr := s.resolveCommand(actor, command)
	if err := leaseMergedContextError(ctx, prepareContext, lease); err != nil {
		return nil, err
	}
	if resolutionErr != nil {
		return nil, resolutionErr
	}
	valueErr := validateCommandValue(command)
	if err := leaseMergedContextError(ctx, prepareContext, lease); err != nil {
		return nil, err
	}
	if valueErr != nil {
		return nil, valueErr
	}
	if err := leaseMergedContextError(ctx, prepareContext, lease); err != nil {
		return nil, err
	}
	return &PreparedOperation{
		service:     s,
		lease:       lease,
		context:     executionContext,
		started:     &atomic.Bool{},
		actor:       actor,
		operation:   command.Operation,
		value:       command.Value,
		source:      resolved.source,
		destination: resolved.destination,
	}, nil
}

func (s *Service) Encrypt(ctx context.Context, actor caller.Caller, profileID, plaintext string) (string, error) {
	return s.prepareAndRun(ctx, actor, Command{Operation: OperationEncrypt, ProfileID: profileID, Value: plaintext})
}

func (s *Service) Decrypt(ctx context.Context, actor caller.Caller, profileID, vaultText string) (string, error) {
	return s.prepareAndRun(ctx, actor, Command{Operation: OperationDecrypt, ProfileID: profileID, Value: vaultText})
}

func (s *Service) Rotate(ctx context.Context, actor caller.Caller, sourceProfileID, destinationProfileID, vaultText string) (string, error) {
	return s.prepareAndRun(ctx, actor, Command{
		Operation:            OperationRotate,
		SourceProfileID:      sourceProfileID,
		DestinationProfileID: destinationProfileID,
		Value:                vaultText,
	})
}

func (s *Service) prepareAndRun(ctx context.Context, actor caller.Caller, command Command) (string, error) {
	lease := leaseFromContext(ctx)
	prepared, err := s.Prepare(ctx, actor, command, lease)
	if err != nil {
		return "", err
	}
	return prepared.Run(ctx)
}

func (s *Service) Preflight(ctx context.Context, actor caller.Caller, operation Operation) error {
	if err := contextError(ctx); err != nil {
		return err
	}
	if _, err := requiredScope(operation); err != nil {
		return err
	}
	switch actor.Kind() {
	case caller.KindAnonymous, caller.KindSession:
		return nil
	case caller.KindBearer:
		scope, _ := requiredScope(operation)
		if !actor.HasScope(scope) {
			return forbidden()
		}
		return nil
	default:
		return notReady("caller is not ready")
	}
}

type resolvedCommand struct {
	source      ProfileExecutor
	destination ProfileExecutor
}

func validateCommandShape(command Command) error {
	switch command.Operation {
	case OperationEncrypt, OperationDecrypt:
		if command.SourceProfileID != "" || command.DestinationProfileID != "" {
			return invalidRequest("source and destination profiles are only valid for rotate")
		}
		if !config.IsValidProfileID(command.ProfileID) {
			return invalidRequest("profile ID is invalid")
		}
	case OperationRotate:
		if command.ProfileID != "" || command.SourceProfileID == "" || command.DestinationProfileID == "" {
			return invalidRequest("rotate requires source and destination profiles")
		}
		if !config.IsValidProfileID(command.SourceProfileID) || !config.IsValidProfileID(command.DestinationProfileID) {
			return invalidRequest("profile ID is invalid")
		}
	default:
		return invalidRequest("operation mode is invalid")
	}
	return nil
}

func validateCommandValue(command Command) error {
	if !utf8.ValidString(command.Value) {
		return invalidRequest("value must be valid UTF-8")
	}
	limit := MaxPlaintextBytes
	if command.Operation != OperationEncrypt {
		limit = MaxVaultTextBytes
	}
	if len(command.Value) > limit {
		return tooLarge()
	}
	return nil
}

func (s *Service) resolveCommand(actor caller.Caller, command Command) (resolvedCommand, error) {
	var resolved resolvedCommand
	switch command.Operation {
	case OperationEncrypt, OperationDecrypt:
		entry, ok := s.byID[command.ProfileID]
		if !ok {
			return resolved, profileAccessError(actor)
		}
		if entry.executor == nil {
			return resolved, notReady("service is not ready")
		}
		resolved.source = entry.executor
	case OperationRotate:
		source, sourceOK := s.byID[command.SourceProfileID]
		destination, destinationOK := s.byID[command.DestinationProfileID]
		if !sourceOK || !destinationOK {
			return resolved, profileAccessError(actor)
		}
		if source.executor == nil || destination.executor == nil {
			return resolved, notReady("service is not ready")
		}
		resolved.source = source.executor
		resolved.destination = destination.executor
	default:
		return resolved, invalidRequest("operation mode is invalid")
	}
	return resolved, nil
}

func (s *Service) authorize(ctx context.Context, actor caller.Caller, command Command) error {
	if actor.Kind() == caller.KindAnonymous {
		return nil
	}
	if err := s.Preflight(ctx, actor, command.Operation); err != nil {
		return err
	}
	if s.authorizer == nil {
		return notReady("authorization is not ready")
	}
	checks := operationChecks(command)
	allowed, err := s.authorizer.Evaluate(actor, checks)
	if contextErr := contextError(ctx); contextErr != nil {
		return contextErr
	}
	if err != nil || len(allowed) != len(checks) {
		return notReady("authorization is not ready")
	}
	for _, decision := range allowed {
		if !decision {
			return forbidden()
		}
	}
	return nil
}

func operationChecks(command Command) []authz.Check {
	switch command.Operation {
	case OperationEncrypt:
		return []authz.Check{{Action: authz.ActionEncrypt, Resource: authz.ProfileResource(command.ProfileID)}}
	case OperationDecrypt:
		return []authz.Check{{Action: authz.ActionDecrypt, Resource: authz.ProfileResource(command.ProfileID)}}
	case OperationRotate:
		return []authz.Check{
			{Action: authz.ActionDecrypt, Resource: authz.ProfileResource(command.SourceProfileID)},
			{Action: authz.ActionEncrypt, Resource: authz.ProfileResource(command.DestinationProfileID)},
		}
	default:
		return nil
	}
}

func requiredScope(operation Operation) (string, error) {
	switch operation {
	case OperationEncrypt:
		return ScopeEncrypt, nil
	case OperationDecrypt:
		return ScopeDecrypt, nil
	case OperationRotate:
		return ScopeRotate, nil
	default:
		return "", invalidRequest("operation mode is invalid")
	}
}

func profileAccessError(actor caller.Caller) error {
	if actor.Kind() == caller.KindAnonymous {
		return notFound()
	}
	return forbidden()
}

func (p ProfileCapabilities) any() bool {
	return p.Encrypt || p.Decrypt || p.RotateSource || p.RotateDestination
}

func (p *PreparedOperation) Run(ctx context.Context) (string, error) {
	if p == nil || p.service == nil || p.lease == nil || p.context == nil || p.started == nil || p.source == nil {
		return "", notReady("prepared operation is not ready")
	}
	if !p.started.CompareAndSwap(false, true) {
		return "", notReady("prepared operation is not ready")
	}
	if err := leaseBoundContextError(ctx, p.lease); err != nil {
		return "", err
	}
	if !p.lease.holdForContext(ctx, p.service.admission) {
		if err := leaseBoundContextError(ctx, p.lease); err != nil {
			return "", err
		}
		return "", notReady("operation admission is not ready")
	}
	defer p.lease.releaseHold()
	executionContext, releaseExecutionContext := mergeCancellationContexts(p.context, ctx)
	defer releaseExecutionContext()
	if err := leaseMergedContextError(ctx, executionContext, p.lease); err != nil {
		return "", err
	}

	switch p.operation {
	case OperationEncrypt:
		result, err := p.source.Encrypt(executionContext, p.value)
		if contextErr := leaseMergedContextError(ctx, executionContext, p.lease); contextErr != nil {
			return "", contextErr
		}
		if err != nil {
			return "", operationFailed()
		}
		if validationErr := p.validateResult(ctx, executionContext, result, MaxVaultTextBytes); validationErr != nil {
			return "", validationErr
		}
		return result, nil
	case OperationDecrypt:
		result, err := p.source.Decrypt(executionContext, p.value)
		if contextErr := leaseMergedContextError(ctx, executionContext, p.lease); contextErr != nil {
			return "", contextErr
		}
		if err != nil {
			return "", operationFailed()
		}
		if validationErr := p.validateResult(ctx, executionContext, result, MaxPlaintextBytes); validationErr != nil {
			return "", validationErr
		}
		return result, nil
	case OperationRotate:
		if p.destination == nil {
			return "", notReady("prepared operation is not ready")
		}
		plaintext, err := p.source.Decrypt(executionContext, p.value)
		if contextErr := leaseMergedContextError(ctx, executionContext, p.lease); contextErr != nil {
			return "", contextErr
		}
		if err != nil {
			return "", operationFailed()
		}
		if validationErr := p.validateResult(ctx, executionContext, plaintext, MaxPlaintextBytes); validationErr != nil {
			return "", validationErr
		}
		result, err := p.destination.Encrypt(executionContext, plaintext)
		if contextErr := leaseMergedContextError(ctx, executionContext, p.lease); contextErr != nil {
			return "", contextErr
		}
		if err != nil {
			return "", operationFailed()
		}
		if validationErr := p.validateResult(ctx, executionContext, result, MaxVaultTextBytes); validationErr != nil {
			return "", validationErr
		}
		return result, nil
	default:
		return "", invalidRequest("operation mode is invalid")
	}
}

func (p *PreparedOperation) validateResult(invocation, execution context.Context, value string, limit int) error {
	valid := utf8.ValidString(value) && len(value) <= limit
	if contextErr := leaseMergedContextError(invocation, execution, p.lease); contextErr != nil {
		return contextErr
	}
	if !valid {
		return operationFailed()
	}
	return nil
}

func mergeCancellationContexts(origin, child context.Context) (context.Context, func()) {
	merged, cancel := context.WithCancelCause(origin)
	stopChild := context.AfterFunc(child, func() {
		cancel(context.Cause(child))
	})
	return merged, func() {
		stopChild()
		cancel(nil)
	}
}

func contextError(ctx context.Context) error {
	if err := contextCancellation(ctx); err != nil {
		return temporarilyUnavailable(err)
	}
	return nil
}

func leaseMergedContextError(invocation, merged context.Context, lease *Lease) error {
	if err := leaseBoundContextError(invocation, lease); err != nil {
		return err
	}
	return leaseBoundContextError(merged, lease)
}

func leaseBoundContextError(ctx context.Context, lease *Lease) error {
	if lease == nil {
		return contextError(ctx)
	}
	if err := lease.contextErr(ctx); err != nil {
		return temporarilyUnavailable(err)
	}
	return nil
}
