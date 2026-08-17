package generate

import (
	"strings"

	"filippo.io/age"
)

// GenerateAgeIdentity creates one native age X25519 identity. The recipient
// returned by the generation dependency must match the recipient rederived
// from the parsed private serialization.
func (g *Generator) GenerateAgeIdentity() (AgeIdentityResult, error) {
	if g == nil || g.ageIdentity == nil {
		return AgeIdentityResult{}, ErrGenerationFailed
	}

	identityText, generatedRecipient, err := g.ageIdentity()
	if err != nil || identityText == "" || generatedRecipient == "" || strings.ContainsAny(identityText, "\r\n") || strings.ContainsAny(generatedRecipient, "\r\n") {
		return AgeIdentityResult{}, ErrGenerationFailed
	}
	identity, err := age.ParseX25519Identity(identityText)
	if err != nil || identity.String() != identityText {
		return AgeIdentityResult{}, ErrGenerationFailed
	}
	recipient := identity.Recipient().String()
	if recipient != generatedRecipient {
		return AgeIdentityResult{}, ErrGenerationFailed
	}
	parsedRecipient, err := age.ParseX25519Recipient(recipient)
	if err != nil || parsedRecipient.String() != recipient {
		return AgeIdentityResult{}, ErrGenerationFailed
	}

	privateBytes := []byte(identityText + "\n")
	private := newPrivateMaterial(privateBytes)
	clear(privateBytes)
	return AgeIdentityResult{
		private:   private,
		recipient: recipient,
	}, nil
}

func generateAgeIdentityStrings() (identity string, recipient string, err error) {
	generated, err := age.GenerateX25519Identity()
	if err != nil {
		return "", "", err
	}
	return generated.String(), generated.Recipient().String(), nil
}
