package generate

import (
	"crypto"
	"crypto/rand"
	"encoding/pem"
	"io"

	"golang.org/x/crypto/ssh"
)

type ageIdentityFactory func() (identity string, recipient string, err error)
type sshPrivateKeyMarshaler func(key crypto.PrivateKey, comment string) (*pem.Block, error)

// Generator owns the package's production cryptographic dependencies. New has
// no options so callers cannot supply seeds, randomness, or alternate formats.
type Generator struct {
	random        io.Reader
	ageIdentity   ageIdentityFactory
	marshalSSHKey sshPrivateKeyMarshaler
}

func New() *Generator {
	return &Generator{
		random:        rand.Reader,
		ageIdentity:   generateAgeIdentityStrings,
		marshalSSHKey: ssh.MarshalPrivateKey,
	}
}
