package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
)

var (
	ErrorInvalidCredentials = errors.New("Invalid credentinals")
)

type Credential struct {
	signingKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

func GenerateCredential() (*Credential, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Credential{signingKey: priv, PublicKey: pub}, nil
}

func (c *Credential) Sign(data []byte) []byte {
	return ed25519.Sign(c.signingKey, data)
}

func (c *Credential) String() string {
	return base64.StdEncoding.EncodeToString(c.PublicKey)
}

func ParseCredential(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func Verify(data, signature, trustedKey []byte) error {
	if !ed25519.Verify(trustedKey, data, signature) {
		return ErrorInvalidCredentials
	}
	return nil
}
