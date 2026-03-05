package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

var (
	ErrorInvalidCredentials = errors.New("invalid credentinals")
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

func LoadCredential(path string) (*Credential, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read credential file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	priv, ok := privKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("expected ed25519 private key, got %T", privKey)
	}

	return &Credential{
		signingKey: priv,
		PublicKey:  priv.Public().(ed25519.PublicKey),
	}, nil
}

func (c *Credential) Save(path string) error {
	privBytes, err := x509.MarshalPKCS8PrivateKey(c.signingKey)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}

	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
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
