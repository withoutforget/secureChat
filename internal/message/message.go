package message

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

var (
	ErrorInitX25519         = errors.New("Cannot generate key for X25519")
	ErrorReadingPublicKey   = errors.New("Can't create public key from data")
	ErrorCreatingSharedKey  = errors.New("Can't create shared key")
	ErrorCreatingAESKey     = errors.New("Can't create AES key")
	ErrorCreatingBlock      = errors.New("Can't create Block")
	ErrorCreatingGCM        = errors.New("Can't create GCM")
	ErrorDecryptingMessage  = errors.New("Can't decrypt message")
	ErrorGeneratingSalt     = errors.New("Can't generate salt")
	ErrorInvalidMessage     = errors.New("Message is too short")
	ErrorCreatingNonce      = errors.New("Can't create nonce")
	ErrorCreatingSessionKey = errors.New("Can't create session key")
	ErrorMergingSalt        = errors.New("Can't merge salt due to different size")
)

type SecretMessage struct {
	privateKey *ecdh.PrivateKey
	salt       []byte

	SharedKey []byte

	writeAesKey []byte
	writeGcm    cipher.AEAD

	readAesKey []byte
	readGcm    cipher.AEAD
}

func NewSecretMessage() (*SecretMessage, error) {
	pKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, ErrorInitX25519
	}
	salt := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, salt)
	if err != nil {
		return nil, ErrorGeneratingSalt
	}
	return &SecretMessage{privateKey: pKey, salt: salt}, nil
}

func (sm *SecretMessage) GetPublicKey() []byte {
	return sm.privateKey.PublicKey().Bytes()
}

// чтобы корректно шифровать и расшифровывать необходимо определять
// кто инициировал общение. чтобы это делать гарантированно однозначно
// просто сравним два ключа. тот кто больше, тот и инициировал (условно)
func (sm *SecretMessage) determineInitiator(publicKey []byte) {
	if bytes.Compare(sm.privateKey.PublicKey().Bytes(), publicKey) > 0 {
		sm.writeAesKey, sm.readAesKey = sm.readAesKey, sm.writeAesKey
		sm.writeGcm, sm.readGcm = sm.readGcm, sm.writeGcm
	}
}

func (sm *SecretMessage) GetSalt() []byte {
	return bytes.Clone(sm.salt)
}

func (sm *SecretMessage) mergeSalt(salt []byte) error {
	if len(salt) != len(sm.salt) {
		return ErrorMergingSalt
	}
	for i := range len(sm.salt) {
		sm.salt[i] ^= salt[i]
	}
	return nil
}

func (sm *SecretMessage) setupSessionKey(sharedKey, bytesInfo []byte) (aesKey []byte, gcm cipher.AEAD, err error) {
	reader := hkdf.New(sha256.New, sharedKey, sm.salt, bytesInfo)
	aesKey = make([]byte, 32)

	_, err = io.ReadFull(reader, aesKey)
	if err != nil {
		return nil, nil, errors.Join(ErrorCreatingAESKey, err)

	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, nil, errors.Join(ErrorCreatingBlock, err)

	}

	gcm, err = cipher.NewGCM(block)
	if err != nil {
		return nil, nil, errors.Join(ErrorCreatingGCM, err)

	}

	return aesKey, gcm, nil
}
func (sm *SecretMessage) SetUpSharedKey(publicKey []byte, salt []byte) error {
	if err := sm.mergeSalt(salt); err != nil {
		return err
	}
	bobKey, err := ecdh.X25519().NewPublicKey(publicKey)
	if err != nil {
		return errors.Join(ErrorReadingPublicKey, err)
	}

	shared, err := sm.privateKey.ECDH(bobKey)
	if err != nil {
		return errors.Join(ErrorCreatingSharedKey, err)

	}

	aesKey, gcm, err := sm.setupSessionKey(shared, []byte("a2b"))
	if err != nil {
		return errors.Join(ErrorCreatingSessionKey, err)
	}
	sm.writeAesKey = aesKey
	sm.writeGcm = gcm

	aesKey, gcm, err = sm.setupSessionKey(shared, []byte("b2a"))
	if err != nil {
		return errors.Join(ErrorCreatingSessionKey, err)
	}
	sm.readAesKey = aesKey
	sm.readGcm = gcm

	sm.determineInitiator(publicKey)
	return nil
}

func (sm *SecretMessage) GenerateMessage(payload []byte) ([]byte, error) {
	nonce := make([]byte, sm.writeGcm.NonceSize())
	_, err := io.ReadFull(rand.Reader, nonce)

	if err != nil {
		return nil, errors.Join(ErrorCreatingNonce, err)
	}

	encrypted := sm.writeGcm.Seal(nonce, nonce, payload, nil)
	return encrypted, nil
}

func (sm *SecretMessage) ReadMessage(payload []byte) ([]byte, error) {
	if len(payload) < sm.readGcm.NonceSize() {
		return nil, ErrorInvalidMessage
	}
	nonce, ct := payload[:sm.readGcm.NonceSize()], payload[sm.readGcm.NonceSize():]

	decrypted, err := sm.readGcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errors.Join(ErrorDecryptingMessage, err)
	}

	return decrypted, nil
}
func main() {
	client1, err := NewSecretMessage()
	if err != nil {
		panic(err)
	}

	client2, err := NewSecretMessage()
	if err != nil {
		panic(err)
	}

	c1Salt, c2Salt := client1.GetSalt(), client2.GetSalt()

	err = client1.SetUpSharedKey(client2.GetPublicKey(), c2Salt)
	if err != nil {
		panic(err)
	}
	err = client2.SetUpSharedKey(client1.GetPublicKey(), c1Salt)
	if err != nil {
		panic(err)
	}

	enc, err := client1.GenerateMessage([]byte("Hello world from me!"))
	if err != nil {
		panic(err)
	}
	dec, err := client2.ReadMessage(enc)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(dec))
}
