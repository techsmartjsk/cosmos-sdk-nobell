package dilithium

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium"
	"golang.org/x/crypto/nacl/secretbox"
)

const (
	nonceLen  = 24
	secretLen = 32
)

var ErrCiphertextDecrypt = errors.New("ciphertext decryption failed")

type Keyring struct {
	keys map[string]dilithium.PrivateKey
}

// NewKeyring initializes a new keyring
func NewKeyring() *Keyring {
	return &Keyring{keys: make(map[string]dilithium.PrivateKey)}
}

// GenerateKey creates a new Dilithium key pair
func (kr *Keyring) GenerateKey(name string) ([]byte, error) {
	if _, exists := kr.keys[name]; exists {
		return nil, errors.New("key already exists")
	}
	pk, sk := dilithium.Mode3.GenerateKey(nil)
	kr.keys[name] = sk
	return pk.Bytes(), nil
}

// GetPublicKey retrieves the public key associated with a name
func (kr *Keyring) GetPublicKey(name string) ([]byte, error) {
	if sk, exists := kr.keys[name]; exists {
		return sk.Public().Bytes(), nil
	}
	return nil, errors.New("key not found")
}

// SignMessage signs a message using the private key
func (kr *Keyring) SignMessage(name string, message []byte) ([]byte, error) {
	if sk, exists := kr.keys[name]; exists {
		return sk.Sign(message), nil
	}
	return nil, errors.New("key not found")
}

// VerifySignature verifies a signature with a given public key
func VerifySignature(pkBytes, message, signature []byte) bool {
	pk, err := dilithium.Mode3.PublicKeyFromBytes(pkBytes)
	if err != nil {
		return false
	}
	return pk.Verify(message, signature)
}

// EncryptSymmetric encrypts data using a secret key
func EncryptSymmetric(plaintext, secret []byte) (ciphertext []byte) {
	if len(secret) != secretLen {
		panic(fmt.Sprintf("Secret must be 32 bytes long, got len %v", len(secret)))
	}
	nonce := randBytes(nonceLen)
	nonceArr := [nonceLen]byte{}
	copy(nonceArr[:], nonce)
	secretArr := [secretLen]byte{}
	copy(secretArr[:], secret)
	ciphertext = make([]byte, nonceLen+secretbox.Overhead+len(plaintext))
	copy(ciphertext, nonce)
	secretbox.Seal(ciphertext[nonceLen:nonceLen], plaintext, &nonceArr, &secretArr)
	return ciphertext
}

// DecryptSymmetric decrypts data using a secret key
func DecryptSymmetric(ciphertext, secret []byte) (plaintext []byte, err error) {
	if len(secret) != secretLen {
		panic(fmt.Sprintf("Secret must be 32 bytes long, got len %v", len(secret)))
	}
	if len(ciphertext) <= secretbox.Overhead+nonceLen {
		return nil, errors.New("ciphertext is too short")
	}
	nonce := ciphertext[:nonceLen]
	nonceArr := [nonceLen]byte{}
	copy(nonceArr[:], nonce)
	secretArr := [secretLen]byte{}
	copy(secretArr[:], secret)
	plaintext = make([]byte, len(ciphertext)-nonceLen-secretbox.Overhead)
	_, ok := secretbox.Open(plaintext[:0], ciphertext[nonceLen:], &nonceArr, &secretArr)
	if !ok {
		return nil, ErrCiphertextDecrypt
	}
	return plaintext, nil
}

// Generates random bytes
func randBytes(numBytes int) []byte {
	b := make([]byte, numBytes)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}