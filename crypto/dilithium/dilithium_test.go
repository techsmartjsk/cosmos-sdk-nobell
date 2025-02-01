package dilithium

import (
	"crypto/sha256"
	"testing"
	"github.com/stretchr/testify/assert"
)

func TestKeyring(t *testing.T) {
	kr := NewKeyring()
	name := "test-key"

	// Test key generation
	pk, err := kr.GenerateKey(name)
	assert.NoError(t, err)
	assert.NotNil(t, pk)

	// Test getting public key
	retrievedPk, err := kr.GetPublicKey(name)
	assert.NoError(t, err)
	assert.Equal(t, pk, retrievedPk)

	// Test signing a message
	message := []byte("Hello, world!")
	sig, err := kr.SignMessage(name, message)
	assert.NoError(t, err)
	assert.NotNil(t, sig)

	// Test signature verification
	valid := VerifySignature(pk, message, sig)
	assert.True(t, valid)
}

func TestSymmetricEncryption(t *testing.T) {
	secret := sha256.Sum256([]byte("supersecretpassword"))
	plaintext := []byte("Sensitive Data")

	// Test encryption
	ciphertext := EncryptSymmetric(plaintext, secret[:])
	assert.NotNil(t, ciphertext)
	assert.NotEqual(t, plaintext, ciphertext)

	// Test decryption
	decrypted, err := DecryptSymmetric(ciphertext, secret[:])
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decrypted)
}
