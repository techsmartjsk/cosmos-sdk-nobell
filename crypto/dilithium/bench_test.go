package dilithium

import (
	"crypto/rand"
	"testing"
)

func BenchmarkGenerateKey(b *testing.B) {
	kr := NewKeyring()
	for i := 0; i < b.N; i++ {
		_, _ = kr.GenerateKey("testKey")
	}
}

func BenchmarkSignMessage(b *testing.B) {
	kr := NewKeyring()
	pk, _ := kr.GenerateKey("testKey")
	message := []byte("Benchmarking Dilithium Signing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = kr.SignMessage("testKey", message)
	}
}

func BenchmarkVerifySignature(b *testing.B) {
	kr := NewKeyring()
	pk, _ := kr.GenerateKey("testKey")
	message := []byte("Benchmarking Dilithium Verification")
	signature, _ := kr.SignMessage("testKey", message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = VerifySignature(pk, message, signature)
	}
}

func BenchmarkEncryptSymmetric(b *testing.B) {
	secret := randBytes(secretLen)
	plaintext := []byte("Benchmarking Encryption")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EncryptSymmetric(plaintext, secret)
	}
}

func BenchmarkDecryptSymmetric(b *testing.B) {
	secret := randBytes(secretLen)
	plaintext := []byte("Benchmarking Decryption")
	ciphertext := EncryptSymmetric(plaintext, secret)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecryptSymmetric(ciphertext, secret)
	}
}
