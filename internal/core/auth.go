package core

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"hash"
)

const passwordIterations = 120000

func NewAdminCredential(username, password string) (AdminCredential, error) {
	if username == "" {
		return AdminCredential{}, errors.New("username is required")
	}
	if password == "" {
		return AdminCredential{}, errors.New("password is required")
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return AdminCredential{}, err
	}

	hash := pbkdf2Key([]byte(password), salt, passwordIterations, 32, sha256.New)
	return AdminCredential{
		Username:   username,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Hash:       base64.StdEncoding.EncodeToString(hash),
		Iterations: passwordIterations,
	}, nil
}

func CheckPassword(cred AdminCredential, username, password string) bool {
	if username != cred.Username || password == "" || cred.Salt == "" || cred.Hash == "" {
		return false
	}

	salt, err := base64.StdEncoding.DecodeString(cred.Salt)
	if err != nil {
		return false
	}
	expected, err := base64.StdEncoding.DecodeString(cred.Hash)
	if err != nil {
		return false
	}

	iterations := cred.Iterations
	if iterations <= 0 {
		iterations = passwordIterations
	}
	actual := pbkdf2Key([]byte(password), salt, iterations, len(expected), sha256.New)
	return subtle.ConstantTimeCompare(actual, expected) == 1
}

func randomSecret(length int) (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i := range buf {
		buf[i] = alphabet[int(buf[i])%len(alphabet)]
	}
	return string(buf), nil
}

func pbkdf2Key(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	blocks := (keyLen + hashLen - 1) / hashLen
	out := make([]byte, 0, blocks*hashLen)
	var counter [4]byte

	for block := 1; block <= blocks; block++ {
		counter[0] = byte(block >> 24)
		counter[1] = byte(block >> 16)
		counter[2] = byte(block >> 8)
		counter[3] = byte(block)

		prf.Reset()
		prf.Write(salt)
		prf.Write(counter[:])
		u := prf.Sum(nil)

		t := make([]byte, len(u))
		copy(t, u)
		for i := 1; i < iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}

		out = append(out, t...)
	}

	return out[:keyLen]
}
