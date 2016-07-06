package tlsconsul

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
)

const nonceSize = 24
const valuePrefix = "caddy-tlsconsul"

func generateNonce() (*[nonceSize]byte, error) {
	nonce := new([nonceSize]byte)
	_, err := io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, err
	}
	return nonce, nil
}

func (t *tlsConsulStorage) encrypt(byts []byte) ([]byte, error) {
	// No key? No encrypt
	if len(t.aesKey) == 0 {
		return byts, nil
	}

	c, err := aes.NewCipher(t.aesKey)
	if err != nil {
		return nil, fmt.Errorf("Unable to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return nil, fmt.Errorf("Unable to create GCM cipher: %v", err)
	}

	nonce, err := generateNonce()
	if err != nil {
		return nil, fmt.Errorf("Unable to generate nonce: %v", err)
	}

	return gcm.Seal(nil, nonce, byts, nil), nil
}

func (t *tlsConsulStorage) toBytes(iface interface{}) ([]byte, error) {
	// JSON marshal, then encrypt if key is there
	byts, err := json.Marshal(iface)
	if err != nil {
		return nil, fmt.Errorf("Unable to marshal: %v", err)
	}

	// Prefix with simple prefix and then encrypt
	byts = append([]byte(valuePrefix), byts)
	return t.encrypt(byts)
}

func (t *tlsConsulStorage) decrypt(byts []byte) ([]byte, error) {
	// No key? No decrypt
	if len(t.aesKey) == 0 {
		return byts, nil
	}
	if len(byts) < aes.BlockSize {
		return nil, fmt.Errorf("Invalid contents")
	}
	block, err := aes.NewCipher(t.aesKey)
	if err != nil {
		return nil, fmt.Errorf("Unable to create AES cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("Unable to create GCM cipher: %v", err)
	}

	nonce := make([]byte, nonceSize)
	copy(nonce, byts)

	out, err := gcm.Open(nil, nonce, byts[nonceSize:], nil)
	if err != nil {
		return nil, fmt.Errorf("Decryption failure: %v", err)
	}

	return out
}

func (t *tlsConsulStorage) fromBytes(byts []byte, iface interface{}) error {
	// We have to decrypt if there is an AES key and then JSON unmarshal
	byts, err := t.decrypt(byts)
	if err != nil {
		return err
	}
	// Simple sanity check of the beginning of the byte array just to check
	if len(byts) < len(valuePrefix) || string(byts[:len(valuePrefix)]) != valuePrefix {
		return fmt.Errorf("Invalid data format")
	}
	// Now just json unmarshal
	if err := json.Unmarshal(byts[valuePrefix:], iface); err != nil {
		return fmt.Errorf("Unable to unmarshal result: %v", err)
	}
	return nil
}
