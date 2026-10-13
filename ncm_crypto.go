package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
)

const (
	ncmIV        = "0102030405060708"
	ncmPresetKey = "0CoJUm6Qyw8W8jud"
	ncmEapiKey   = "e82ckenh8dichen8"
	ncmBase62    = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

const ncmPublicKeyPEM = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgtQn2JZ34ZC28NWYpAUd98iZ3
7BUrX/aKzmFbt7clFSs6sXqHauqKWqdtLkF2KexO40H1YTX8z2lSgBBOAxLsvakl
V8k4cBFK9snQXE9/DDaFt6Rr7iVZMldczhC0JNgTz+SHXT6CBHuX3e9SdB1Ua44o
ncaTWz7OBGLbCiK45wIDAQAB
-----END PUBLIC KEY-----`

// ncmRSAPublicKey is the parsed public key used by the weapi encryption
var ncmRSAPublicKey *rsa.PublicKey

// ncmRandomBase62 returns n random characters from the base62 alphabet
func ncmRandomBase62(n int) string {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		panic(err)
	}
	out := make([]byte, n)
	for i := range raw {
		out[i] = ncmBase62[int(raw[i])%62]
	}
	return string(out)
}

// aesCBCEncryptBase64 encrypts plain with AES-128-CBC and returns the base64 ciphertext
func aesCBCEncryptBase64(plain, key, iv []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	padded := pkcs7Pad(plain, aes.BlockSize)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return base64.StdEncoding.EncodeToString(out), nil
}

// aesECBEncryptHexUpper encrypts plain with AES-128-ECB and returns the uppercase hex ciphertext
func aesECBEncryptHexUpper(plain, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	padded := pkcs7Pad(plain, aes.BlockSize)
	out := make([]byte, len(padded))
	newECB(block).Encrypt(out, padded)
	return hex.EncodeToString(out), nil
}

// aesECBDecryptHex decrypts an uppercase hex ciphertext with AES-128-ECB
func aesECBDecryptHex(hexText string, key []byte) ([]byte, error) {
	data, err := hex.DecodeString(hexText)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("invalid ciphertext length")
	}
	out := make([]byte, len(data))
	newECB(block).Decrypt(out, data)
	return unpad(out), nil
}

// pkcs7Pad appends PKCS#7 padding to reach a multiple of the block size
func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

// rsaEncryptNoPad performs textbook RSA encryption and returns a 128 byte hex string
func rsaEncryptNoPad(plain []byte) (string, error) {
	if ncmRSAPublicKey == nil {
		block, _ := pem.Decode([]byte(ncmPublicKeyPEM))
		if block == nil {
			return "", fmt.Errorf("parse public key pem")
		}
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return "", err
		}
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return "", fmt.Errorf("unexpected public key type")
		}
		ncmRSAPublicKey = key
	}
	padded := make([]byte, 128)
	copy(padded[128-len(plain):], plain)
	m := new(big.Int).SetBytes(padded)
	c := new(big.Int).Exp(m, big.NewInt(int64(ncmRSAPublicKey.E)), ncmRSAPublicKey.N)
	out := c.Bytes()
	if len(out) < 128 {
		left := make([]byte, 128-len(out))
		out = append(left, out...)
	}
	return hex.EncodeToString(out), nil
}

// weapiEncrypt encrypts request JSON with the two layer AES-CBC plus RSA weapi scheme
func weapiEncrypt(dataJSON string) (string, string, error) {
	secret := ncmRandomBase62(16)
	layer1, err := aesCBCEncryptBase64([]byte(dataJSON), []byte(ncmPresetKey), []byte(ncmIV))
	if err != nil {
		return "", "", err
	}
	params, err := aesCBCEncryptBase64([]byte(layer1), []byte(secret), []byte(ncmIV))
	if err != nil {
		return "", "", err
	}
	reversed := []byte(secret)
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	encSecKey, err := rsaEncryptNoPad(reversed)
	if err != nil {
		return "", "", err
	}
	return params, encSecKey, nil
}

// eapiEncrypt encrypts request JSON with the eapi AES-ECB scheme for the given uri
func eapiEncrypt(uri, dataJSON string) (string, error) {
	msg := "nobody" + uri + "use" + dataJSON + "md5forencrypt"
	sum := md5.Sum([]byte(msg))
	digest := hex.EncodeToString(sum[:])
	payload := uri + "-36cd479b6b5-" + dataJSON + "-36cd479b6b5-" + digest
	return aesECBEncryptHexUpper([]byte(payload), []byte(ncmEapiKey))
}

// eapiDecryptJSON decrypts an encrypted eapi response body into plain JSON bytes
func eapiDecryptJSON(hexText string) ([]byte, error) {
	data, err := aesECBDecryptHex(hexText, []byte(ncmEapiKey))
	if err != nil {
		return nil, err
	}
	return bytes.TrimRight(data, "\x00"), nil
}
