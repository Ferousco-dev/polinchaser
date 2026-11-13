// Package github implements the GitHub App integration: app JWTs,
// short-lived installation tokens, webhook signature verification and the
// REST calls PolinChaser needs. Installation tokens are cached in memory
// only and never persisted.
package github

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ParsePrivateKey accepts PKCS#1 or PKCS#8 RSA PEM (GitHub issues PKCS#1).
func ParsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, errors.New("github: private key is not PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, errors.New("github: unsupported private key format")
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("github: private key is not RSA")
	}
	return rk, nil
}

// AppJWT builds the RS256 JWT used to authenticate as the app. iat is
// backdated 60s for clock drift; exp is 9 minutes (GitHub max is 10).
func AppJWT(appID int64, key *rsa.PrivateKey, now time.Time) (string, error) {
	enc := base64.RawURLEncoding
	hdr, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	claims, _ := json.Marshal(map[string]any{
		"iat": now.Add(-60 * time.Second).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": appID,
	})
	signing := enc.EncodeToString(hdr) + "." + enc.EncodeToString(claims)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", fmt.Errorf("github: sign jwt: %w", err)
	}
	return signing + "." + enc.EncodeToString(sig), nil
}

// VerifySignature checks X-Hub-Signature-256 against the RAW request body
// using a constant-time comparison. An empty secret never verifies.
func VerifySignature(secret string, body []byte, header string) bool {
	if secret == "" {
		return false
	}
	hexSig, ok := strings.CutPrefix(header, "sha256=")
	if !ok {
		return false
	}
	got, err := hex.DecodeString(hexSig)
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}
