package panda

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"regexp"
	"testing"
)

// TestProfileAuthSign_SignsRealRequest is a regression test for a critical bug
// where ProfileAuth.Sign built a separate, hardcoded GET /api/v1/users/profile/
// request, signed THAT, and copied the resulting Authorization/Date headers
// onto the real outgoing request. That meant every real lion->panda call
// (e.g. POST /panda/container/create/) carried a signature bound to the
// wrong method/path and would be rejected by panda's signature verification.
//
// This test asserts the signature is bound to the REAL request's
// method + path, not the old hardcoded profile URL.
func TestProfileAuthSign_SignsRealRequest(t *testing.T) {
	const keyID = "test"
	const secret = "test-secret"

	req, err := http.NewRequest(http.MethodPost, "http://panda:9001/panda/container/create/", nil)
	if err != nil {
		t.Fatalf("failed to build request: %v", err)
	}

	auth := &ProfileAuth{KeyID: keyID, SecretID: secret}
	if err := auth.Sign(req); err != nil {
		t.Fatalf("Sign returned error: %v", err)
	}

	date := req.Header.Get("Date")
	if date == "" {
		t.Fatal("expected Date header to be set by Sign")
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		t.Fatal("expected Authorization header to be set by Sign")
	}

	sigParamRe := regexp.MustCompile(`signature="([^"]+)"`)
	m := sigParamRe.FindStringSubmatch(authHeader)
	if m == nil {
		t.Fatalf("could not find signature param in Authorization header: %s", authHeader)
	}
	gotSig, err := base64.StdEncoding.DecodeString(m[1])
	if err != nil {
		t.Fatalf("failed to base64-decode signature: %v", err)
	}

	// The regression this guards against: the old code always signed
	// "(request-target): get /api/v1/users/profile/", regardless of the
	// real request. Confirm the signing string used is bound to the real
	// method+path instead.
	expectedSigningString := fmt.Sprintf("(request-target): post /panda/container/create/\ndate: %s", date)
	badSigningString := "(request-target): get /api/v1/users/profile/\ndate: " + date

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(expectedSigningString))
	expectedSig := mac.Sum(nil)

	mac2 := hmac.New(sha256.New, []byte(secret))
	mac2.Write([]byte(badSigningString))
	badSig := mac2.Sum(nil)

	if hmac.Equal(gotSig, badSig) {
		t.Fatal("signature is bound to the old hardcoded profile URL, not the real request (regression!)")
	}
	if !hmac.Equal(gotSig, expectedSig) {
		t.Fatalf("signature does not match expected HMAC over the real request-target string %q", expectedSigningString)
	}
}
