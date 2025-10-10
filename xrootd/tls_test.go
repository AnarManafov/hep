// Copyright ©2025 The go-hep Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xrootd

import (
	"crypto/tls"
	"os"
	"testing"

	"go-hep.org/x/hep/xrootd/xrdproto/auth"
)

func TestWithTLS(t *testing.T) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	client := &Client{
		cancel:          func() {},
		auths:           make(map[string]auth.Auther),
		username:        "test",
		sessions:        make(map[string]*cliSession),
		maxRedirections: 10,
	}

	opt := WithTLS(tlsConfig)
	if err := opt(client); err != nil {
		t.Fatalf("WithTLS failed: %v", err)
	}

	if client.tlsConfig == nil {
		t.Fatal("TLS config not set")
	}

	if client.tlsConfig.InsecureSkipVerify != true {
		t.Fatal("TLS config not preserved")
	}
}

func TestDiscoverZTNToken(t *testing.T) {
	// Test 1: BEARER_TOKEN environment variable
	expectedToken := "test-token-12345"
	os.Setenv("BEARER_TOKEN", expectedToken)
	defer os.Unsetenv("BEARER_TOKEN")

	token := discoverZTNToken()
	if token != expectedToken {
		t.Fatalf("Expected token %q, got %q", expectedToken, token)
	}

	// Test 2: No token (should return empty string)
	os.Unsetenv("BEARER_TOKEN")
	token = discoverZTNToken()
	if token != "" {
		t.Fatalf("Expected empty token, got %q", token)
	}

	// Test 3: BEARER_TOKEN_FILE
	tmpFile, err := os.CreateTemp("", "bearer_token_*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	fileToken := "file-token-67890"
	if _, err := tmpFile.WriteString(fileToken + "\n"); err != nil {
		t.Fatalf("Failed to write token file: %v", err)
	}
	tmpFile.Close()

	os.Setenv("BEARER_TOKEN_FILE", tmpFile.Name())
	defer os.Unsetenv("BEARER_TOKEN_FILE")

	token = discoverZTNToken()
	if token != fileToken {
		t.Fatalf("Expected token %q from file, got %q", fileToken, token)
	}
}
