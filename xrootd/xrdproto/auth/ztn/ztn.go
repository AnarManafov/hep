// Copyright ©2025 The go-hep Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package ztn contains the implementation for the "ztn" (Zero Trust Network) security provider.
// ZTN uses bearer tokens for authentication, typically SciTokens or JWT tokens.
package ztn // import "go-hep.org/x/hep/xrootd/xrdproto/auth/ztn"

import (
	"encoding/binary"
	"fmt"

	"go-hep.org/x/hep/xrootd/xrdproto/auth"
)

// Default is a ZTN security provider that will be configured with a bearer token.
// This is initialized with empty token and should be replaced with WithToken() or
// will auto-discover token from environment via discoverZTNToken() in session.go
var Default auth.Auther

func init() {
	// Initialize with empty token - will be set during session creation
	Default = &Auth{Token: ""}
}

// Auth implements the ZTN (Zero Trust Network) security provider.
// It uses bearer tokens for authentication.
type Auth struct {
	Token string
}

// Provider implements auth.Auther and returns the protocol name
func (*Auth) Provider() string {
	return "ztn"
}

// Type indicates ZTN (Zero Trust Network) authentication is used.
// The protocol identifier is "ztn" followed by version byte
var Type = [4]byte{'z', 't', 'n', 0}

// Request implements auth.Auther
// The credentials format matches XRootD's TokenResp structure:
// - TokenHdr (8 bytes): id="ztn", ver=0, opr='T', rsvd={0,0}
// - uint16_t len (2 bytes, big-endian): token length + 1 (for null terminator)
// - token bytes + null terminator
func (a *Auth) Request(params []string) (*auth.Request, error) {
	if a.Token == "" {
		return nil, fmt.Errorf("no bearer token available for ZTN authentication")
	}

	// Build TokenResp structure
	// TokenHdr: 8 bytes
	hdr := make([]byte, 8)
	copy(hdr[0:3], "ztn")     // id[4] = "ztn\0" (null already present from make)
	hdr[4] = 0                 // ver = 0
	hdr[5] = 'T'               // opr = 'T' (IsTkn)
	// hdr[6] and hdr[7] are rsvd = 0 (already set by make)

	// Token length (including null terminator)
	tokenLen := len(a.Token) + 1
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(tokenLen))

	// Build complete credentials: hdr + len + token + null
	credentials := string(hdr) + string(lenBytes) + a.Token + "\x00"

	return &auth.Request{
		Type:        Type,
		Credentials: credentials,
	}, nil
}

// WithToken creates a new ZTN Auth with the specified bearer token
func WithToken(token string) *Auth {
	return &Auth{Token: token}
}

var (
	_ auth.Auther = (*Auth)(nil)
)
