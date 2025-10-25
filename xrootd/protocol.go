// Copyright ©2018 The go-hep Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xrootd // import "go-hep.org/x/hep/xrootd"

import (
	"context"

	"go-hep.org/x/hep/xrootd/xrdproto/protocol"
)

// Protocol obtains the protocol version number, type of the server and security information, such as:
// the security version, the security options, the security level, and the list of alterations
// needed to the specified predefined security level.
func (sess *cliSession) Protocol(ctx context.Context) (protocol.Response, error) {
	var resp protocol.Response
	
	// Use TLS-aware request if client has TLS config
	var req *protocol.Request
	if sess.client.tlsConfig != nil {
		// Send kXR_ableTLS and kXR_wantTLS flags to indicate TLS capability and request
		req = protocol.NewRequestWithTLS(sess.protocolVersion, true, true)
	} else {
		req = protocol.NewRequest(sess.protocolVersion, true)
	}
	
	_, err := sess.Send(ctx, &resp, req)
	// TODO: should we react somehow to redirection?
	return resp, err
}
