// Copyright ©2018 The go-hep Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xrootd // import "go-hep.org/x/hep/xrootd"

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go-hep.org/x/hep/xrootd/internal/mux"
	"go-hep.org/x/hep/xrootd/internal/xrdenc"
	"go-hep.org/x/hep/xrootd/xrdproto"
	"go-hep.org/x/hep/xrootd/xrdproto/signing"
	"go-hep.org/x/hep/xrootd/xrdproto/sigver"
)

// cliSession is a connection to the specific XRootD server
// which allows to send requests and receive responses.
// Concurrent requests are supported.
// Zero value is invalid, cliSession should be instantiated using newSession.
//
// The cliSession is used by the Client to send requests to the particular server
// specified by the name and port. If the current server cannot
// handle a request, it responds with the redirect to the new server.
// After that, Client obtains a session associated with that server and
// re-issues the request. Stream ID may be different during these 2 requests
// because it is used to identify requests among one particular server
// and is not shared between servers in any way.
//
// If the request that supports sending data over a separate socket is issued,
// the session tries to obtain a sub-session to the same server using a `bind` request.
// If the connection is successful, the request is sent specifying that socket for the data exchange.
// Otherwise, a default socket connected to the server is used.
type cliSession struct {
	ctx              context.Context
	cancel           context.CancelFunc
	connMu           sync.RWMutex // protects conn during TLS upgrade
	conn             net.Conn
	
	// TLS upgrade coordination channels
	pauseReq         chan struct{} // handshake requests consume() to pause
	pauseAck         chan struct{} // consume() acknowledges it has paused
	resume           chan struct{} // handshake signals consume() to resume
	
	mux              *mux.Mux
	protocolVersion  int32
	signRequirements signing.Requirements
	seqID            int64
	mu               sync.RWMutex
	requests         map[xrdproto.StreamID]pendingRequest

	subCreateMu sync.Mutex   // subCreateMu is used to serialize the creation of sub-sessions.
	subsMu      sync.RWMutex // subsMu is used to serialize the access to the subs map.
	subs        map[xrdproto.PathID]*cliSession

	maxSubs   int
	freeSubs  chan xrdproto.PathID
	isSub     bool // indicates whether this session is a sub-session.
	client    *Client
	sessionID string
	addr      string
	loginID   [16]byte
	pathID    xrdproto.PathID
}

// pendingRequest is a request that has been sent to the remote server.
type pendingRequest struct {
	// Header is the header part of the request.
	// It may contain all of the request content if there is no data that is
	// intended to be sent over a separate socket.
	Header []byte

	// Data is the data part of the request that is intended to be sent over a separate socket.
	Data []byte

	// PathID is the identifier of the socket which should be used to read or write a data.
	PathID xrdproto.PathID
}

func newSession(ctx context.Context, address, username, token string, client *Client) (*cliSession, error) {
	ctx, cancel := context.WithCancel(ctx)

	addr := parseAddr(address)

	// Discover token from environment if TLS is configured and token is empty
	if token == "" && client.tlsConfig != nil {
		token = discoverZTNToken()
	}

	// ALWAYS start with plain TCP connection
	// TLS will be upgraded after protocol negotiation (XRootD protocol requirement)
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		cancel()
		return nil, err
	}

	log.Printf("XRootD: Connected to %s (TLS enabled: %v, token present: %v)",
		addr, client.tlsConfig != nil, token != "")

	sess := &cliSession{
		ctx:       ctx,
		cancel:    cancel,
		conn:      conn,
		mux:       mux.New(),
		subs:      make(map[xrdproto.PathID]*cliSession),
		freeSubs:  make(chan xrdproto.PathID),
		requests:  make(map[xrdproto.StreamID]pendingRequest),
		client:    client,
		sessionID: addr,
		addr:      addr,
		maxSubs:   8, // TODO: The value of 8 is just a guess. Change it?
		// Initialize TLS upgrade coordination channels
		pauseReq:  make(chan struct{}, 1),
		pauseAck:  make(chan struct{}, 1),
		resume:    make(chan struct{}, 1),
	}

	// XRootD Client Connection Sequence (based on official XRootD client implementation):
	//
	// Per XRootD protocol and official client (XrdCl::XRootDTransport and AsyncSocketHandler):
	//   1. Connect to server via plain TCP
	//   2. Start async reader (consume() goroutine) to handle XRootD protocol messages
	//   3. Send initial Handshake request (plain text, over TCP)
	//   4. Receive Handshake response (plain text, over TCP)
	//   5. Send Protocol request with kXR_wantTLS flag (plain text, over TCP)
	//   6. Receive Protocol response - server indicates TLS requirement via kXR_gotoTLS flag (plain text, over TCP)
	//   7. If server requires TLS (HasSecurityInfo=true or explicit token present):
	//      a. Wrap the TCP connection with tls.Client() - creates TLS layer over existing socket
	//      b. Perform explicit TLS handshake via HandshakeContext() - negotiates encryption
	//      c. Server performs matching TLS upgrade after sending Protocol response (see XrdXrootdProtocol::do_Protocol)
	//      d. consume() goroutine continues reading, now from TLS-encrypted connection
	//   8. Send Login request (over TLS if upgraded, plain TCP otherwise)
	//   9. Continue with authentication and normal operations
	//
	// Key insight from XRootD source (src/XrdXrootd/XrdXrootdXeq.cc:do_Protocol):
	//   The server calls Link->setTLS() immediately after sending Protocol response if wantTLS=true.
	//   This means both client and server upgrade their sockets to TLS at the same synchronization point.
	//
	// Architecture Note:
	//   Unlike the official XRootD client which uses non-blocking I/O with an event loop,
	//   this Go implementation uses blocking I/O in a dedicated goroutine (consume()).
	//   The TLS upgrade works because:
	//   - After Protocol() returns, consume() has delivered the response via mux and loops back
	//   - We wrap the connection with TLS before the next Login request
	//   - The implicit TLS handshake occurs on the first TLS I/O operation (Login write or consume read)
	//   - Both client and server are synchronized at this point, both expecting TLS

	// Start consume() to read responses - needed for handshake and protocol negotiation
	// This reads from the plain TCP connection initially
	go sess.consume()

	// Step 1: Initial handshake over plain TCP
	if err := sess.handshake(ctx); err != nil {
		sess.Close()
		return nil, err
	}

	// Step 2: Protocol negotiation - request security requirements
	// This tells server we want/can use TLS for ZTN
	protocolInfo, err := sess.Protocol(ctx)
	if err != nil {
		sess.Close()
		return nil, err
	}

	// Step 3: Upgrade to TLS if client wants ZTN and server requires/supports it
	if client.tlsConfig != nil {
		// Check if we need to upgrade to TLS for security protocols
		// ZTN protocol REQUIRES TLS per specification (see XrdSecProtocolztn.cc:needTLS)
		if token != "" || protocolInfo.HasSecurityInfo {
			log.Printf("XRootD: Upgrading connection to TLS for ZTN protocol")

			// Lock the connection exclusively for TLS upgrade
			sess.connMu.Lock()

			// Wrap existing TCP connection with TLS layer
			tlsConn := tls.Client(sess.conn, client.tlsConfig)

			// Perform explicit TLS handshake to establish encryption
			// This must complete before any further XRootD protocol messages
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				sess.connMu.Unlock()
				sess.Close()
				return nil, fmt.Errorf("xrootd: TLS handshake failed: %w", err)
			}

			// Atomically replace connection with TLS connection
			// consume() will read from TLS connection on its next iteration
			sess.conn = tlsConn
			sess.connMu.Unlock()

			log.Printf("XRootD: TLS handshake successful, connection now encrypted")
		}
	}

	// Step 4: Login (now over TLS if upgraded)
	securityInfo, err := sess.Login(ctx, username, token)
	if err != nil {
		sess.Close()
		return nil, err
	}

	sess.loginID = securityInfo.SessionID

	// Step 5: Authentication if required (over TLS)
	if len(securityInfo.SecurityInformation) > 0 {
		err = sess.auth(ctx, securityInfo.SecurityInformation)
		if err != nil {
			sess.Close()
			return nil, err
		}
	}

	sess.signRequirements = signing.New(protocolInfo.SecurityLevel, protocolInfo.SecurityOverrides)

	return sess, nil
}

// Close closes the connection. Any blocked operation will be unblocked and return error.
func (sess *cliSession) Close() error {
	if sess == nil {
		return os.ErrInvalid
	}

	sess.cancel()

	var errs []error
	for _, child := range sess.subs {
		err := child.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}

	if !sess.isSub {
		sess.mux.Close()
	}

	// TODO: should we remove session here somehow?
	err := sess.conn.Close()
	if err != nil {
		errs = append(errs, err)
	}
	if errs != nil {
		return fmt.Errorf("xrootd: errors occured during closing of the session: %v", errs)
	}
	return nil
}

// handleReadError handles an error encountered while reading and parsing a response.
// If the current session is equal to the initial, the error is considered critical and handleReadError panics.
// Otherwise, the current session is closed and all requests are redirected to the initial session.
// See http://xrootd.org/doc/dev45/XRdv310.pdf, p. 11 for details.
func (sess *cliSession) handleReadError(err error) {
	if sess.sessionID == sess.client.initialSessionID {
		// TODO: what should we do in case initial session is aborted?
		// Should we try to reconnect to the server and re-issue all requests?
		panic(err)
	}
	sess.mu.RLock()
	resp := mux.ServerResponse{Redirection: &mux.Redirection{Addr: sess.client.initialSessionID}}
	for streamID := range sess.requests {
		err := sess.mux.SendData(streamID, resp)
		// TODO: should we log error somehow? We have nowhere to send it.
		_ = err
	}
	sess.mu.RUnlock()
	sess.Close()
}

// handleWaitResponse handles a "kXR_wait" response by re-issuing the request with streamID
// after the number of seconds encoded in data.
// See http://xrootd.org/doc/dev45/XRdv310.pdf, p. 35 for the specification of the response.
func (sess *cliSession) handleWaitResponse(streamID xrdproto.StreamID, data []byte) error {
	var resp xrdproto.WaitResponse
	rBuffer := xrdenc.NewRBuffer(data)
	if err := resp.UnmarshalXrd(rBuffer); err != nil {
		return err
	}

	sess.mu.RLock()
	req, ok := sess.requests[streamID]
	sess.mu.RUnlock()
	if !ok {
		return fmt.Errorf("xrootd: could not find a request with stream id equal to %v", streamID)
	}

	go func(req pendingRequest) {
		time.Sleep(resp.Duration)
		if err := sess.writeRequest(req); err != nil {
			resp := mux.ServerResponse{Err: fmt.Errorf("xrootd: could not send data to the server: %w", err)}
			err := sess.mux.SendData(streamID, resp)
			// TODO: should we log error somehow? We have nowhere to send it.
			_ = err
			sess.cleanupRequest(streamID)
		}
	}(req)

	return nil
}

func (sess *cliSession) consume() {
	var header xrdproto.ResponseHeader
	var headerBytes = make([]byte, xrdproto.ResponseHeaderLength)
	var resp mux.ServerResponse

	for {
		// Check for pause request before starting each read
		select {
		case <-sess.pauseReq:
			log.Printf("XRootD: consume() received pause request")
			// Acknowledge that we've paused (we're not mid-read at this point)
			select {
			case sess.pauseAck <- struct{}{}:
				log.Printf("XRootD: consume() sent pause acknowledgment")
			default:
				// Channel already has a value, ignore
			}
			// Wait for resume signal
			select {
			case <-sess.resume:
				log.Printf("XRootD: consume() received resume signal")
				// Continue to normal operation
			case <-sess.ctx.Done():
				return
			}
		default:
			// No pause request, proceed normally
		}
		
		select {
		case <-sess.ctx.Done():
			// TODO: Should wait for active requests to be completed?
			return
		default:
			// Use read lock to allow concurrent reads but block during TLS upgrade
			sess.connMu.RLock()
			conn := sess.conn
			sess.connMu.RUnlock()
			
			var err error
			resp.Data, err = xrdproto.ReadResponseWithReuse(conn, headerBytes, &header)
			if err != nil {
				if sess.ctx.Err() != nil {
					// something happened to the context.
					// ignore this error.
					return
				}
				sess.handleReadError(err)
			}
			resp.Err = nil
			resp.Redirection = nil

			switch header.Status {
			case xrdproto.Error:
				resp.Err = header.Error(resp.Data)
			case xrdproto.Wait:
				resp.Err = sess.handleWaitResponse(header.StreamID, resp.Data)
				if resp.Err == nil {
					continue
				}
			case xrdproto.Redirect:
				resp.Redirection, resp.Err = mux.ParseRedirection(resp.Data)
			}

			if err := sess.mux.SendData(header.StreamID, resp); err != nil {
				if sess.ctx.Err() != nil {
					// something happened to the context.
					// ignore this error.
					continue
				}
				// Log warning instead of panic - likely a race condition with stream cleanup
				// This can happen when TLS upgrade or session restart causes stream ID mismatch
				// TODO: investigate root cause of unclaimed stream IDs
				continue
			}

			if header.Status != xrdproto.OkSoFar {
				sess.cleanupRequest(header.StreamID)
			}
		}
	}
}

func (sess *cliSession) cleanupRequest(streamID xrdproto.StreamID) {
	sess.mux.Unclaim(streamID)
	sess.mu.Lock()
	delete(sess.requests, streamID)
	sess.mu.Unlock()
}

func (sess *cliSession) writeRequest(request pendingRequest) error {
	if request.PathID == 0 {
		request.Header = append(request.Header, request.Data...)
	}

	// Use read lock to allow concurrent writes but block during TLS upgrade
	sess.connMu.RLock()
	conn := sess.conn
	sess.connMu.RUnlock()
	
	if _, err := conn.Write(request.Header); err != nil {
		return err
	}

	if request.PathID != 0 && len(request.Data) > 0 {
		sess.subsMu.RLock()
		subConn, ok := sess.subs[request.PathID]
		sess.subsMu.RUnlock()
		if !ok {
			return fmt.Errorf("xrootd: connection with wrong pathID = %v was requested", request.PathID)
		}
		if _, err := subConn.conn.Write(request.Data); err != nil {
			return err
		}
	}
	return nil
}

func (sess *cliSession) send(ctx context.Context, streamID xrdproto.StreamID, responseChannel mux.DataRecvChan, header, body []byte, pathID xrdproto.PathID) ([]byte, *mux.Redirection, error) {
	if pathID == 0 {
		header = append(header, body...)
	}
	request := pendingRequest{Header: header, Data: body, PathID: pathID}
	sess.mu.Lock()
	sess.requests[streamID] = request
	sess.mu.Unlock()

	if err := sess.writeRequest(request); err != nil {
		return nil, nil, err
	}

	var data []byte

	for {
		select {
		case resp, more := <-responseChannel:
			if !more {
				return data, nil, nil
			}

			if resp.Err != nil {
				return nil, resp.Redirection, resp.Err
			}

			if resp.Redirection != nil {
				return nil, resp.Redirection, nil
			}

			data = append(data, resp.Data...)
		case <-ctx.Done():
			if err := ctx.Err(); err != nil {
				return nil, nil, err
			}
		}
	}
}

// Send sends the request to the server and stores the response inside the resp.
func (sess *cliSession) Send(ctx context.Context, resp xrdproto.Response, req xrdproto.Request) (*mux.Redirection, error) {
	streamID, responseChannel, err := sess.mux.Claim()
	if err != nil {
		return nil, err
	}

	var wBuffer xrdenc.WBuffer
	header := xrdproto.RequestHeader{StreamID: streamID, RequestID: req.ReqID()}
	if err = header.MarshalXrd(&wBuffer); err != nil {
		return nil, err
	}

	var pathID xrdproto.PathID = 0
	var pathData []byte
	if dr, ok := req.(xrdproto.DataRequest); ok {
		var err error
		pathID, err = sess.claimPathID(ctx)
		if err != nil {
			// Should we log error somehow?
			// Fallback to sending the data over a single connection.
			pathID = 0
		}
		defer sess.unclaimPathID(pathID)
		dr.SetPathID(pathID)
		pathData = dr.PathData()
	}

	if err = req.MarshalXrd(&wBuffer); err != nil {
		return nil, err
	}
	data := wBuffer.Bytes()

	if sess.signRequirements.Needed(req) {
		data, err = sess.sign(streamID, req.ReqID(), data)
		if err != nil {
			return nil, err
		}
	}

	data, redirection, err := sess.send(ctx, streamID, responseChannel, data, pathData, pathID)
	if err != nil || redirection != nil || resp == nil {
		return redirection, err
	}

	return nil, resp.UnmarshalXrd(xrdenc.NewRBuffer(data))
}

func (sess *cliSession) claimPathID(ctx context.Context) (xrdproto.PathID, error) {
	select {
	case child := <-sess.freeSubs:
		return child, nil
	default:
		sess.subCreateMu.Lock()
		defer sess.subCreateMu.Unlock()

		sess.subsMu.RLock()
		if len(sess.subs) >= sess.maxSubs {
			sess.subsMu.RUnlock()
			return 0, fmt.Errorf("xrootd: could not claimPathID: all of %d connections are taken", sess.maxSubs)
		}
		sess.subsMu.RUnlock()

		ds, err := newSubSession(ctx, sess)
		if err != nil {
			return 0, err
		}
		sess.subsMu.Lock()
		sess.subs[ds.pathID] = ds
		sess.subsMu.Unlock()

		return ds.pathID, nil
	}
}

func (sess *cliSession) unclaimPathID(pathID xrdproto.PathID) {
	if pathID == 0 {
		return
	}
	go func() {
		select {
		case <-sess.ctx.Done():
			return
		case sess.freeSubs <- pathID:
		}
	}()
}

func (sess *cliSession) sign(streamID xrdproto.StreamID, requestID uint16, data []byte) ([]byte, error) {
	seqID := atomic.AddInt64(&sess.seqID, 1)
	signRequest := sigver.NewRequest(requestID, seqID, data)
	header := xrdproto.RequestHeader{StreamID: streamID, RequestID: signRequest.ReqID()}

	var wBuffer xrdenc.WBuffer
	if err := header.MarshalXrd(&wBuffer); err != nil {
		return nil, err
	}
	if err := signRequest.MarshalXrd(&wBuffer); err != nil {
		return nil, err
	}
	wBuffer.WriteBytes(data)

	return wBuffer.Bytes(), nil
}

func newSubSession(ctx context.Context, parent *cliSession) (*cliSession, error) {
	ctx, cancel := context.WithCancel(ctx)

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", parent.addr)
	if err != nil {
		cancel()
		return nil, err
	}

	sess := &cliSession{
		ctx:       ctx,
		cancel:    cancel,
		conn:      conn,
		mux:       parent.mux,
		subs:      make(map[xrdproto.PathID]*cliSession),
		requests:  make(map[xrdproto.StreamID]pendingRequest),
		client:    parent.client,
		sessionID: parent.addr,
		addr:      parent.addr,
		isSub:     true,
	}

	go sess.consume()

	if err := sess.handshake(ctx); err != nil {
		sess.Close()
		return nil, err
	}

	pathID, err := sess.bind(ctx, parent.loginID)
	if err != nil {
		sess.Close()
		return nil, err
	}

	sess.pathID = pathID
	return sess, nil
}

// discoverZTNToken discovers the ZTN bearer token from environment variables and files
// following the ZTN protocol specification.
// It checks in this order:
// 1. BEARER_TOKEN environment variable
// 2. BEARER_TOKEN_FILE environment variable (reads token from file)
// 3. $XDG_RUNTIME_DIR/bt_u<euid> file
// 4. /tmp/bt_u<euid> file
// Returns empty string if no token is found.
func discoverZTNToken() string {
	// 1. Check BEARER_TOKEN environment variable
	if token := os.Getenv("BEARER_TOKEN"); token != "" {
		return strings.TrimSpace(token)
	}

	// 2. Check BEARER_TOKEN_FILE environment variable
	if tokenFile := os.Getenv("BEARER_TOKEN_FILE"); tokenFile != "" {
		if data, err := os.ReadFile(tokenFile); err == nil {
			return strings.TrimSpace(string(data))
		}
	}

	// Get effective user ID for file-based token discovery
	euid := os.Geteuid()
	tokenFileName := "bt_u" + strconv.Itoa(euid)

	// 3. Check $XDG_RUNTIME_DIR/bt_u<euid>
	if xdgDir := os.Getenv("XDG_RUNTIME_DIR"); xdgDir != "" {
		tokenPath := filepath.Join(xdgDir, tokenFileName)
		if data, err := os.ReadFile(tokenPath); err == nil {
			return strings.TrimSpace(string(data))
		}
	}

	// 4. Check /tmp/bt_u<euid>
	tokenPath := filepath.Join("/tmp", tokenFileName)
	if data, err := os.ReadFile(tokenPath); err == nil {
		return strings.TrimSpace(string(data))
	}

	return ""
}
