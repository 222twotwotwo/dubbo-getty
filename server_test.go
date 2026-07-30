/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package getty

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

import (
	"github.com/stretchr/testify/assert"
)

func testTCPServer(t *testing.T, address string) {
	var (
		server           *server
		serverMsgHandler MessageHandler
	)

	func() {
		server = newServer(
			TCP_SERVER,
			WithLocalAddress(address),
		)
		newServerSession := func(session Session) error {
			return newSessionCallback(session, &serverMsgHandler)
		}
		server.RunEventLoop(newServerSession)
		assert.True(t, server.ID() > 0)
		assert.True(t, server.EndPointType() == TCP_SERVER)
		assert.NotNil(t, server.streamListener)
	}()
	time.Sleep(500e6)

	addr := server.streamListener.Addr().String()
	t.Logf("@address:%s, tcp server addr: %v", address, addr)
	clt := newClient(TCP_CLIENT,
		WithServerAddress(addr),
		WithReconnectInterval(5e8),
		WithConnectionNumber(1),
	)
	assert.NotNil(t, clt)
	assert.True(t, clt.ID() > 0)
	assert.Equal(t, clt.endPointType, TCP_CLIENT)

	var msgHandler MessageHandler
	cb := func(session Session) error {
		return newSessionCallback(session, &msgHandler)
	}

	clt.RunEventLoop(cb)
	time.Sleep(1e9)

	assert.Equal(t, 1, msgHandler.SessionNumber())
	clt.Close()
	assert.True(t, clt.IsClosed())

	server.Close()
	assert.True(t, server.IsClosed())
}

func testTCPTlsServer(t *testing.T, address string) {
	var (
		server           *server
		serverMsgHandler MessageHandler
	)
	serverPemPath, _ := filepath.Abs("./demo/hello/tls/certs/server0.pem")
	serverKeyPath, _ := filepath.Abs("./demo/hello/tls/certs/server0.key")
	caPemPath, _ := filepath.Abs("./demo/hello/tls/certs/ca.pem")

	configBuilder := &ServerTlsConfigBuilder{
		ServerKeyCertChainPath:        serverPemPath,
		ServerPrivateKeyPath:          serverKeyPath,
		ServerTrustCertCollectionPath: caPemPath,
	}

	func() {
		server = newServer(
			TCP_SERVER,
			WithLocalAddress(address),
			WithServerSslEnabled(true),
			WithServerTlsConfigBuilder(configBuilder),
		)
		newServerSession := func(session Session) error {
			return newSessionCallback(session, &serverMsgHandler)
		}
		server.RunEventLoop(newServerSession)
		assert.True(t, server.ID() > 0)
		assert.True(t, server.EndPointType() == TCP_SERVER)
		assert.NotNil(t, server.streamListener)
	}()
	time.Sleep(500e6)

	addr := server.streamListener.Addr().String()
	t.Logf("@address:%s, tcp server addr: %v", address, addr)
	keyPath, _ := filepath.Abs("./demo/hello/tls/certs/ca.key")
	clientCaPemPath, _ := filepath.Abs("./demo/hello/tls/certs/ca.pem")

	clientConfig := &ClientTlsConfigBuilder{
		ClientTrustCertCollectionPath: clientCaPemPath,
		ClientPrivateKeyPath:          keyPath,
	}

	clt := newClient(TCP_CLIENT,
		WithServerAddress(addr),
		WithReconnectInterval(5e8),
		WithConnectionNumber(1),
		WithClientTlsConfigBuilder(clientConfig),
	)
	assert.NotNil(t, clt)
	assert.True(t, clt.ID() > 0)
	assert.Equal(t, clt.endPointType, TCP_CLIENT)

	var msgHandler MessageHandler
	cb := func(session Session) error {
		return newSessionCallback(session, &msgHandler)
	}

	clt.RunEventLoop(cb)
	time.Sleep(1e9)

	assert.Equal(t, 1, msgHandler.SessionNumber())
	clt.Close()
	assert.True(t, clt.IsClosed())

	server.Close()
	assert.True(t, server.IsClosed())
}

func testUDPServer(t *testing.T, address string) {
	var (
		server           *server
		serverMsgHandler MessageHandler
	)
	func() {
		server = newServer(
			UDP_ENDPOINT,
			WithLocalAddress(address),
		)
		newServerSession := func(session Session) error {
			return newSessionCallback(session, &serverMsgHandler)
		}
		server.RunEventLoop(newServerSession)
		assert.True(t, server.ID() > 0)
		assert.True(t, server.EndPointType() == UDP_ENDPOINT)
		assert.NotNil(t, server.pktListener)
	}()
	time.Sleep(500e6)

	addr := server.pktListener.LocalAddr().String()
	t.Logf("@address:%s, udp server addr: %v", address, addr)
}

func TestServer(t *testing.T) {
	var addr string

	testTCPServer(t, addr)
	testUDPServer(t, addr)

	addr = "127.0.0.1:0"
	testTCPServer(t, addr)
	testUDPServer(t, addr)

	addr = "127.0.0.1"
	testTCPServer(t, addr)
	testUDPServer(t, addr)
	addr = "127.0.0.9999"
	testTCPTlsServer(t, addr)
}

func TestWSServeWSRequestClosesSelfConnectConn(t *testing.T) {
	server := newServer(WS_SERVER)
	newSessionCalled := false
	handler := newWSHandler(server, func(Session) error {
		newSessionCalled = true
		return errors.New("self-connect request should not create session")
	})

	conn := &selfConnectConn{addr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 65000}}
	rw := &hijackResponseWriter{
		header: make(http.Header),
		conn:   conn,
	}
	req, err := http.NewRequest(http.MethodGet, "http://127.0.0.1/ws", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	handler.serveWSRequest(rw, req)

	if !strings.HasPrefix(conn.writes.String(), "HTTP/1.1 101 Switching Protocols\r\n") {
		t.Fatalf("expected websocket upgrade to succeed, got response %q", conn.writes.String())
	}
	if newSessionCalled {
		t.Fatal("expected self-connect websocket request to be rejected before session creation")
	}
	if !conn.closed {
		t.Fatal("expected self-connect websocket connection to be closed")
	}
}

func TestWSSServerCloseDoesNotPanic(t *testing.T) {
	certFile := filepath.Join(t.TempDir(), "server.crt")
	keyFile := filepath.Join(t.TempDir(), "server.key")
	assert.NoError(t, DownloadFile(certFile, WssServerCRT))
	assert.NoError(t, DownloadFile(keyFile, WssServerKEY))

	srv := NewWSSServer(
		WithLocalAddress("127.0.0.1:0"),
		WithWebsocketServerPath("/hello"),
		WithWebsocketServerCert(certFile),
		WithWebsocketServerPrivateKey(keyFile),
	)
	defer srv.Close()

	var serverMsgHandler MessageHandler
	srv.RunEventLoop(func(session Session) error {
		return newSessionCallback(session, &serverMsgHandler)
	})

	waitUntilHTTPServerReady(t, srv.(*server))
	srv.Close()
	assert.True(t, srv.IsClosed())
}

func TestHTTPServeCloseErrorClassification(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{
			name: "http server closed",
			err:  http.ErrServerClosed,
			want: true,
		},
		{
			name: "wrapped net closed",
			err:  fmt.Errorf("wrapped: %w", net.ErrClosed),
			want: true,
		},
		{
			name: "fatal error with closed listener text",
			err:  errors.New("fatal listener failure after use of closed network connection marker"),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isHTTPServeCloseError(tt.err))
		})
	}
}

func TestWSSEventLoopServeCloseErrorDoesNotPanic(t *testing.T) {
	srv := newTestWSSServerWithListener(t, &serveErrorListener{
		err: fmt.Errorf("listener closed: %w", net.ErrClosed),
	})

	srv.runWSSEventLoop(func(Session) error {
		return nil
	})
	waitUntilHTTPServerReady(t, srv)
	waitUntilServerLoopDone(t, srv)
}

func TestWSSEventLoopUnexpectedServeErrorPanics(t *testing.T) {
	if os.Getenv("GETTY_WSS_FATAL_SERVE_ERROR") == "1" {
		SetLogger(stderrTestLogger{})
		srv := newTestWSSServerWithListener(t, &serveErrorListener{
			err: errors.New("fatal listener failure after use of closed network connection marker"),
		})

		srv.runWSSEventLoop(func(Session) error {
			return nil
		})
		srv.wg.Wait()
		t.Fatal("expected WSS Serve error to panic")
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestWSSEventLoopUnexpectedServeErrorPanics$")
	cmd.Env = append(os.Environ(), "GETTY_WSS_FATAL_SERVE_ERROR=1")
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected child process to fail from WSS Serve panic, got success:\n%s", output)
	}
	if !strings.Contains(string(output), "http.server.Serve") {
		t.Fatalf("expected child process output to include WSS Serve error log, got:\n%s", output)
	}
	if !strings.Contains(string(output), "panic: fatal listener failure after use of closed network connection marker") {
		t.Fatalf("expected child process output to include WSS Serve panic, got:\n%s", output)
	}
}

type hijackResponseWriter struct {
	header http.Header
	conn   *selfConnectConn
	status int
}

func (w *hijackResponseWriter) Header() http.Header {
	return w.header
}

func (w *hijackResponseWriter) Write(p []byte) (int, error) {
	return len(p), nil
}

func (w *hijackResponseWriter) WriteHeader(status int) {
	w.status = status
}

func (w *hijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

type selfConnectConn struct {
	writes bytes.Buffer
	addr   net.Addr
	closed bool
}

func (c *selfConnectConn) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (c *selfConnectConn) Write(p []byte) (int, error) {
	return c.writes.Write(p)
}

func (c *selfConnectConn) Close() error {
	c.closed = true
	return nil
}

func (c *selfConnectConn) LocalAddr() net.Addr {
	return c.addr
}

func (c *selfConnectConn) RemoteAddr() net.Addr {
	return c.addr
}

func (c *selfConnectConn) SetDeadline(time.Time) error {
	return nil
}

func (c *selfConnectConn) SetReadDeadline(time.Time) error {
	return nil
}

func (c *selfConnectConn) SetWriteDeadline(time.Time) error {
	return nil
}

type serveErrorListener struct {
	err error
}

func (l *serveErrorListener) Accept() (net.Conn, error) {
	return nil, l.err
}

func (l *serveErrorListener) Close() error {
	return nil
}

func (l *serveErrorListener) Addr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
}

func newTestWSSServerWithListener(t *testing.T, listener net.Listener) *server {
	t.Helper()

	certFile := filepath.Join(t.TempDir(), "server.crt")
	keyFile := filepath.Join(t.TempDir(), "server.key")
	assert.NoError(t, DownloadFile(certFile, WssServerCRT))
	assert.NoError(t, DownloadFile(keyFile, WssServerKEY))

	srv := NewWSSServer(
		WithLocalAddress(listener.Addr().String()),
		WithWebsocketServerPath("/hello"),
		WithWebsocketServerCert(certFile),
		WithWebsocketServerPrivateKey(keyFile),
	).(*server)
	srv.streamListener = listener

	return srv
}

func waitUntilHTTPServerReady(t *testing.T, server *server) {
	t.Helper()

	timeout := time.After(3 * time.Second)
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()

	for {
		server.lock.Lock()
		ready := server.server != nil
		server.lock.Unlock()
		if ready {
			return
		}

		select {
		case <-timeout:
			t.Fatal("timeout waiting for http server to start")
		case <-tick.C:
		}
	}
}

func waitUntilServerLoopDone(t *testing.T, server *server) {
	t.Helper()

	done := make(chan struct{})
	go func() {
		server.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for server event loop to exit")
	}
}

type stderrTestLogger struct{}

func (stderrTestLogger) Info(args ...any)     {}
func (stderrTestLogger) Warn(args ...any)     {}
func (stderrTestLogger) Error(args ...any)    {}
func (stderrTestLogger) Debug(args ...any)    {}
func (stderrTestLogger) Infof(string, ...any) {}
func (stderrTestLogger) Warnf(string, ...any) {}
func (stderrTestLogger) Errorf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}
func (stderrTestLogger) Debugf(string, ...any) {}
