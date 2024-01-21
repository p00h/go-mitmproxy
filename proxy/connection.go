package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/imroc/req/v3"

	uuid "github.com/satori/go.uuid"
	log "github.com/sirupsen/logrus"
)

type MyClient struct {
	client *req.Client
}

func NewMyClient(debug int) *MyClient {
	c := &MyClient{
		client: newReqClient(debug),
	}

	return c
}

func (c *MyClient) Do(r *http.Request) (*req.Response, error) {
	strUrl := r.URL.String()
	request := c.client.R()

	for _, cookie := range r.Cookies() {
		request.SetCookies(cookie)
	}

	for key, value := range r.Header {
		for _, v := range value {
			request.SetHeader(key, v)
		}
	}

	if r.Body != nil {
		request.SetBody(r.Body)
	}

	if r.Method == "GET" {
		return request.Get(strUrl)
	}

	if r.Method == "POST" {
		return request.Post(strUrl)
	}

	if r.Method == "PUT" {
		return request.Put(strUrl)
	}

	if r.Method == "PATCH" {
		return request.Patch(strUrl)
	}

	if r.Method == "DELETE" {
		return request.Delete(strUrl)
	}

	return nil, fmt.Errorf("No handler for %s method", r.Method)
}

func newReqClient(debug int) *req.Client {
	client := req.C().
		ImpersonateChrome()

	client.SetRedirectPolicy(req.NoRedirectPolicy())

	if debug > 0 {
		client.EnableDebugLog()
		// EnableDumpAll().
	}

	return client
}

// client connection
type ClientConn struct {
	Id           uuid.UUID
	Conn         net.Conn
	Tls          bool
	UpstreamCert bool // Connect to upstream server to look up certificate details. Default: True
	clientHello  *tls.ClientHelloInfo
}

func newClientConn(c net.Conn) *ClientConn {
	return &ClientConn{
		Id:           uuid.NewV4(),
		Conn:         c,
		Tls:          false,
		UpstreamCert: false,
	}
}

func (c *ClientConn) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	m["id"] = c.Id
	m["tls"] = c.Tls
	m["address"] = c.Conn.RemoteAddr().String()
	return json.Marshal(m)
}

// server connection
type ServerConn struct {
	Id      uuid.UUID
	Address string
	Conn    net.Conn

	tlsHandshaked   chan struct{}
	tlsHandshakeErr error
	tlsConn         *tls.Conn
	tlsState        *tls.ConnectionState
	client          *MyClient
}

func newServerConn() *ServerConn {
	return &ServerConn{
		Id:            uuid.NewV4(),
		tlsHandshaked: make(chan struct{}),
	}
}

func (c *ServerConn) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	m["id"] = c.Id
	m["address"] = c.Address
	peername := ""
	if c.Conn != nil {
		peername = c.Conn.RemoteAddr().String()
	}
	m["peername"] = peername
	return json.Marshal(m)
}

func (c *ServerConn) TlsState() *tls.ConnectionState {
	<-c.tlsHandshaked
	return c.tlsState
}

// connection context ctx key
var connContextKey = new(struct{})

// connection context
type ConnContext struct {
	ClientConn *ClientConn `json:"clientConn"`
	ServerConn *ServerConn `json:"serverConn"`
	Intercept  bool        `json:"intercept"` // Indicates whether to parse HTTPS
	FlowCount  uint32      `json:"-"`         // Number of HTTP requests made on the same connection

	proxy              *Proxy
	pipeConn           *pipeConn
	closeAfterResponse bool // after http response, http server will close the connection
}

func newConnContext(c net.Conn, proxy *Proxy) *ConnContext {
	clientConn := newClientConn(c)
	return &ConnContext{
		ClientConn: clientConn,
		proxy:      proxy,
	}
}

func (connCtx *ConnContext) Id() uuid.UUID {
	return connCtx.ClientConn.Id
}

func (connCtx *ConnContext) initHttpServerConn() {
	if connCtx.ServerConn != nil {
		return
	}
	if connCtx.ClientConn.Tls {
		return
	}

	serverConn := newServerConn()
	serverConn.client = NewMyClient(connCtx.proxy.Opts.Debug)
	connCtx.ServerConn = serverConn
}

func (connCtx *ConnContext) initServerTcpConn(req *http.Request) error {
	log.Debugln("in initServerTcpConn")
	ServerConn := newServerConn()
	connCtx.ServerConn = ServerConn
	ServerConn.Address = connCtx.pipeConn.host

	plainConn, err := connCtx.proxy.getUpstreamConn(req)
	if err != nil {
		return err
	}
	ServerConn.Conn = &wrapServerConn{
		Conn:    plainConn,
		proxy:   connCtx.proxy,
		connCtx: connCtx,
	}

	for _, addon := range connCtx.proxy.Addons {
		addon.ServerConnected(connCtx)
	}

	return nil
}

func (connCtx *ConnContext) initHttpsServerConn() {
	if !connCtx.ClientConn.Tls {
		return
	}

	log.Debugf("UpstreamCert=%t\n", connCtx.ClientConn.UpstreamCert)
	if connCtx.ClientConn.UpstreamCert {
		connCtx.ServerConn.client = NewMyClient(connCtx.proxy.Opts.Debug)
	} else {
		serverConn := newServerConn()
		serverConn.client = NewMyClient(connCtx.proxy.Opts.Debug)
		connCtx.ServerConn = serverConn
	}
}

func (connCtx *ConnContext) tlsHandshake(clientHello *tls.ClientHelloInfo) error {
	cfg := &tls.Config{
		InsecureSkipVerify: connCtx.proxy.Opts.SslInsecure,
		KeyLogWriter:       getTlsKeyLogWriter(),
		ServerName:         clientHello.ServerName,
		NextProtos:         []string{"http/1.1"}, // todo: h2
		// CurvePreferences:   clientHello.SupportedCurves, // todo: 如果打开会出错
		CipherSuites: clientHello.CipherSuites,
	}
	if len(clientHello.SupportedVersions) > 0 {
		minVersion := clientHello.SupportedVersions[0]
		maxVersion := clientHello.SupportedVersions[0]
		for _, version := range clientHello.SupportedVersions {
			if version < minVersion {
				minVersion = version
			}
			if version > maxVersion {
				maxVersion = version
			}
		}
		cfg.MinVersion = minVersion
		cfg.MaxVersion = maxVersion
	}

	tlsConn := tls.Client(connCtx.ServerConn.Conn, cfg)
	err := tlsConn.HandshakeContext(context.Background())
	if err != nil {
		connCtx.ServerConn.tlsHandshakeErr = err
		close(connCtx.ServerConn.tlsHandshaked)
		return err
	}

	connCtx.ServerConn.tlsConn = tlsConn
	tlsState := tlsConn.ConnectionState()
	connCtx.ServerConn.tlsState = &tlsState
	close(connCtx.ServerConn.tlsHandshaked)

	return nil
}

// wrap tcpConn for remote client
type wrapClientConn struct {
	net.Conn
	proxy    *Proxy
	connCtx  *ConnContext
	closed   bool
	closeErr error
}

func (c *wrapClientConn) Close() error {
	if c.closed {
		return c.closeErr
	}
	log.Debugln("in wrapClientConn close", c.connCtx.ClientConn.Conn.RemoteAddr())

	c.closed = true
	c.closeErr = c.Conn.Close()

	for _, addon := range c.proxy.Addons {
		addon.ClientDisconnected(c.connCtx.ClientConn)
	}

	if c.connCtx.ServerConn != nil && c.connCtx.ServerConn.Conn != nil {
		c.connCtx.ServerConn.Conn.Close()
	}

	return c.closeErr
}

// wrap tcpListener for remote client
type wrapListener struct {
	net.Listener
	proxy *Proxy
}

func (l *wrapListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &wrapClientConn{
		Conn:  c,
		proxy: l.proxy,
	}, nil
}

// wrap tcpConn for remote server
type wrapServerConn struct {
	net.Conn
	proxy    *Proxy
	connCtx  *ConnContext
	closed   bool
	closeErr error
}

func (c *wrapServerConn) Close() error {
	if c.closed {
		return c.closeErr
	}
	log.Debugln("in wrapServerConn close", c.connCtx.ClientConn.Conn.RemoteAddr())

	c.closed = true
	c.closeErr = c.Conn.Close()

	for _, addon := range c.proxy.Addons {
		addon.ServerDisconnected(c.connCtx)
	}

	if !c.connCtx.ClientConn.Tls {
		c.connCtx.ClientConn.Conn.(*wrapClientConn).Conn.(*net.TCPConn).CloseRead()
	} else {
		// if keep-alive connection close
		if !c.connCtx.closeAfterResponse {
			c.connCtx.pipeConn.Close()
		}
	}

	return c.closeErr
}

// connect proxy when set https_proxy env
// ref: http/transport.go dialConn func
func getProxyConn(proxyUrl *url.URL, address string) (net.Conn, error) {
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", proxyUrl.Host)
	if err != nil {
		return nil, err
	}
	connectReq := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: address},
		Host:   address,
		Header: http.Header{},
	}
	if proxyUrl.User != nil {
		connectReq.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(proxyUrl.User.String())))
	}
	connectCtx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()
	didReadResponse := make(chan struct{}) // closed after CONNECT write+read is done or fails
	var resp *http.Response
	// Write the CONNECT request & read the response.
	go func() {
		defer close(didReadResponse)
		err = connectReq.Write(conn)
		if err != nil {
			return
		}
		// Okay to use and discard buffered reader here, because
		// TLS server will not speak until spoken to.
		br := bufio.NewReader(conn)
		resp, err = http.ReadResponse(br, connectReq)
	}()
	select {
	case <-connectCtx.Done():
		conn.Close()
		<-didReadResponse
		return nil, connectCtx.Err()
	case <-didReadResponse:
		// resp or err now set
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	if resp.StatusCode != 200 {
		_, text, ok := strings.Cut(resp.Status, " ")
		conn.Close()
		if !ok {
			return nil, errors.New("unknown status code")
		}
		return nil, errors.New(text)
	}
	return conn, nil
}
