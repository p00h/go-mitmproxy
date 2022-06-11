package flow

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"

	"github.com/lqqyt2423/go-mitmproxy/connection"
)

var ConnContextKey = new(struct{})

type ConnContext struct {
	Client *connection.Client
	Server *connection.Server
}

func NewConnContext(c net.Conn) *ConnContext {
	client := connection.NewClient(c)
	return &ConnContext{
		Client: client,
	}
}

type serverConn struct {
	net.Conn
}

func (c *serverConn) Close() error {
	log.Debugln("in http serverConn close")
	return c.Conn.Close()
}

func (connCtx *ConnContext) InitHttpServer(SslInsecure bool) {
	if connCtx.Server != nil {
		return
	}
	if connCtx.Client.Tls {
		return
	}

	server := connection.NewServer()
	server.Client = &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,

			// todo: change here
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				c, err := (&net.Dialer{
					// Timeout:   30 * time.Second,
					// KeepAlive: 30 * time.Second,
				}).DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}

				cw := &serverConn{c}
				server.Conn = cw
				return cw, nil
			},
			ForceAttemptHTTP2: false, // disable http2

			DisableCompression: true, // To get the original response from the server, set Transport.DisableCompression to true.
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: SslInsecure,
				KeyLogWriter:       GetTlsKeyLogWriter(),
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 禁止自动重定向
			return http.ErrUseLastResponse
		},
	}
	connCtx.Server = server
}

func (connCtx *ConnContext) InitHttpsServer(SslInsecure bool) {
	if connCtx.Server != nil {
		return
	}
	if !connCtx.Client.Tls {
		return
	}

	server := connection.NewServer()
	server.Client = &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyFromEnvironment,

			// todo: change here
			DialContext: (&net.Dialer{
				// Timeout:   30 * time.Second,
				// KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2: false, // disable http2

			DisableCompression: true, // To get the original response from the server, set Transport.DisableCompression to true.
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: SslInsecure,
				KeyLogWriter:       GetTlsKeyLogWriter(),
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// 禁止自动重定向
			return http.ErrUseLastResponse
		},
	}
	connCtx.Server = server
}