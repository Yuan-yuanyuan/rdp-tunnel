package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v3"
)

// ================================================================
// 配置结构
// ================================================================

type Config struct {
	Mode string `yaml:"mode"` // "server" 或 "client"

	// 服务端配置
	Listen  string        `yaml:"listen"`
	TLS     TLSConfig     `yaml:"tls"`
	Token   string        `yaml:"token"`
	Path    string        `yaml:"path"`
	Proxies []ProxyConfig `yaml:"proxies"` // 正向代理

	// 客户端配置
	Servers []ServerDef `yaml:"servers"`
	Tunnels []TunnelDef `yaml:"tunnels"` // 正向隧道
	Expose  []ExposeDef `yaml:"expose"`  // 反向隧道
}

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	CertPEM  string `yaml:"cert_pem"`
	KeyPEM   string `yaml:"key_pem"`
}

type ProxyConfig struct {
	Name    string `yaml:"name"`
	Backend string `yaml:"backend"` // 支持 "@name" 指向反向代理
}

type ServerDef struct {
	Name     string `yaml:"name"`
	URL      string `yaml:"url"`
	Token    string `yaml:"token"`
	Insecure bool   `yaml:"insecure"`
}

type TunnelDef struct {
	Listen    string `yaml:"listen"`
	Server    string `yaml:"server"`
	ProxyName string `yaml:"proxy_name"`
}

type ExposeDef struct {
	Name       string `yaml:"name"`
	Backend    string `yaml:"backend"`
	RemotePort int    `yaml:"remote_port"` // 让服务端监听的端口
	Server     string `yaml:"server"`
}

// ================================================================
// 服务端：正向代理 session
// ================================================================

type session struct {
	backend net.Conn
	ws      *websocket.Conn
	mu      sync.Mutex
	closed  bool
}

func (s *session) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		if s.backend != nil {
			s.backend.Close()
		}
		if s.ws != nil {
			s.ws.Close()
		}
	}
}

var sessions = sync.Map{}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  32 * 1024,
	WriteBufferSize: 32 * 1024,
	CheckOrigin:     func(r *http.Request) bool { return true },
}

// ================================================================
// 服务端：反向代理注册表
// ================================================================

type reverseClient struct {
	ws         *websocket.Conn
	mu         sync.Mutex
	remotePort int
	listener   net.Listener
}

func (rc *reverseClient) sendDialRequest(sid string) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	msg := "DIAL:" + sid
	rc.ws.WriteMessage(websocket.TextMessage, []byte(msg))
}

// reverseRegistry：name -> *reverseClient
var reverseRegistry sync.Map

// reverseDataConns：sessionID -> chan net.Conn
var reverseDataConns sync.Map

func runServer(cfg *Config) {
	if cfg.Token == "" {
		log.Fatal("[server] token must be set")
	}
	if cfg.Path == "" {
		cfg.Path = "/tunnel"
	}

	proxyMap := map[string]string{}
	for _, p := range cfg.Proxies {
		proxyMap[p.Name] = p.Backend
		if strings.HasPrefix(p.Backend, "@") {
			log.Printf("[server] forward proxy [%s] -> reverse:%s", p.Name, p.Backend[1:])
		} else {
			log.Printf("[server] forward proxy [%s] -> %s", p.Name, p.Backend)
		}
	}

	mux := http.NewServeMux()

	mux.HandleFunc(cfg.Path, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+cfg.Token {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		connType := r.Header.Get("X-Tunnel-Type")
		switch connType {
		case "reverse-control":
			serverHandleReverseControl(w, r)
		case "reverse-data":
			serverHandleReverseData(w, r)
		default:
			serverHandleWS(w, r, proxyMap)
		}
	})

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	srv := &http.Server{Addr: cfg.Listen, Handler: mux}

	if cfg.TLS.Enabled {
		tlsCfg, err := buildTLSConfig(cfg.TLS)
		if err != nil {
			log.Fatalf("[server] TLS config error: %v", err)
		}
		srv.TLSConfig = tlsCfg
		log.Printf("[server] starting (TLS) on %s  path=%s", cfg.Listen, cfg.Path)
		if err := srv.ListenAndServeTLS("", ""); err != nil {
			log.Fatal(err)
		}
	} else {
		log.Printf("[server] starting (HTTP) on %s  path=%s", cfg.Listen, cfg.Path)
		if err := srv.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}
}

// serverHandleReverseControl：处理客户端的控制连接，动态监听端口
func serverHandleReverseControl(w http.ResponseWriter, r *http.Request) {
	exposeName := r.Header.Get("X-Expose-Name")
	remotePortStr := r.Header.Get("X-Remote-Port")
	if exposeName == "" || remotePortStr == "" {
		http.Error(w, "Missing X-Expose-Name or X-Remote-Port", http.StatusBadRequest)
		return
	}

	remotePort, err := strconv.Atoi(remotePortStr)
	if err != nil || remotePort <= 0 || remotePort > 65535 {
		http.Error(w, "Invalid X-Remote-Port", http.StatusBadRequest)
		return
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[server] reverse control upgrade failed: %v", err)
		return
	}

	// 动态监听端口
	listenAddr := fmt.Sprintf("0.0.0.0:%d", remotePort)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Printf("[server] reverse [%s] failed to listen on %s: %v", exposeName, listenAddr, err)
		ws.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "port unavailable"))
		ws.Close()
		return
	}

	rc := &reverseClient{
		ws:         ws,
		remotePort: remotePort,
		listener:   ln,
	}
	reverseRegistry.Store(exposeName, rc)
	log.Printf("[server] reverse client registered: [%s] listening on %s", exposeName, listenAddr)

	// 启动监听 goroutine
	go serverListenReverse(exposeName, ln)

	defer func() {
		reverseRegistry.Delete(exposeName)
		ln.Close()
		ws.Close()
		log.Printf("[server] reverse client disconnected: [%s], port %d closed", exposeName, remotePort)
	}()

	// 保持控制连接
	for {
		_, _, err := ws.ReadMessage()
		if err != nil {
			break
		}
	}
}

func serverListenReverse(name string, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener 关闭
		}
		go serverHandleReverseConn(conn, name)
	}
}

func serverHandleReverseConn(extConn net.Conn, name string) {
	val, ok := reverseRegistry.Load(name)
	if !ok {
		log.Printf("[server] reverse [%s]: client disconnected", name)
		extConn.Close()
		return
	}
	rc := val.(*reverseClient)

	sid := newSessionID()
	ch := make(chan net.Conn, 1)
	reverseDataConns.Store(sid, ch)
	defer reverseDataConns.Delete(sid)

	rc.sendDialRequest(sid)
	log.Printf("[server] reverse [%s] [%s] waiting for client data connection...", name, sid)

	select {
	case dataConn := <-ch:
		log.Printf("[server] reverse [%s] [%s] data connection established, bridging", name, sid)
		bridge(extConn, dataConn, sid)
	case <-time.After(15 * time.Second):
		log.Printf("[server] reverse [%s] [%s] timeout waiting for client", name, sid)
		extConn.Close()
	}
}

func serverHandleReverseData(w http.ResponseWriter, r *http.Request) {
	sid := r.Header.Get("X-Session-ID")
	if sid == "" {
		http.Error(w, "Missing X-Session-ID", http.StatusBadRequest)
		return
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[server] reverse data upgrade failed: %v", err)
		return
	}

	wsConn := &wsNetConn{ws: ws}

	val, ok := reverseDataConns.Load(sid)
	if !ok {
		log.Printf("[server] reverse data [%s]: no pending session", sid)
		ws.Close()
		return
	}
	ch := val.(chan net.Conn)
	ch <- wsConn
}

// serverHandleWS：正向代理，支持 @name 指向反向代理
func serverHandleWS(w http.ResponseWriter, r *http.Request, proxyMap map[string]string) {
	proxyName := r.Header.Get("X-Proxy-Name")
	if proxyName == "" {
		http.Error(w, "Missing X-Proxy-Name", http.StatusBadRequest)
		return
	}
	backend, ok := proxyMap[proxyName]
	if !ok {
		http.Error(w, "Unknown proxy name", http.StatusBadRequest)
		return
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("[server] WebSocket upgrade failed: %v", err)
		return
	}

	sid := r.Header.Get("X-Session-ID")
	if sid == "" {
		sid = newSessionID()
	}

	// 检查是否指向反向代理
	if strings.HasPrefix(backend, "@") {
		reverseName := backend[1:]
		serverHandleForwardToReverse(ws, sid, proxyName, reverseName)
		return
	}

	// 普通正向代理：连接本机 backend
	backendConn, err := net.DialTimeout("tcp", backend, 10*time.Second)
	if err != nil {
		log.Printf("[server] [%s] failed to connect to backend %s: %v", sid, backend, err)
		ws.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "backend unavailable"))
		ws.Close()
		return
	}

	sess := &session{backend: backendConn, ws: ws}
	sessions.Store(sid, sess)
	log.Printf("[server] [%s] forward proxy [%s] -> %s", sid, proxyName, backend)

	wsConn := &wsNetConn{ws: ws}
	bridge(backendConn, wsConn, sid)
	sessions.Delete(sid)
	log.Printf("[server] [%s] session closed", sid)
}

// serverHandleForwardToReverse：正向代理指向反向代理
func serverHandleForwardToReverse(ws *websocket.Conn, sid, proxyName, reverseName string) {
	val, ok := reverseRegistry.Load(reverseName)
	if !ok {
		log.Printf("[server] [%s] forward proxy [%s] -> reverse:%s: client not connected", sid, proxyName, reverseName)
		ws.WriteMessage(websocket.CloseMessage,
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "reverse client unavailable"))
		ws.Close()
		return
	}
	rc := val.(*reverseClient)

	ch := make(chan net.Conn, 1)
	reverseDataConns.Store(sid, ch)
	defer reverseDataConns.Delete(sid)

	rc.sendDialRequest(sid)
	log.Printf("[server] [%s] forward proxy [%s] -> reverse:%s, waiting for client...", sid, proxyName, reverseName)

	select {
	case dataConn := <-ch:
		log.Printf("[server] [%s] forward proxy [%s] -> reverse:%s established, bridging", sid, proxyName, reverseName)
		wsConn := &wsNetConn{ws: ws}
		bridge(wsConn, dataConn, sid)
	case <-time.After(15 * time.Second):
		log.Printf("[server] [%s] forward proxy [%s] -> reverse:%s timeout", sid, proxyName, reverseName)
		ws.Close()
	}
}

func buildTLSConfig(t TLSConfig) (*tls.Config, error) {
	var cert tls.Certificate
	var err error
	if t.CertPEM != "" && t.KeyPEM != "" {
		cert, err = tls.X509KeyPair([]byte(t.CertPEM), []byte(t.KeyPEM))
	} else {
		cert, err = tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
	}
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// ================================================================
// 客户端
// ================================================================

func runClient(cfg *Config) {
	if len(cfg.Servers) == 0 {
		log.Fatal("[client] at least one server must be configured")
	}
	hasTunnels := len(cfg.Tunnels) > 0
	hasExpose := len(cfg.Expose) > 0
	if !hasTunnels && !hasExpose {
		log.Fatal("[client] at least one tunnel or expose must be configured")
	}

	serverMap := map[string]*ServerDef{}
	for i := range cfg.Servers {
		s := &cfg.Servers[i]
		serverMap[s.Name] = s
		log.Printf("[client] server [%s]: %s", s.Name, s.URL)
	}

	var wg sync.WaitGroup

	// 正向隧道
	for _, t := range cfg.Tunnels {
		srv, ok := serverMap[t.Server]
		if !ok {
			log.Fatalf("[client] tunnel %s references unknown server: %s", t.Listen, t.Server)
		}
		wg.Add(1)
		go func(tunnel TunnelDef, server *ServerDef) {
			defer wg.Done()
			log.Printf("[client] tunnel [%s] -> server=%s proxy=%s", tunnel.Listen, tunnel.Server, tunnel.ProxyName)
			if err := clientListen(tunnel, server); err != nil {
				log.Fatalf("[client] tunnel [%s] failed: %v", tunnel.Listen, err)
			}
		}(t, srv)
	}

	// 反向隧道（expose）
	for _, e := range cfg.Expose {
		srv, ok := serverMap[e.Server]
		if !ok {
			log.Fatalf("[client] expose %s references unknown server: %s", e.Name, e.Server)
		}
		if e.RemotePort <= 0 || e.RemotePort > 65535 {
			log.Fatalf("[client] expose %s: invalid remote_port %d", e.Name, e.RemotePort)
		}
		wg.Add(1)
		go func(exp ExposeDef, server *ServerDef) {
			defer wg.Done()
			log.Printf("[client] expose [%s] backend=%s remote_port=%d -> server=%s", exp.Name, exp.Backend, exp.RemotePort, exp.Server)
			clientRunExpose(exp, server)
		}(e, srv)
	}

	wg.Wait()
}

func clientRunExpose(exp ExposeDef, server *ServerDef) {
	for {
		if err := clientExposeOnce(exp, server); err != nil {
			log.Printf("[client] expose [%s] disconnected: %v, reconnecting in 5s...", exp.Name, err)
		}
		time.Sleep(5 * time.Second)
	}
}

func clientExposeOnce(exp ExposeDef, server *ServerDef) error {
	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: server.Insecure},
		HandshakeTimeout: 10 * time.Second,
	}
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+server.Token)
	headers.Set("X-Tunnel-Type", "reverse-control")
	headers.Set("X-Expose-Name", exp.Name)
	headers.Set("X-Remote-Port", strconv.Itoa(exp.RemotePort))

	ws, _, err := dialer.Dial(httpToWS(server.URL), headers)
	if err != nil {
		return fmt.Errorf("control dial failed: %w", err)
	}
	defer ws.Close()
	log.Printf("[client] expose [%s] control connection established, server listening on port %d", exp.Name, exp.RemotePort)

	// 心跳
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			if err := ws.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}()

	// 读取 DIAL 请求
	for {
		msgType, data, err := ws.ReadMessage()
		if err != nil {
			return fmt.Errorf("control read: %w", err)
		}
		if msgType != websocket.TextMessage {
			continue
		}
		msg := string(data)
		if len(msg) > 5 && msg[:5] == "DIAL:" {
			sid := msg[5:]
			log.Printf("[client] expose [%s] received DIAL request for session %s", exp.Name, sid)
			go clientDialBack(exp, server, sid)
		}
	}
}

func clientDialBack(exp ExposeDef, server *ServerDef, sid string) {
	localConn, err := net.DialTimeout("tcp", exp.Backend, 10*time.Second)
	if err != nil {
		log.Printf("[client] expose [%s] [%s] failed to connect local backend %s: %v", exp.Name, sid, exp.Backend, err)
		return
	}

	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: server.Insecure},
		HandshakeTimeout: 10 * time.Second,
	}
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+server.Token)
	headers.Set("X-Tunnel-Type", "reverse-data")
	headers.Set("X-Session-ID", sid)

	ws, _, err := dialer.Dial(httpToWS(server.URL), headers)
	if err != nil {
		log.Printf("[client] expose [%s] [%s] data dial failed: %v", exp.Name, sid, err)
		localConn.Close()
		return
	}

	log.Printf("[client] expose [%s] [%s] bridging local %s <-> server", exp.Name, sid, exp.Backend)
	wsConn := &wsNetConn{ws: ws}
	bridge(localConn, wsConn, sid)
}

func clientListen(tunnel TunnelDef, server *ServerDef) error {
	ln, err := net.Listen("tcp", tunnel.Listen)
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[client] [%s] accept error: %v", tunnel.Listen, err)
			continue
		}
		sid := newSessionID()
		log.Printf("[client] [%s] new connection  session=%s", tunnel.Listen, sid)
		go clientHandleConn(conn, sid, tunnel.ProxyName, server)
	}
}

func clientHandleConn(local net.Conn, sid, proxyName string, server *ServerDef) {
	defer local.Close()

	dialer := websocket.Dialer{
		TLSClientConfig:  &tls.Config{InsecureSkipVerify: server.Insecure},
		HandshakeTimeout: 10 * time.Second,
	}
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+server.Token)
	headers.Set("X-Session-ID", sid)
	headers.Set("X-Proxy-Name", proxyName)

	ws, _, err := dialer.Dial(httpToWS(server.URL), headers)
	if err != nil {
		log.Printf("[client] [%s] WebSocket dial failed: %v", sid, err)
		return
	}
	defer ws.Close()

	log.Printf("[client] [%s] connected to %s [%s]", sid, server.Name, proxyName)
	wsConn := &wsNetConn{ws: ws}
	bridge(local, wsConn, sid)
	log.Printf("[client] [%s] session closed", sid)
}

// ================================================================
// wsNetConn：把 WebSocket 包装成 net.Conn
// ================================================================

type wsNetConn struct {
	ws      *websocket.Conn
	readBuf []byte
	mu      sync.Mutex
}

func (c *wsNetConn) Read(b []byte) (int, error) {
	for {
		if len(c.readBuf) > 0 {
			n := copy(b, c.readBuf)
			c.readBuf = c.readBuf[n:]
			return n, nil
		}
		msgType, data, err := c.ws.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				return 0, io.EOF
			}
			return 0, err
		}
		if msgType != websocket.BinaryMessage {
			continue
		}
		c.readBuf = data
	}
}

func (c *wsNetConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.ws.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *wsNetConn) Close() error {
	c.ws.WriteMessage(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
	return c.ws.Close()
}

func (c *wsNetConn) LocalAddr() net.Addr                { return c.ws.LocalAddr() }
func (c *wsNetConn) RemoteAddr() net.Addr               { return c.ws.RemoteAddr() }
func (c *wsNetConn) SetDeadline(t time.Time) error      { return c.ws.SetReadDeadline(t) }
func (c *wsNetConn) SetReadDeadline(t time.Time) error  { return c.ws.SetReadDeadline(t) }
func (c *wsNetConn) SetWriteDeadline(t time.Time) error { return c.ws.SetWriteDeadline(t) }

// ================================================================
// bridge：双向转发
// ================================================================

func bridge(a, b net.Conn, sid string) {
	defer a.Close()
	defer b.Close()

	done := make(chan struct{}, 2)
	copy := func(dst, src net.Conn) {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				if _, werr := dst.Write(buf[:n]); werr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}

	go copy(a, b)
	go copy(b, a)
	<-done
}

// ================================================================
// 工具函数
// ================================================================

func httpToWS(u string) string {
	switch {
	case len(u) >= 8 && u[:8] == "https://":
		return "wss://" + u[8:]
	case len(u) >= 7 && u[:7] == "http://":
		return "ws://" + u[7:]
	}
	return u
}

func newSessionID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// ================================================================
// 入口
// ================================================================

func main() {
	cfgFile := flag.String("config", "config.yaml", "Path to config file")
	flag.Parse()

	data, err := os.ReadFile(*cfgFile)
	if err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	switch cfg.Mode {
	case "server":
		runServer(&cfg)
	case "client":
		runClient(&cfg)
	case "both":
		go runServer(&cfg)
		time.Sleep(500 * time.Millisecond)
		runClient(&cfg)
	default:
		log.Fatalf("Invalid mode: %q — must be 'server', 'client', or 'both'", cfg.Mode)
	}
}
