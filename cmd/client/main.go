package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v3"
)

// ---- 配置结构 ----

type ClientConfig struct {
	Servers []ServerDef `yaml:"servers"`
	Proxies []ProxyDef  `yaml:"proxies"`
}

type ServerDef struct {
	Name     string `yaml:"name"`
	URL      string `yaml:"url"`
	Token    string `yaml:"token"`
	Insecure bool   `yaml:"insecure"`
}

type ProxyDef struct {
	Listen    string `yaml:"listen"`
	Server    string `yaml:"server"`
	ProxyName string `yaml:"proxy_name"`
}

var cfg ClientConfig
var serverMap = map[string]*ServerDef{}

func main() {
	cfgFile := flag.String("config", "client.yaml", "Path to config file")
	flag.Parse()

	data, err := os.ReadFile(*cfgFile)
	if err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	if len(cfg.Servers) == 0 {
		log.Fatal("at least one server must be configured")
	}
	if len(cfg.Proxies) == 0 {
		log.Fatal("at least one proxy must be configured")
	}

	for i := range cfg.Servers {
		s := &cfg.Servers[i]
		if s.Name == "" || s.URL == "" || s.Token == "" {
			log.Fatalf("server config incomplete: %+v", s)
		}
		serverMap[s.Name] = s
		log.Printf("Server [%s]: %s", s.Name, s.URL)
	}

	done := make(chan struct{})
	for _, p := range cfg.Proxies {
		srv, ok := serverMap[p.Server]
		if !ok {
			log.Fatalf("Proxy %s references unknown server: %s", p.Listen, p.Server)
		}
		go func(proxy ProxyDef, server *ServerDef) {
			if err := listenProxy(proxy, server); err != nil {
				log.Fatalf("Proxy [%s] failed: %v", proxy.Listen, err)
			}
		}(p, srv)
		log.Printf("Proxy [%s] -> server=%s proxy=%s", p.Listen, p.Server, p.ProxyName)
	}
	<-done
}

func listenProxy(proxy ProxyDef, server *ServerDef) error {
	ln, err := net.Listen("tcp", proxy.Listen)
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[%s] Accept error: %v", proxy.Listen, err)
			continue
		}
		sid := newSessionID()
		log.Printf("[%s] New connection  session=%s", proxy.Listen, sid)
		go handleConn(conn, sid, proxy.ProxyName, server)
	}
}

func handleConn(local net.Conn, sid, proxyName string, server *ServerDef) {
	defer local.Close()

	// 建立 WebSocket 连接
	wsURL := httpToWS(server.URL)
	dialer := websocket.Dialer{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: server.Insecure},
		HandshakeTimeout: 10 * time.Second,
	}
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+server.Token)
	headers.Set("X-Session-ID", sid)
	headers.Set("X-Proxy-Name", proxyName)

	ws, _, err := dialer.Dial(wsURL, headers)
	if err != nil {
		log.Printf("[%s] WebSocket dial failed: %v", sid, err)
		return
	}
	defer ws.Close()

	log.Printf("[%s] WebSocket connected to %s [%s]", sid, server.Name, proxyName)

	done := make(chan struct{}, 2)

	// Local -> WebSocket
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := local.Read(buf)
			if n > 0 {
				if err := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
					log.Printf("[%s] WS write error: %v", sid, err)
					return
				}
			}
			if err != nil {
				ws.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
				return
			}
		}
	}()

	// WebSocket -> Local
	go func() {
		defer func() { done <- struct{}{} }()
		for {
			msgType, data, err := ws.ReadMessage()
			if err != nil {
				if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
					log.Printf("[%s] WS read error: %v", sid, err)
				}
				return
			}
			if msgType != websocket.BinaryMessage {
				continue
			}
			if _, err := local.Write(data); err != nil {
				log.Printf("[%s] Local write error: %v", sid, err)
				return
			}
		}
	}()

	// 任意一端断开就结束
	<-done
	log.Printf("[%s] Session closed", sid)
}

// httpToWS 把 http:// 换成 ws://，https:// 换成 wss://
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

// 仅用于引入 io 包
var _ = io.EOF
