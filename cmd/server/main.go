package main

import (
	"crypto/tls"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"gopkg.in/yaml.v3"
)

// ---- 配置结构 ----

type ServerConfig struct {
	Listen  string        `yaml:"listen"`
	TLS     TLSConfig     `yaml:"tls"`
	Token   string        `yaml:"token"`
	Path    string        `yaml:"path"`
	Proxies []ProxyConfig `yaml:"proxies"`
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
	Backend string `yaml:"backend"`
}

// ---- Session ----

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
var cfg ServerConfig
var proxyMap = map[string]string{}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  32 * 1024,
	WriteBufferSize: 32 * 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true // 生产环境建议校验 Origin
	},
}

func main() {
	cfgFile := flag.String("config", "server.yaml", "Path to config file")
	flag.Parse()

	data, err := os.ReadFile(*cfgFile)
	if err != nil {
		log.Fatalf("Failed to read config: %v", err)
	}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	if cfg.Path == "" {
		cfg.Path = "/tunnel"
	}
	if cfg.Token == "" {
		log.Fatal("token must be set in config")
	}
	if len(cfg.Proxies) == 0 {
		log.Fatal("at least one proxy must be configured")
	}
	for _, p := range cfg.Proxies {
		proxyMap[p.Name] = p.Backend
		log.Printf("Proxy [%s] -> %s", p.Name, p.Backend)
	}

	mux := http.NewServeMux()
	mux.HandleFunc(cfg.Path, authMiddleware(handleWebSocket))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	srv := &http.Server{
		Addr:    cfg.Listen,
		Handler: mux,
	}

	if cfg.TLS.Enabled {
		tlsCfg, err := buildTLSConfig(cfg.TLS)
		if err != nil {
			log.Fatalf("TLS config error: %v", err)
		}
		srv.TLSConfig = tlsCfg
		log.Printf("Server starting (TLS) on %s  path=%s", cfg.Listen, cfg.Path)
		if err := srv.ListenAndServeTLS("", ""); err != nil {
			log.Fatal(err)
		}
	} else {
		log.Printf("Server starting (HTTP) on %s  path=%s", cfg.Listen, cfg.Path)
		if err := srv.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
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

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+cfg.Token {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next(w, r)
	}
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
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

	// 升级到 WebSocket
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}

	// 连接后端
	backendConn, err := net.DialTimeout("tcp", backend, 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to backend %s: %v", backend, err)
		ws.WriteMessage(websocket.CloseMessage, 
			websocket.FormatCloseMessage(websocket.CloseInternalServerErr, "Backend unavailable"))
		ws.Close()
		return
	}

	sid := r.Header.Get("X-Session-ID")
	if sid == "" {
		sid = "unknown"
	}

	sess := &session{
		backend: backendConn,
		ws:      ws,
	}
	sessions.Store(sid, sess)
	log.Printf("[%s] New session [%s] -> %s", sid, proxyName, backend)

	// 双向转发
	var wg sync.WaitGroup
	wg.Add(2)

	// WebSocket -> Backend
	go func() {
		defer wg.Done()
		defer sess.close()
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
			if _, err := backendConn.Write(data); err != nil {
				log.Printf("[%s] Backend write error: %v", sid, err)
				return
			}
		}
	}()

	// Backend -> WebSocket
	go func() {
		defer wg.Done()
		defer sess.close()
		buf := make([]byte, 32*1024)
		for {
			n, err := backendConn.Read(buf)
			if n > 0 {
				if err := ws.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
					log.Printf("[%s] WS write error: %v", sid, err)
					return
				}
			}
			if err != nil {
				if err != io.EOF {
					log.Printf("[%s] Backend read error: %v", sid, err)
				}
				return
			}
		}
	}()

	wg.Wait()
	sessions.Delete(sid)
	log.Printf("[%s] Session closed", sid)
}
