# rdp-tunnel

TCP over WebSocket/TLS 隧道工具，支持正向代理和反向代理（内网穿透）。

## 特性

- **协议伪装**：流量伪装成 HTTPS/WebSocket，不易被防火墙识别
- **内网穿透**：客户端 `expose` + 服务端 `@name` 路由，无需修改服务端配置
- **动态端口**：客户端通过 `remote_port` 决定服务端监听端口，服务端动态开放
- **正向代理**：支持访问服务端本机服务
- **TLS 支持**：文件路径或 PEM 内容两种方式配置证书
- **单二进制**：一个文件通过配置文件决定运行模式（server/client/both）

## 使用场景

```
家里电脑 ──WSS──▶ 云服务器:8443 ◀──WSS── 公司电脑
  (tunnel client)   (tunnel server)   (tunnel client)
  mstsc 127.0.0.1:13389               expose 127.0.0.1:3389
```

两段流量都是 WSS（WebSocket over TLS），伪装成 HTTPS。

## 快速开始

### 生成自签证书（云服务器）

```bash
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
  -days 3650 -nodes -subj "/CN=tunnel"
```

### 云服务器 `server.yaml`

```yaml
mode: server
listen: "0.0.0.0:8443"
token: "your-secret-token"   # openssl rand -hex 32
path: "/api/v1/metrics"

tls:
  enabled: true
  cert_file: "server.crt"
  key_file: "server.key"

proxies:
  - name: home-to-office
    backend: "@office-rdp"   # @ 指向反向代理名称
```

### 公司电脑 `client.yaml`（内网，暴露 RDP）

```yaml
mode: client

servers:
  - name: cloud
    url: "https://云服务器IP:8443/api/v1/metrics"
    token: "your-secret-token"
    insecure: true

expose:
  - name: office-rdp
    backend: "127.0.0.1:3389"
    remote_port: 13389   # 服务端动态监听此端口
    server: cloud
```

### 家里电脑 `client.yaml`

```yaml
mode: client

servers:
  - name: cloud
    url: "https://云服务器IP:8443/api/v1/metrics"
    token: "your-secret-token"
    insecure: true

tunnels:
  - listen: "127.0.0.1:13389"
    server: cloud
    proxy_name: home-to-office
```

家里电脑启动 tunnel 后，`mstsc /v:127.0.0.1:13389` 即可连接公司电脑。

## 运行

```bash
./tunnel -config server.yaml   # 服务端
./tunnel -config client.yaml   # 客户端
```

## 配置说明

### 服务端

| 字段 | 说明 |
|------|------|
| `mode` | `server` / `client` / `both` |
| `listen` | 监听地址 |
| `token` | 认证 token |
| `path` | WebSocket 路径（伪装用） |
| `proxies[].name` | 代理名称 |
| `proxies[].backend` | 目标地址，`@name` 表示指向反向代理 |

### 客户端

| 字段 | 说明 |
|------|------|
| `servers[].url` | 服务端地址（http/https） |
| `servers[].insecure` | 跳过证书验证（自签证书时用） |
| `tunnels[].listen` | 本地监听地址 |
| `tunnels[].proxy_name` | 对应服务端 `proxies.name` |
| `expose[].name` | 暴露名称，对应服务端 `@name` |
| `expose[].backend` | 本地服务地址 |
| `expose[].remote_port` | 服务端动态监听的端口 |

## 与 frp / stunnel 对比

| 特性 | rdp-tunnel | frp | stunnel |
|------|-----------|-----|---------|
| 内网穿透 | ✅ | ✅ | ❌ |
| 协议伪装 | ✅ HTTPS | ❌ 自定义协议 | ⚠️ 仅加密 |
| 动态端口 | ✅ 客户端决定 | ✅ | ❌ |
| UDP 支持 | ❌ | ✅ | ❌ |
| DPI 抗性 | 高 | 低 | 中 |
