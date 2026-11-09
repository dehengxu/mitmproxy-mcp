# 故障排查

## `ModuleNotFoundError: No module named 'mcp.server.fastmcp'`

**原因**：`mcp` 2.x 把 `FastMCP` 改名 `MCPServer`，两个上游用的都是 v1 API。两个上游都只声明 `mcp>=1.x` 无上限，装 2.x 必崩。

**修复**：

```bash
# spectral
uv tool install --reinstall --with "mcp<2" mitmproxy-mcp

# u33pk
cd ~/Projects/personal/mcp-servers/mitmproxy-mcp-u33pk
uv pip install "mcp<2"
```

## `MapRemoteRule() argument after ** must be a mapping, not MapRemoteRule`

**原因**：u33pk 上游 bug，见 [upstream-fixes.md](upstream-fixes.md)。

**修复**：用本仓库 vendoring 的版本，或把上游的 `MapRemoteRule(**rule)` 改成 `MapRemoteRule.model_validate(rule)`。

## `int_parsing` / `flow_id` 报错

**原因**：u33pk 的 `flow_id` 是整数，但 `http_ctl(cmd="list")` 返回的 `id` 字段是 UUID 字符串。

**修复**：用列表里的 `store_id` 字段（从 1 开始），不是 `id`。

## HTTPS 抓不到 / 浏览器报「证书不受信任」

**原因**：CA 没装，或装错钥匙串。

**检查**：

```bash
ls ~/.mitmproxy/mitmproxy-ca-cert.pem
security dump-trust-settings -d | grep -A2 mitmproxy
```

**注意**：装进**登录钥匙串**对 Safari 无效，必须装**系统钥匙串**：

```bash
sudo security add-trusted-cert -d -r trustRoot -p ssl \
  -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem
```

## 「地址不受信任」但信任设置里明明有

**原因**：这是**主机名不匹配**（错误码 `-67602`），不是信任问题。

**原因 2**：如果签发出来的证书颁发者对不上，通常是 CA basename 传错。`CertStore.from_store(path, basename, key_size)` 会拼 `{basename}-ca.pem`，basename 必须传 `"mitmproxy"` 而不是 `"mitmproxy-ca"`——传错会静默新建一张 CA（CN=mitmproxy-ca），签发者就对不上了。

## 两个代理端口冲突 / 流量串台

**原因**：两个 server 默认都监听 8080。

**修复**：始终显式传端口。spectral 用 `start_proxy(port=8081)`，u33pk 用 `proxy_ctl(cmd="start", port=8082)`；u33pk 开图形界面再加 `web_port=8083`。

## SQLite 建表失败（`CREATE TABLE IF NOT EXISTS flows`）

**原因**：spectral 的 traffic db 路径硬编码在 CWD。某些受限环境（如只读目录、或沙箱禁止在工作区外创建文件）会失败。

**修复**：在可写目录启动。本仓库的 wrapper 已把 CWD 固定到 `~/.local/state/mitmproxy-mcp/spectral/`。

## `No module named 'websockets'`

u33pk 的 `websocket_ctl` 需要 `websockets`，它在 `[dev]` extras 里，源码安装时带上：

```bash
uv pip install -e ".[dev]"
```

## mitmproxy 本体装不上（asdf 插件失效）

官方 `asdf-mitmproxy` 插件会从 `downloads.mitmproxy.org` 下载二进制，该地址对 9.0.1–12.3.1 全部 404——官方已改为只发 PyPI。

**修复**：用 PyPI 路线装（requires-python >= 3.12），插件的 `install_version` 改为建 venv + `pip install` + 建 shim。见 [README](../README.md) 的致谢部分与本仓库 issue。

## `crypt_ctl` 加载脚本报错

`crypt_ctl(cmd="load")` 会执行指定路径的 Python 代码，只加载可信脚本。报错可查 `mitmproxy://crypto/scripts` resource 看错误计数与最近错误。

## 抓不到手机流量

u33pk 支持 WireGuard 透明代理模式，能捕获 QUIC/HTTP3：

```python
proxy_ctl(cmd="start", host="0.0.0.0", port=51820, extra_options={"mode": ["wireguard"]})
proxy_ctl(cmd="wireguard_config")   # 返回给客户端的 wireguard_config INI
```

客户端需信任 mitmproxy CA 才能解密。
