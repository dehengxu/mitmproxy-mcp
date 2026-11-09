# 能力对比与选型

两个实现**功能互补**，不是二选一。以下全部为真实抓包实测结论。

> 通过统一入口 `mitmproxy-mcp` 使用时，工具名分别带 `spectral_` / `u33pk_` 前缀
> （如 `spectral_start_proxy`、`u33pk_http_ctl`）。下文表格里的工具名省略了前缀。

## 总览

| 维度 | Spectral | u33pk |
|---|---|---|
| 工具数量 | 25 个细粒度工具 | 12 个 composite 工具 |
| 只读 MCP resource | 无 | 7 个 |
| 工具风格 | 一函数一动作，参数直白 | `xxx_ctl(cmd=..., ...)` 复合式 |
| flow 标识 | UUID 字符串 | 整数 `store_id`（另附 UUID） |
| 状态存储 | SQLite `mitm_mcp_traffic.db`（路径硬编码在 CWD） | 内存 + 可导出 .mitm / HAR |
| 安装方式 | PyPI（`uv tool install`） | 源码（`uv pip install -e`） |

## Spectral 独有的能力

| 工具 | 作用 |
|---|---|
| `export_openapi_spec` | 从抓到的流量导出 OpenAPI 3.0.0 文档（实测产出完整 spec） |
| `detect_auth_pattern` | 识别 Bearer / JWT / API Key / session cookie / OAuth2 模式 |
| `generate_scraper_code` | 基于真实流量生成爬虫代码（`target_framework="requests"`） |
| `fuzz_endpoint` | 对 query 参数或 JSON 字段做轻量 fuzz |
| `set_session_variable` / `extract_session_variable` | 从一次响应取值、复用到后续重放 |
| `get_api_patterns` / `get_flow_schema` | 推断 API 模式与 JSON schema |
| `set_scope` | 限定抓包范围 |

## u33pk 独有的能力

| 工具 / resource | 作用 |
|---|---|
| `websocket_ctl` | WebSocket 列表、注入、主动连接、消息级规则（drop/改写） |
| `crypt_ctl` | 加载自定义加解密脚本（用户态加密应用，如前端 JS 加密） |
| `mock_server_ctl` | 用已抓流量起本地 mock server（实测 `mocked_flows=1`） |
| `u33pk_proxy_ctl(cmd="start", webui=True)` | 起 mitmweb 图形界面 |
| `capture_rule_ctl` | 按 filter 只抓特定域名 |
| `ca_ctl` | 导出 CA、配置上游 CA、mTLS 客户端证书 |
| `u33pk_http_ctl(cmd="export_har")` | 导出 HAR，兼容 Chrome DevTools / Charles |
| `u33pk_http_ctl(cmd="load")` | 加载 .mitm 文件做离线分析 |
| `u33pk_proxy_ctl(extra_options={"mode":["wireguard"]})` | WireGuard 透明代理，能抓 iOS/Android 的 QUIC/HTTP3 |
| `mitmproxy://flows/latest` 等 7 个 resource | 只读读取状态/流量/规则/事件，省 token |

### u33pk 的只读 MCP resource

`mitmproxy://proxy/status`、`mitmproxy://flows/latest`、`mitmproxy://flows/{id}`、`mitmproxy://config/rules`、`mitmproxy://events/latest`、`mitmproxy://crypto/scripts`、`mitmproxy://ca/status`。

无需调用工具即可读取，适合先快速看状态再决定要不要展开细节。

## 选型建议

**默认用 Spectral。** 工具命名直白、`flow_id` 就是 UUID 字符串没有类型陷阱，且独有 OpenAPI 导出 / 认证检测 / 爬虫代码生成 / fuzzing / 会话变量这些高价值分析能力。

**换 u33pk 的场景**：

- 需要 WebSocket 注入或消息级改写
- 目标应用在用户态做了加解密（`crypt_ctl`）
- 要用 mock server 回放
- 要 mitmweb 图形界面看流量
- 想用只读 resource 省 token
- 要抓手机端 QUIC（WireGuard 模式）

## 坑位速查

### u33pk

| 坑 | 说明 |
|---|---|
| `flow_id` 必须是整数 | `u33pk_http_ctl(cmd="list")` 返回的 `id` 是 UUID 字符串，但 `flow_id` 参数类型是 int。传 UUID 报 pydantic `int_parsing`，`get`/`replay` 全废。改用列表里的 `store_id`（从 1 开始） |
| `map_*_ctl` 崩溃 | 上游 bug（`rule` 二次解包），本仓库已修复为 `model_validate(rule)`，实测 add/list/clear 全部通过（见 [upstream-fixes.md](upstream-fixes.md)） |
| 规则参数要查 `tool_info` | 规则对象必须含 `id` + `filter`；`capture_rule_ctl` 用 `action`（include/exclude）而非布尔 `include`；`set_header` action 还需 `target`；`jsonpath` 必须是数组 |
| `--port` 是 SSE 端口 | CLI 的 `--port`（默认 8081）是 SSE 传输端口，**不是代理端口**。代理端口只能用 `u33pk_proxy_ctl(cmd="start", port=...)` |

### Spectral

| 坑 | 说明 |
|---|---|
| `flow_ids` 是字符串 | 传逗号分隔字符串，不是数组：`flow_ids="id1,id2"` |
| `action_type` 枚举有限 | 仅 `inject_header` / `replace_body` / `block` |
| `target_framework` 有限 | 仅支持 `requests` |
| SQLite 落 CWD | `mitm_mcp_traffic.db` 路径硬编码在当前工作目录。wrapper 已固定到 `~/.local/state/mitmproxy-mcp/spectral/` |

## 通用提示

- **任何参数报错，先调 `tool_info(tool_name, cmd)`**（u33pk 提供），它返回该命令的必填参数和示例，比猜快得多。
- 抓大 body 时用 `max_content_size` 限制，避免撑爆上下文。
- 看流量协议细节读 `flow["protocol"]`（HTTP 版本、ALPN、TLS 版本、SNI）。
