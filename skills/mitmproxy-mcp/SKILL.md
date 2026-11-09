---
name: mitmproxy-mcp
description: 用 mitmproxy MCP server 抓取、检查、重放、修改 HTTP/HTTPS/WebSocket 流量。单一入口暴露两个互补实现（Spectral 细粒度工具 / u33pk composite 工具），共 37 个工具，可同时运行、端口隔离。触发词：mitmproxy、抓包、流量分析、API 逆向、重放请求、mock 接口、OpenAPI 导出、websocket 注入、自定义加解密。
---

# mitmproxy MCP 双实现使用约定

本机通过**单一 MCP 入口** `mitmproxy-mcp` 同时挂起两套互补实现。**不是二选一，两个都可随时用。**

## 工具名前缀（重要）

统一入口下所有工具都带来源前缀，调用时**必须带前缀**：

| 前缀 | 后端 | 工具数 | 风格 |
|---|---|---|---|
| `spectral_` | snapspecter/mitmproxy-mcp | 25 | 细粒度，一函数一动作 |
| `u33pk_` | u33pk/mitmproxy-mcp | 12 | composite（`xxx_ctl(cmd=...)`） |

例：

- `spectral_start_proxy(port=8081)` — 不是 `start_proxy(port=8081)`
- `u33pk_proxy_ctl(cmd="start", port=8082)` — 不是 `proxy_ctl(cmd="start")`
- `spectral_get_traffic_summary(limit=20)`
- `u33pk_http_ctl(cmd="list", limit=20)`

## 端口分配（必须遵守）

两个后端默认都监听 8080，直接用默认值会撞车。统一入口已固定隔离：

| 后端 | 代理端口 | mitmweb 端口 |
|---|---|---|
| spectral | **8081** | — |
| u33pk | **8082** | 8083 |

启动代理时**必须显式传端口**，不要用默认值 8080。

- spectral：`spectral_start_proxy(port=8081)`
- u33pk：`u33pk_proxy_ctl(cmd="start", port=8082, host="127.0.0.1")`
- u33pk 开图形界面：`u33pk_proxy_ctl(cmd="start", port=8082, webui=True, web_port=8083)`

两个代理可同时运行，各自独立抓包，互不串流（已实测）。

## 选型

**默认用 spectral**（`spectral_*`）。理由：工具命名直白、`flow_id` 就是 UUID 字符串没有类型陷阱，且独有 OpenAPI 导出 / 认证模式检测 / 爬虫代码生成 / fuzzing / 会话变量。

**用 u33pk 的场景**（`u33pk_*`）：WebSocket 注入、自定义加解密脚本（`u33pk_crypt_ctl`）、mock server 回放（`u33pk_mock_server_ctl`）、mitmweb 图形界面、或用只读 MCP resource 省 token。

## u33pk 的坑（实测踩过）

1. **`flow_id` 必须是整数 `store_id`，不是 UUID。** `u33pk_http_ctl(cmd="list")` 返回的 `id` 字段是 UUID 字符串，但 `flow_id` 参数类型是 int —— 直接传 UUID 会报 pydantic `int_parsing` 错误，`get`/`replay` 全废。要用列表里的 `store_id`（从 1 开始）。

2. **`map_local_ctl` / `map_remote_ctl` 在上游是坏的。** 根因：FastMCP 已把 JSON dict 校验成 pydantic 模型，函数体内又 `**rule` 二次解包 → `TypeError: argument after ** must be a mapping`。
   本仓库已修复（改为 `model_validate(rule)`），**在统一入口下同样生效**。若用的是未经修复的上游版本，这两个工具 100% 崩溃，不要在它们身上浪费时间。

3. **规则类工具参数要靠 `tool_info` 查。** `u33pk_tool_info(tool_name, cmd)` 返回该命令的必填参数和示例，比猜快得多。规则对象必须含 `id` 和 `filter`；`u33pk_capture_rule_ctl` 用 `action`（`include`/`exclude`）而不是 `include` 布尔；`set_header` action 还需要 `target` 字段；`jsonpath` 必须是**数组**，如 `["$.data[0].id"]`。

## spectral 的坑

1. `flow_ids` 传**逗号分隔的字符串**，不是数组：`spectral_generate_scraper_code(flow_ids="id1,id2")`、`spectral_detect_auth_pattern(flow_ids="id1")`。
2. `spectral_add_interception_rule` 的 `action_type` 只接受 `inject_header` / `replace_body` / `block`。
3. `spectral_generate_scraper_code` 的 `target_framework` 只支持 `requests`（传 `python` 报 not supported）。

## 流量存储副作用

spectral 会在**当前工作目录**写 `mitm_mcp_traffic.db`（SQLite）。wrapper 已把工作目录固定到 `~/.local/state/mitmproxy-mcp/<flavor>/`，不会乱落到项目目录。

## CA 证书

两个后端都用默认 confdir `~/.mitmproxy`，共用**同一张 CA**（`mitmproxy-ca-cert.pem`），装一次即可。

要导出 CA 给别的设备：`u33pk_ca_ctl(cmd="export_ca", output_dir="/tmp")`。

> macOS 上装 CA 到**系统钥匙串**才有效（登录钥匙串对 Safari 不生效）：
> `sudo security add-trusted-cert -d -r trustRoot -p ssl -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem`

## 常用流程

```python
# 1. 起代理（选一个端口，别都用 8080）
spectral_start_proxy(port=8081)                   # spectral 后端
u33pk_proxy_ctl(cmd="start", port=8082)           # u33pk 后端

# 2. 让客户端走代理（浏览器/curl/App 都行）
#    代理地址 127.0.0.1:8081 或 127.0.0.1:8082

# 3. 看流量
spectral_get_traffic_summary(limit=20)            # spectral
u33pk_http_ctl(cmd="list", limit=20)              # u33pk

# 4. 停代理
spectral_stop_proxy()                             # spectral
u33pk_proxy_ctl(cmd="stop")                      # u33pk
```

## 深入参考

- `references/crypto_handler.md` — 自定义加解密脚本写法（u33pk `crypt_ctl`）
- 完整能力对比见仓库 `docs/comparison.md`
