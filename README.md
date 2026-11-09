# mitmproxy-mcp

把两个互补的 [mitmproxy](https://mitmproxy.org/) MCP server 和配套 skill 整合到一个仓库：**统一安装、统一端口约定、统一 skill、带上游 bug 修复**。

| | Spectral | u33pk |
|---|---|---|
| 上游 | [snapspecter/mitmproxy-mcp](https://github.com/snapspecter/mitmproxy-mcp) | [u33pk/mitmproxy-mcp](https://github.com/u33pk/mitmproxy-mcp) |
| 许可 | MIT（仓库含 LICENSE） | MIT（README 声明，无 LICENSE 文件） |
| 工具风格 | 25 个细粒度工具 | 12 个 composite 工具 + 7 个只读 MCP resource |
| 工具数 | 25 | 12 + 7 resources |
| 独有能力 | OpenAPI 导出、认证模式检测、爬虫代码生成、fuzzing、会话变量 | WebSocket 注入、自定义加解密、mock server、mitmweb 图形界面、只读 resource |

两者**不是二选一**——功能互补，可同时运行，端口隔离互不串流。

## 统一入口（推荐）

本仓库提供**单一 MCP 入口**，同时挂起两套后端，共 37 个工具：

| 前缀 | 后端 | 工具数 | 独有能力 |
|---|---|---|---|
| `spectral_` | snapspecter/mitmproxy-mcp | 25 | OpenAPI 导出、认证模式检测、爬虫代码生成、fuzzing、会话变量 |
| `u33pk_` | u33pk/mitmproxy-mcp | 12 | WebSocket 注入、自定义加解密、mock server、mitmweb 图形界面、只读 resource |

工具名带来源前缀，调用时必须带（如 `spectral_start_proxy(port=8081)`、`u33pk_proxy_ctl(cmd="start", port=8082)`）。

两个后端各自保持独立代理端口，抓包会话互不干扰。

```json
{
  "mcpServers": {
    "mitmproxy-mcp": {
      "command": "~/.local/bin/mitmproxy-mcp-unified",
      "args": []
    }
  }
}
```

也可以继续用两个独立入口（`mitmproxy-mcp-spectral` / `mitmproxy-mcp-u33pk`），功能等价，只是不用带前缀。

## 快速开始

```bash
# 1. 克隆并安装（幂等，可重复执行）
git clone https://github.com/dehengxu/mitmproxy-mcp.git
cd mitmproxy-mcp
./scripts/install.sh

# 2. 自检：确认两个后端、统一入口、端口、CA 全部就绪
./scripts/verify.sh
```

脚本结束时会打印可直接粘贴的 MCP 客户端配置：

```json
{
  "mcpServers": {
    "mitmproxy-mcp": {
      "command": "~/.local/bin/mitmproxy-mcp-unified",
      "args": []
    }
  }
}
```

> `~` 不会被客户端展开，请改成绝对路径。

### 前置依赖

| 依赖 | 说明 |
|---|---|
| Python 3.13+ | 两个后端都要求 |
| [uv](https://docs.astral.sh/uv/) | 安装 Python 包 |
| [mitmproxy](https://mitmproxy.org/) 12.2.3+ | 代理内核（`install.sh` 会尝试用 asdf 装） |
| git | 源码安装 u33pk |

详细步骤、CA 证书安装、自定义路径见 [docs/install.md](docs/install.md)。

## 端口分配（固定约定）

两个 server 默认都监听 **8080**，直接用默认值会撞车。本仓库通过 wrapper 固定隔离：

| Server | 代理端口 | mitmweb | 启动命令（统一入口，前缀必带） |
|---|---|---|---|
| Spectral | **8081** | — | `spectral_start_proxy(port=8081)` |
| u33pk | **8082** | 8083 | `u33pk_proxy_ctl(cmd="start", port=8082)` |

启动代理时**必须显式传端口**，不要用默认 8080。

## 最小可跑示例

从零到抓到一条流量，五步：

```bash
# 1. 安装 + 自检
git clone https://github.com/dehengxu/mitmproxy-mcp.git
cd mitmproxy-mcp
./scripts/install.sh && ./scripts/verify.sh
```

```json
// 2. 注册到 MCP 客户端（command 用绝对路径，客户端不展开 ~）
{
  "mcpServers": {
    "mitmproxy-mcp": {
      "command": "/Users/you/.local/bin/mitmproxy-mcp-unified",
      "args": []
    }
  }
}
```

```python
# 3. 启动代理（两套后端任选或同时开；端口必须显式传，不要用默认 8080）
spectral_start_proxy(port=8081)                            # spectral 后端
u33pk_proxy_ctl(cmd="start", port=8082, host="127.0.0.1")  # u33pk 后端
```

```bash
# 4. 让流量走代理（CA 已装进系统钥匙串时可省 --cacert）
curl --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem -x http://127.0.0.1:8081 https://example.com
```

```python
# 5. 看流量、然后停掉
spectral_get_traffic_summary(limit=20)   # spectral 视角
u33pk_http_ctl(cmd="list", limit=20)     # u33pk 视角
spectral_stop_proxy()
u33pk_proxy_ctl(cmd="stop")
```

> 首次使用建议先只起一个后端。确认链路通畅后再叠加第二个——两个代理端口不同，
> 抓包会话互不串流，但同时开着会多占一份内存与一次 CA 协商。

## 重新安装与卸载

```bash
./scripts/install.sh --force      # 从 vendored 源码重装两个后端（修复环境损坏用）
./scripts/install.sh --uninstall  # 卸载本脚本装过的全部东西
./scripts/install.sh --check      # 只报告现状，不做任何改动
```

## 本仓库做的整合工作

1. **端口隔离与可移植**：`scripts/wrappers/` 下三个 wrapper（两个独立入口 + 一个统一入口），各自把工作目录固定到 `~/.local/state/mitmproxy-mcp/<flavor>/`（避免状态文件乱落），并通过同目录软链自定位上游可执行文件——wrapper 复制到任意目录都能工作。
2. **上游 bug 修复**：u33pk 的 `map_local_ctl` / `map_remote_ctl` 100% 崩溃，根因是 FastMCP 已把 JSON dict 校验成 pydantic 模型，函数体内又 `**rule` 二次解包。已改为 `model_validate(rule)`（同时兼容模型实例与 dict）。见 [docs/upstream-fixes.md](docs/upstream-fixes.md)。
3. **依赖约束收紧**：u33pk 的 `mcp>=1.28.0` 没有上限，而 `mcp 2.x` 把 `FastMCP` 改名为 `MCPServer`，装上即崩。已收紧为 `mcp>=1.28.0,<2.0.0`。
4. **统一 skill**：`skills/mitmproxy-mcp/` 一份 skill 覆盖两个 server，含端口表、选型建议与两边各自的参数坑。

## CI

仓库带一份 GitHub Actions workflow（`scripts/ci.yml`）：静态检查 + map 工具回归测试。

它默认**不在 git 里**，因为推送 `.github/workflows/*` 要求 token 带 `workflow` scope，
缺 scope 时 GitHub 会直接拒绝 push。恢复方式：

```bash
gh auth refresh -h github.com -s workflow   # 一次性授权
./scripts/enable-ci.sh                        # 恢复并推送 workflow
```

回归测试也可以本地直接跑：

```bash
python3 scripts/test_map_tools.py ~/.local/bin/mitmproxy-mcp-u33pk
```

## 上游引用

本仓库 vendoring 两份上游源码，**精确基线 commit、本地补丁清单、同步流程**记录在 [UPSTREAM.md](UPSTREAM.md)。

| 上游 | 路径 | 许可 | 基线 | 本地改动 |
|---|---|---|---|---|
| [snapspecter/mitmproxy-mcp](https://github.com/snapspecter/mitmproxy-mcp) | `spectral/` | MIT | `919bf0f4` (v0.8.0) | 无 |
| [u33pk/mitmproxy-mcp](https://github.com/u33pk/mitmproxy-mcp) | `u33pk/` | MIT | `307e6912` (2026-08-29) | 2 处（见 UPSTREAM.md） |

维护者请先读 [UPSTREAM.md](UPSTREAM.md)。

## 目录结构

```
mitmproxy-mcp/
├── UPSTREAM.md          # 上游引用记录：基线 commit、补丁清单、同步流程
├── NOTICE.md            # 第三方归属声明
├── spectral/            # 上游 A 源码（snapspecter, MIT）
├── u33pk/               # 上游 B 源码（u33pk, MIT，含本仓库的修复）
├── skills/
│   └── mitmproxy-mcp/   # 统一 skill（装到 ~/.agents/skills/）
├── scripts/
│   ├── install.sh       # 一键安装
│   ├── wrappers/        # 三个 wrapper 脚本（spectral / u33pk / unified）
│   └── verify.sh        # 装完自检
└── docs/
    ├── install.md       # 安装与配置
    ├── comparison.md    # 能力对比与选型
    ├── upstream-fixes.md# 本仓库对上游做的改动
    └── troubleshooting.md
```

## 许可

本仓库自有内容（`scripts/`、`docs/`、`skills/`）为 MIT，见 [LICENSE](LICENSE)。

两份 vendored 上游源码保持各自的许可与归属声明：
- `spectral/` — MIT, Copyright (c) 2025 SnapSpecter，见 `spectral/LICENSE`
- `u33pk/` — MIT，版权归 u33pk，见 `u33pk/README.md` 末尾「许可证」章节

## 致谢

- [snapspecter/mitmproxy-mcp](https://github.com/snapspecter/mitmproxy-mcp) — MIT
- [u33pk/mitmproxy-mcp](https://github.com/u33pk/mitmproxy-mcp) — MIT
- [mitmproxy](https://github.com/mitmproxy/mitmproxy) — MIT
