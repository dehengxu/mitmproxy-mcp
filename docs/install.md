# 安装指南

## 前置

| 依赖 | 用途 | 检查 |
|---|---|---|
| Python 3.13+ | 两个 server 都要求 3.13+（spectral 3.12–3.13） | `python3 --version` |
| [uv](https://docs.astral.sh/uv/) | 安装/管理 Python 包 | `uv --version` |
| [mitmproxy](https://mitmproxy.org/) 12.2.3+ | 代理内核（两个 server 都依赖它） | `mitmproxy --version` |
| git | 源码安装 u33pk | `git --version` |

## 一条命令

```bash
git clone https://github.com/dehengxu/mitmproxy-mcp.git
cd mitmproxy-mcp
./scripts/install.sh
```

脚本是幂等的，可重复执行。要看它会做什么而不实际执行：

```bash
./scripts/install.sh --check
```

## 脚本具体做了什么

1. **mitmproxy** — 若未安装，通过 asdf 插件装（若已装则跳过）。
2. **spectral** — `uv tool install --with "mcp<2" mitmproxy-mcp`，装到 `~/.local/share/uv/tools/mitmproxy-mcp/`。
3. **u33pk** — 从 GitHub 源码 clone 到 `~/Projects/personal/mcp-servers/mitmproxy-mcp-u33pk`，`uv venv` + `uv pip install -e ".[dev]"`。
4. **wrapper** — 复制到 `~/.local/bin/mitmproxy-mcp-spectral` 和 `~/.local/bin/mitmproxy-mcp-u33pk`。
5. **skill** — 复制到 `~/.agents/skills/mitmproxy-mcp/`。
6. **CA 检查** — 确认 mitmproxy CA 存在且已被系统钥匙串信任。

## `mcp<2` 是必须的（不是可选）

`mcp` 2.x 把 `FastMCP` 改名成 `MCPServer`，而两个上游项目用的都是 v1 API。装上 mcp 2.x 会立刻崩：

```
ModuleNotFoundError: No module named 'mcp.server.fastmcp'
```

两个上游都只声明了 `mcp>=1.x` **没有上限**，所以 pip/uv 默认会装最新的 2.x。

- spectral 0.8.0 已经在 `pyproject.toml` 里写死了 `mcp>=1.25.0,<2.0.0`，装它不再需要额外处理。
- u33pk 仍是无上限的 `mcp>=1.28.0`，本仓库已把它改成 `mcp>=1.28.0,<2.0.0`（见 [upstream-fixes.md](upstream-fixes.md)）。从源码安装仍建议显式 `uv pip install "mcp<2"` 兜底。

## MCP 客户端配置

脚本结束时会打印可直接粘贴的配置：

```json
{
  "mcpServers": {
    "mitmproxy-spectral": {
      "command": "~/.local/bin/mitmproxy-mcp-spectral",
      "args": []
    },
    "mitmproxy-u33pk": {
      "command": "~/.local/bin/mitmproxy-mcp-u33pk",
      "args": []
    }
  }
}
```

> 用绝对路径，客户端不会展开 `~`。

## CA 证书（抓 HTTPS 必需）

mitmproxy 首次启动时自动在 `~/.mitmproxy/` 生成 CA。两个 server 共用同一个 confdir，**装一次就够**。

macOS 上必须装进**系统钥匙串**，装进登录钥匙串对 Safari 无效：

```bash
sudo security add-trusted-cert -d -r trustRoot -p ssl \
  -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem
```

验证：

```bash
security dump-trust-settings -d | grep -A2 mitmproxy
```

## 自检

```bash
./scripts/verify.sh
```

会验证 wrapper 可执行、两个 server 都能响应 `tools/list`、端口状态、CA 信任状态。

## 自定义安装路径

所有路径都可用环境变量覆盖：

| 变量 | 默认值 |
|---|---|
| `BIN_DIR` | `~/.local/bin` |
| `SKILLS_DIR` | `~/.agents/skills` |
| `STATE_DIR` | `~/.local/state/mitmproxy-mcp` |
| `U33PK_HOME` | `~/Projects/personal/mcp-servers/mitmproxy-mcp-u33pk` |
| `SPECTRAL_BIN` | `~/.local/share/uv/tools/mitmproxy-mcp/bin/mitmproxy-mcp` |
| `U33PK_BIN` | `$U33PK_HOME/.venv/bin/mitmproxy-mcp` |

wrapper 也支持用 `SPECTRAL_BIN` / `U33PK_BIN` 指向别处的可执行文件。

## 卸载

```bash
uv tool uninstall mitmproxy-mcp
rm -rf ~/Projects/personal/mcp-servers/mitmproxy-mcp-u33pk
rm -f ~/.local/bin/mitmproxy-mcp-spectral ~/.local/bin/mitmproxy-mcp-u33pk
rm -rf ~/.agents/skills/mitmproxy-mcp
rm -rf ~/.local/state/mitmproxy-mcp
```
