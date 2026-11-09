# 安装指南

## 前置

| 依赖 | 用途 | 检查 |
|---|---|---|
| Python 3.13+ | 两个 server 都要求 3.13+（spectral 3.12–3.13） | `python3 --version` |
| [uv](https://docs.astral.sh/uv/) | 安装/管理 Python 包 | `uv --version` |
| [mitmproxy](https://mitmproxy.org/) 12.2.3+ | 代理内核（两个 server 都依赖它） | `mitmproxy --version` |
| git | 克隆本仓库 | `git --version` |

## 一条命令

```bash
git clone https://github.com/dehengxu/mitmproxy-mcp.git
cd mitmproxy-mcp
./scripts/install.sh
```

脚本是幂等的，可重复执行。

| 参数 | 作用 |
|---|---|
| `--check` | 只报告现状，**不改动任何文件** |
| `--force` | 从 vendored 源码重装两个后端（环境被搞坏、依赖被升级成 mcp 2.x 时用） |
| `--uninstall` | 卸载本脚本装过的全部东西 |
| `--no-mitmproxy` | 跳过 mitmproxy 本体的安装检查 |

```bash
./scripts/install.sh --check      # 只看现状
./scripts/install.sh --force      # 重装后端
./scripts/install.sh --uninstall  # 卸载
```

## 脚本具体做了什么

1. **mitmproxy** — 若未安装，通过 asdf 插件装（若已装则跳过）。
2. **spectral** — `uv tool install --with "mcp<2" "$REPO_ROOT/spectral"`，从**本仓库 vendored 源码**安装，装到 `~/.local/share/uv/tools/mitmproxy-mcp/`。
3. **u33pk** — 从**本仓库 vendored 源码**复制到 `~/Projects/personal/mcp-servers/mitmproxy-mcp-u33pk`，`uv venv` + `uv pip install -e ".[dev]"` + `uv pip install "mcp<2"`。
4. **wrapper** — 复制三个到 `~/.local/bin/`：
   `mitmproxy-mcp-spectral`、`mitmproxy-mcp-u33pk`（两个独立入口）、
   `mitmproxy-mcp-unified`（统一入口），并把两个上游可执行文件软链为
   `mitmproxy-mcp-spectral-upstream` / `mitmproxy-mcp-u33pk-upstream`
   与 wrapper 并排——wrapper 据此自定位，安装到任何目录都能工作。
5. **skill** — 复制到 `~/.agents/skills/mitmproxy-mcp/`。
6. **CA 检查** — 确认 mitmproxy CA 存在且已被系统钥匙串信任。

> 两个后端都从**本仓库内的 vendored 源码**安装，不从 PyPI 装、也不去 GitHub 现拉。
> 这样装到的必然是**带本仓库补丁、且 pin 了 `mcp<2`** 的那一版，不会踩上游的坑。

## `mcp<2` 是必须的（不是可选）

`mcp` 2.x 把 `FastMCP` 改名成 `MCPServer`，而两个上游项目用的都是 v1 API。装上 mcp 2.x 会立刻崩：

```
ModuleNotFoundError: No module named 'mcp.server.fastmcp'
```

两个上游都只声明了 `mcp>=1.x` **没有上限**，所以 pip/uv 默认会装最新的 2.x。

- spectral 0.8.0 已经在 `pyproject.toml` 里写死了 `mcp>=1.25.0,<2.0.0`，装它不再需要额外处理。
- u33pk 仍是无上限的 `mcp>=1.28.0`，本仓库已把它改成 `mcp>=1.28.0,<2.0.0`（见 [upstream-fixes.md](upstream-fixes.md)）。从源码安装仍建议显式 `uv pip install "mcp<2"` 兜底。

## MCP 客户端配置

### 统一入口（推荐）

一个条目暴露两套后端的全部 37 个工具，工具名带来源前缀：

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

| 前缀 | 后端 | 工具数 |
|---|---|---|
| `spectral_` | snapspecter/mitmproxy-mcp | 25 |
| `u33pk_` | u33pk/mitmproxy-mcp | 12 |

### 两个独立入口

功能等价，只是不用带前缀：

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

| 变量 | 默认值 | 作用 |
|---|---|---|
| `BIN_DIR` | `~/.local/bin` | wrapper 与软链的安装目录 |
| `SKILLS_DIR` | `~/.agents/skills` | skill 安装目录 |
| `STATE_DIR` | `~/.local/state/mitmproxy-mcp` | 运行状态目录（各后端子目录） |
| `U33PK_HOME` | `~/Projects/personal/mcp-servers/mitmproxy-mcp-u33pk` | u33pk 源码安装位置 |
| `SPECTRAL_BIN` | wrapper 同目录的 `mitmproxy-mcp-spectral-upstream`，回退 `~/.local/share/uv/tools/mitmproxy-mcp/bin/mitmproxy-mcp` | spectral 上游可执行文件 |
| `U33PK_BIN` | wrapper 同目录的 `mitmproxy-mcp-u33pk-upstream`，回退 `$U33PK_HOME/.venv/bin/mitmproxy-mcp` | u33pk 上游可执行文件 |
| `MITMPROXY_MCP_PYTHON` | 自动探测带 `mcp` SDK 的 python | 统一入口使用的解释器 |
| `MITMPROXY_MCP_SERVER_SCRIPT` | wrapper 同目录的 `mitmproxy_mcp_unified.py` | 聚合器脚本位置 |
| `MITMPROXY_MCP_STATE_DIR` | `~/.local/state/mitmproxy-mcp/<flavor>` | 单个后端的状态目录 |

> 上表是**运行时**环境变量（在调用 wrapper 时生效）。
> `BIN_DIR` / `SKILLS_DIR` / `STATE_DIR` / `U33PK_HOME` 同时也是 `install.sh` 的安装参数。

wrapper 的查找顺序是：显式环境变量 → 自身目录旁的软链 → 默认安装位置。
因此**把 wrapper 复制到别处也能正常工作**，无需额外配置。

## 启用 CI（可选）

仓库带一份 GitHub Actions workflow（`scripts/ci.yml`），默认不在 git 里——推送
`.github/workflows/*` 需要 token 带 `workflow` scope，缺 scope 时 GitHub 会拒绝 push。

```bash
gh auth refresh -h github.com -s workflow
./scripts/enable-ci.sh
```

## 卸载

推荐用脚本——它知道所有安装路径，且跟随环境变量变化：

```bash
./scripts/install.sh --uninstall
```

会删除：三个 wrapper、两个上游软链、聚合器脚本 `mitmproxy_mcp_unified.py`、
skill 目录、运行状态目录、u33pk 源码安装目录、spectral 的 uv tool 包。

**保留不动**：mitmproxy 本体、`~/.mitmproxy/`（CA 证书）。

仓库已经删掉时的手工等价命令（路径与默认安装一致时）：

```bash
# 两个后端
uv tool uninstall mitmproxy-mcp
rm -rf ~/Projects/personal/mcp-servers/mitmproxy-mcp-u33pk

# wrapper、统一入口与软链
rm -f ~/.local/bin/mitmproxy-mcp-spectral \
      ~/.local/bin/mitmproxy-mcp-u33pk \
      ~/.local/bin/mitmproxy-mcp-unified \
      ~/.local/bin/mitmproxy_mcp_unified.py \
      ~/.local/bin/mitmproxy-mcp-spectral-upstream \
      ~/.local/bin/mitmproxy-mcp-u33pk-upstream

# 早期版本遗留的旧名文件（当前版本不再安装）
rm -f ~/.local/bin/mitmproxy_mcp_server.py

# skill 与状态
rm -rf ~/.agents/skills/mitmproxy-mcp
rm -rf ~/.local/state/mitmproxy-mcp
```
