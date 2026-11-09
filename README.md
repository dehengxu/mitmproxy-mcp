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

## 快速开始

```bash
git clone https://github.com/dehengxu/mitmproxy-mcp.git
cd mitmproxy-mcp
./scripts/install.sh          # 安装两个 server + skill + wrapper
```

脚本会打印一段 MCP 客户端配置，粘进你的客户端即可。详细步骤见 [docs/install.md](docs/install.md)。

## 端口分配（固定约定）

两个 server 默认都监听 **8080**，直接用默认值会撞车。本仓库通过 wrapper 固定隔离：

| Server | 代理端口 | mitmweb | 启动命令 |
|---|---|---|---|
| Spectral | **8081** | — | `start_proxy(port=8081)` |
| u33pk | **8082** | 8083 | `proxy_ctl(cmd="start", port=8082)` |

启动代理时**必须显式传端口**，不要用默认 8080。

## 本仓库做的整合工作

1. **端口隔离**：`scripts/wrappers/` 下两个 wrapper 脚本，各自固定工作目录（避免状态文件乱落）与默认端口。
2. **上游 bug 修复**：u33pk 的 `map_local_ctl` / `map_remote_ctl` 100% 崩溃，根因是 FastMCP 已把 JSON dict 校验成 pydantic 模型，函数体内又 `**rule` 二次解包。已改为 `model_validate(rule)`（同时兼容模型实例与 dict）。见 [docs/upstream-fixes.md](docs/upstream-fixes.md)。
3. **依赖约束收紧**：u33pk 的 `mcp>=1.28.0` 没有上限，而 `mcp 2.x` 把 `FastMCP` 改名为 `MCPServer`，装上即崩。已收紧为 `mcp>=1.28.0,<2.0.0`。
4. **统一 skill**：`skills/mitmproxy-mcp/` 一份 skill 覆盖两个 server，含端口表、选型建议与两边各自的参数坑。

## 目录结构

```
mitmproxy-mcp/
├── spectral/            # 上游 A 源码（snapspecter, MIT）
├── u33pk/               # 上游 B 源码（u33pk, MIT，含本仓库的修复）
├── skills/
│   └── mitmproxy-mcp/   # 统一 skill（装到 ~/.agents/skills/）
├── scripts/
│   ├── install.sh       # 一键安装
│   ├── wrappers/        # 两个 wrapper 脚本
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
