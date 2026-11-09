# Third-party notices

本仓库 vendoring 了两份上游源码，各自保留原始许可与归属。

各上游的精确基线 commit、本地改动清单与同步流程见 [UPSTREAM.md](UPSTREAM.md)。

## spectral/ — snapspecter/mitmproxy-mcp

- 来源：https://github.com/snapspecter/mitmproxy-mcp
- 许可：MIT，完整文本见 `spectral/LICENSE`
- Copyright (c) 2025 SnapSpecter
- 本仓库未修改其源码。

## u33pk/ — u33pk/mitmproxy-mcp

- 来源：https://github.com/u33pk/mitmproxy-mcp
- 许可：MIT（上游 README「许可证」章节声明；上游仓库未提供 LICENSE 文件）
- Copyright (c) u33pk
- 本仓库对 `u33pk/src/mitmproxy_mcp/server.py` 与 `u33pk/pyproject.toml` 做了修复，
  详见 [docs/upstream-fixes.md](docs/upstream-fixes.md)。

## mitmproxy

两个 server 均依赖 https://github.com/mitmproxy/mitmproxy （MIT）。mitmproxy 本体不在本仓库内，
需单独安装（见 [docs/install.md](docs/install.md)）。
