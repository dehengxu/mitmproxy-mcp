# 上游引用记录（UPSTREAM.md）

本文件记录本仓库**援引（vendoring）的所有开源仓库**，用于日后跟进上游更新、判断何时需要同步，
以及在升级时确认本地改动是否仍然必要。

本文件是维护者的单一事实来源。**每次同步上游后，必须更新本文件中的 commit SHA、日期与本地补丁清单。**

最后核对：2026-11-09

---

## 总览

| # | 上游仓库 | 本仓库路径 | 许可 | 基线 commit | 本地改动 |
|---|---|---|---|---|---|
| 1 | [snapspecter/mitmproxy-mcp](https://github.com/snapspecter/mitmproxy-mcp) | `spectral/` | MIT（含 LICENSE 文件） | `919bf0f4` (v0.8.0) | 无 |
| 2 | [u33pk/mitmproxy-mcp](https://github.com/u33pk/mitmproxy-mcp) | `u33pk/` | MIT（README 声明，**无 LICENSE 文件**） | `307e6912` (2026-08-29) | 2 处（见下） |

两个上游均为**直接依赖**（vendoring 完整源码），不是可选引用。

另有**间接依赖**（通过 pip/uv 安装，未 vendoring）：见文末「间接依赖」一节。

---

## 1. snapspecter/mitmproxy-mcp（`spectral/`）

| 项 | 值 |
|---|---|
| 仓库 | https://github.com/snapspecter/mitmproxy-mcp |
| Homebrew/PyPI 名 | `mitmproxy-mcp`（PyPI 最新 **0.6.1**，落后于 git） |
| 许可 | **MIT**，仓库含 `LICENSE` 文件（Copyright (c) 2025 SnapSpecter） |
| Stars | 135 |
| 基线 commit | `919bf0f4d792e80eda780e2f27ca9f5cb48e1817` |
| 基线版本 | v0.8.0 |
| 基线日期 | 2026-11-06 |
| 上游 release | v0.8.0 (2026-11-06) / v0.7.2 (2026-09-28) / v0.7.0 (2026-09-22) |
| 默认分支 | `main` |
| 本地改动 | **无**（与基线逐字节一致） |

### 同步要点

- 上游 git 领先于 PyPI：PyPI 上的 `mitmproxy-mcp` 仍是 0.6.1，而 git `main` 已是 0.8.0。
  本仓库 vendoring 的是 **git main 的 0.8.0**，不是 PyPI 版本。
- **0.8.0 已自行修复 `mcp` 版本约束**（`mcp>=1.25.0,<2.0.0`）。0.6.1 没有上限，会被 `mcp 2.x` 装崩。
  这是本仓库选用 0.8.0 而非 0.6.1 的原因。
- 上游 `src/mitmproxy_mcp/tests/` 未 vendoring（仅 1 个文件 `test_security_fix.py`）。
- 上游发布 tag 但不发 GitHub release notes 正文。

## 2. u33pk/mitmproxy-mcp（`u33pk/`）

| 项 | 值 |
|---|---|
| 仓库 | https://github.com/u33pk/mitmproxy-mcp |
| 许可 | **MIT**（README 末尾「许可证」章节声明；**仓库未提供 LICENSE 文件**） |
| Stars | 8 |
| 基线 commit | `307e69121f0bb390699221f1c6c519ed47f89880` |
| 基线日期 | 2026-08-29 |
| 基线信息 | `Merge pull request #1 from Muirelle/feat/dual-proxy` |
| GitHub Releases | **无**（该仓库不使用 release） |
| 上游 issue/PR | 无相关 issue 或 PR |
| 默认分支 | `main` |
| 本地改动 | **2 处**（见下） |

### 本地改动清单（同步后需逐一复核）

#### 改动 1 — 修复 `map_local_ctl` / `map_remote_ctl` 100% 崩溃

文件：`u33pk/src/mitmproxy_mcp/server.py`（第 1074、1108 行）

```diff
-            rule_obj = MapLocalRule(**rule)
+            rule_obj = MapLocalRule.model_validate(rule)
-            rule_obj = MapRemoteRule(**rule)
+            rule_obj = MapRemoteRule.model_validate(rule)
```

根因：FastMCP 已把 JSON dict 校验为 pydantic 模型实例，函数体内又 `**rule` 二次解包；
pydantic v2 的 `BaseModel` 无 `keys()`，故抛 `TypeError`。详见 [docs/upstream-fixes.md](docs/upstream-fixes.md)。

**上游状态：截至基线 commit 仍未修复。** 若上游修复了，应删除本改动并改用上游实现。

#### 改动 2 — 收紧 `mcp` 依赖上限

文件：`u33pk/pyproject.toml`（第 8 行）

```diff
-    "mcp>=1.28.0",
+    "mcp>=1.28.0,<2.0.0",
```

原因：`mcp` 2.x 将 `FastMCP` 改名为 `MCPServer`，两个上游都用 v1 API，装上即崩。

**上游状态：截至基线 commit 仍无上限。** 若上游补上，应删除本改动。

### 同步要点

- 上游自 2026-08-29 起无新提交，活跃度低，同步频率可低。
- 仓库无 LICENSE 文件，仅 README 声明 MIT。**若上游补上 LICENSE 文件，应一并 vendoring。**
- `u33pk/INSTALL.md` 声称可 `uv pip install mitmproxy-mcp` 从 PyPI 安装，但该 PyPI 包是
  snapspecter 的同名包（见 §1），不是 u33pk 的。u33pk 只能源码安装。

---

## 同步上游的标准流程

```bash
# 1. 查看上游是否有新提交
gh api repos/snapspecter/mitmproxy-mcp/commits/main --jq .sha
gh api repos/u33pk/mitmproxy-mcp/commits/main --jq .sha

# 2. 导出新版本（用 git archive，不带 .git）
git clone --depth 1 https://github.com/snapspecter/mitmproxy-mcp.git /tmp/spectral-new
git clone --depth 1 https://github.com/u33pk/mitmproxy-mcp.git /tmp/u33pk-new

# 3. 对比差异，确认本地补丁是否仍需要
diff -ru --exclude=.git /tmp/spectral-new/ spectral/
diff -ru --exclude=.git /tmp/u33pk-new/ u33pk/

# 4. 若上游已修复 map_*_ctl bug，撤销本地改动 1；若已加 mcp 上限，撤销改动 2

# 5. 替换 vendored 目录（保留 .gitignore 等本地文件）
#    注意：不要用 cp -R 复制 .git，会把 stale lock 一并带过去

# 6. 跑回归测试与自检
python3 scripts/test_map_tools.py ~/.local/bin/mitmproxy-mcp-u33pk
./scripts/verify.sh

# 7. 更新本文件的 commit SHA / 日期 / 补丁清单
```

---

## 间接依赖（未 vendoring）

以下通过 pip/uv 安装，版本由各上游的 `pyproject.toml` / `uv.lock` 决定：

| 依赖 | 用途 | 说明 |
|---|---|---|
| [mitmproxy/mitmproxy](https://github.com/mitmproxy/mitmproxy) (MIT) | 代理内核 | spectral 要求 `>=12.0.0`，u33pk 要求 `>=12.2.3` |
| [modelcontextprotocol/python-sdk](https://github.com/modelcontextprotocol/python-sdk) (MIT) | MCP 协议 | **必须 `<2.0.0`**（2.x 改名 `FastMCP`→`MCPServer`） |
| [pydantic/pydantic](https://github.com/pydantic/pydantic) (MIT) | 数据校验 | 改动 1 依赖其 `model_validate` 行为 |

各上游的完整依赖锁定见 `spectral/uv.lock` 与 `u33pk/uv.lock`。

---

## 相关文件

| 文件 | 内容 |
|---|---|
| [NOTICE.md](NOTICE.md) | 第三方许可与归属声明 |
| [docs/upstream-fixes.md](docs/upstream-fixes.md) | 本地改动的技术细节与 A/B 实测 |
| [docs/comparison.md](docs/comparison.md) | 两个上游的能力对比与选型 |
| [docs/troubleshooting.md](docs/troubleshooting.md) | 故障排查（含 `mcp 2.x` 崩溃） |
