# 本仓库对上游做的改动

本仓库 vendoring 两份上游源码。以下改动只影响 `u33pk/`，`spectral/` 未做任何修改。

## 1. `map_local_ctl` / `map_remote_ctl` 100% 崩溃

### 现象

```
map_remote_ctl(cmd="add", rule={...})
→ {"success": false, "error": "MapRemoteRule() argument after ** must be a mapping, not MapRemoteRule"}
```

无论参数怎么传都崩。`map_local_ctl` 同样。

### 根因

FastMCP 会依据工具函数的类型注解做校验。u33pk 把 `rule` 标注成了 pydantic 模型：

```python
# u33pk/src/mitmproxy_mcp/server.py:1095
def map_remote_ctl(
    cmd: Literal["list", "add", "delete", "clear"],
    rule: MapRemoteRule | None = None,      # ← FastMCP 已把 JSON dict 校验成模型实例
    rule_id: str | None = None,
) -> dict[str, Any]:
    ...
    rule_obj = MapRemoteRule(**rule)        # ← 又把它当 dict 二次解包
```

进入函数体时 `rule` 已经是 `MapRemoteRule` 实例，而不是 dict。pydantic v2 的 `BaseModel` 虽然实现了 `__iter__`，但**没有** `keys()`，所以 `**model` 抛 `TypeError`。

对比同文件里正常的工具——它们把 `rule` 标注为 `dict[str, Any]`，所以 `**rule` 合法：

```python
def rule_ctl(..., rule: dict[str, Any] | None = None):        # 正常
def capture_rule_ctl(..., rule: dict[str, Any] | None = None): # 正常
def websocket_ctl(..., rule: dict[str, Any] | None = None):    # 正常
def map_local_ctl(..., rule: MapLocalRule | None = None):      # 坏
def map_remote_ctl(..., rule: MapRemoteRule | None = None):    # 坏
```

### 修复

把二次解包换成 `model_validate()`，它同时接受模型实例和 dict：

```python
rule_obj = MapRemoteRule.model_validate(rule)
rule_obj = MapLocalRule.model_validate(rule)
```

改动位置：`u33pk/src/mitmproxy_mcp/server.py:1074` 和 `:1108`。

### 实测对照

对同一组调用，分别跑未打补丁的上游版本与本仓库 vendored 版本：

| 调用 | 未打补丁（上游） | 已打补丁（本仓库） |
|---|---|---|
| `map_remote_ctl(cmd="add")` | ✗ `MapRemoteRule() argument after ** must be a mapping` | ✓ `success: true` |
| `map_local_ctl(cmd="add")` | ✗ `MapLocalRule() argument after ** must be a mapping` | ✓ `success: true` |
| `map_remote_ctl(cmd="list")` | ✓ | ✓ |
| `map_local_ctl(cmd="list")` | ✓ | ✓ |
| `rule_ctl(cmd="add")` | ✓ | ✓ |
| `capture_rule_ctl(cmd="add")` | ✓ | ✓ |
| `websocket_ctl(cmd="add_rule")` | ✓ | ✓ |
| 各自的 `clear` | ✓ | ✓ |

补丁精确命中两个坏工具，**其余工具无回归**。

### 上游状态

截至本仓库制作时（u33pk 上游 commit `307e691`，2026-08-29），**上游未修复此问题**，仓库里也没有对应的 issue/PR。

## 2. `mcp` 依赖缺少版本上限

### 问题

u33pk 的 `pyproject.toml` 声明 `mcp>=1.28.0`，没有上限。`mcp` 2.x 把 `FastMCP` 改名成 `MCPServer`，装上即崩：

```
ModuleNotFoundError: No module named 'mcp.server.fastmcp'
```

### 修复

```diff
-    "mcp>=1.28.0",
+    "mcp>=1.28.0,<2.0.0",
```

改动位置：`u33pk/pyproject.toml:8`。

> spectral 0.8.0 上游已自行修好（`mcp>=1.25.0,<2.0.0`），本仓库的 spectral 源码未改动。

## 3. 端口隔离

不涉及上游代码。两个 server 默认都监听 8080，本仓库通过 `scripts/wrappers/` 里的 wrapper 脚本固定为 8081 / 8082，见 [README](../README.md#端口分配固定约定)。

## 复现与验证

修复有效性可以直接验证：

```bash
python3 scripts/mcp_probe.py ~/.local/bin/mitmproxy-mcp-u33pk
```

再实际调用一次 `map_remote_ctl(cmd="add", ...)` 即可确认不再抛 `TypeError`。
