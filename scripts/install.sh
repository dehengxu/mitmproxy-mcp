#!/usr/bin/env bash
# Install both mitmproxy MCP servers, the unified skill, and the wrapper scripts.
#
# Usage:
#   ./scripts/install.sh                 # install everything
#   ./scripts/install.sh --no-mitmproxy  # skip installing mitmproxy itself
#   ./scripts/install.sh --check         # report what is present, change nothing
#   ./scripts/install.sh --force         # re-install both backends from vendored source
#   ./scripts/install.sh --uninstall     # remove everything this script installed
#
# Idempotent: safe to re-run.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILL_DIR="${SKILLS_DIR:-$HOME/.agents/skills}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
STATE_DIR="${STATE_DIR:-$HOME/.local/state/mitmproxy-mcp}"
U33PK_HOME="${U33PK_HOME:-$HOME/Projects/personal/mcp-servers/mitmproxy-mcp-u33pk}"

CHECK_ONLY=0
INSTALL_MITMPROXY=1
FORCE=0
UNINSTALL=0
for arg in "$@"; do
  case "$arg" in
    --check) CHECK_ONLY=1 ;;
    --no-mitmproxy) INSTALL_MITMPROXY=0 ;;
    --force) FORCE=1 ;;
    --uninstall) UNINSTALL=1 ;;
    -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

say()  { printf '\033[1;34m==\033[0m %s\n' "$*"; }
ok()   { printf '  \033[0;32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[0;33m!\033[0m %s\n' "$*"; }
die()  { printf '  \033[0;31m✗\033[0m %s\n' "$*" >&2; exit 1; }

echo
say "mitmproxy-mcp installer"
echo "  repo: $REPO_ROOT"
echo

# --------------------------------------------------------------- uninstall
if [ "$UNINSTALL" -eq 1 ]; then
  say "uninstall"
  if [ "$CHECK_ONLY" -eq 0 ]; then
    for f in mitmproxy-mcp-spectral mitmproxy-mcp-u33pk mitmproxy-mcp-unified \
             mitmproxy_mcp_unified.py mitmproxy-mcp-spectral-upstream \
             mitmproxy-mcp-u33pk-upstream; do
      if rm -f "$BIN_DIR/$f" 2>/dev/null; then
        ok "removed $BIN_DIR/$f"
      else
        warn "could not remove $BIN_DIR/$f"
      fi
    done
    rm -rf "$STATE_DIR" 2>/dev/null && ok "removed state dir $STATE_DIR" \
      || warn "could not remove $STATE_DIR"
    rm -rf "$SKILL_DIR/mitmproxy-mcp" 2>/dev/null && ok "removed skill $SKILL_DIR/mitmproxy-mcp" \
      || warn "could not remove $SKILL_DIR/mitmproxy-mcp"
    rm -rf "$U33PK_HOME" 2>/dev/null && ok "removed u33pk source install $U33PK_HOME" \
      || warn "could not remove $U33PK_HOME"
    if command -v uv >/dev/null 2>&1; then
      if uv tool uninstall mitmproxy-mcp >/dev/null 2>&1; then
        ok "removed uv tool mitmproxy-mcp (spectral)"
      else
        warn "uv tool mitmproxy-mcp was not installed"
      fi
    fi
    echo
    echo "Left untouched: mitmproxy itself, ~/.mitmproxy (CA), and any other uv tool."
  else
    echo "  would remove: wrappers+links in $BIN_DIR, $STATE_DIR,"
    echo "                $SKILL_DIR/mitmproxy-mcp, $U33PK_HOME, uv tool mitmproxy-mcp"
  fi
  echo
  exit 0
fi

# ---------------------------------------------------------------- mitmproxy
if [ "$INSTALL_MITMPROXY" -eq 1 ]; then
  say "mitmproxy"
  if command -v mitmproxy >/dev/null 2>&1; then
    ok "already installed: $(mitmproxy --version 2>&1 | head -1)"
  else
    if command -v asdf >/dev/null 2>&1; then
      if asdf plugin list 2>/dev/null | grep -q mitmproxy; then
        asdf install mitmproxy latest && asdf set -u mitmproxy latest
        ok "installed via asdf"
      else
        warn "asdf has no mitmproxy plugin; see docs/install.md"
      fi
    else
      warn "asdf not found; install mitmproxy manually, see docs/install.md"
    fi
  fi
  echo
fi

# ------------------------------------------------- spectral (vendored source)
say "spectral (snapspecter/mitmproxy-mcp)"
SPECTRAL_DIR="$HOME/.local/share/uv/tools/mitmproxy-mcp"
if [ -x "$SPECTRAL_DIR/bin/mitmproxy-mcp" ] && [ "$FORCE" -eq 0 ]; then
  ok "already installed: $SPECTRAL_DIR/bin/mitmproxy-mcp"
else
  if command -v uv >/dev/null 2>&1; then
    if [ "$CHECK_ONLY" -eq 0 ]; then
      # Install the vendored 0.8.0 (the git main version). PyPI still ships
      # 0.6.1, which declares "mcp>=1.25.0" with no upper bound: mcp 2.x
      # renamed FastMCP -> MCPServer, so that install crashes with
      # ModuleNotFoundError: mcp.server.fastmcp. The vendored 0.8.0 already
      # pins mcp>=1.25.0,<2.0.0.
      if [ "$FORCE" -eq 1 ]; then
        uv tool install --reinstall --with "mcp<2" "$REPO_ROOT/spectral"
        ok "reinstalled from vendored source (uv tool install --reinstall)"
      else
        uv tool install --with "mcp<2" "$REPO_ROOT/spectral"
        ok "installed from vendored source via uv tool install"
      fi
    else
      warn "not installed (would install from vendored source via uv tool install)"
    fi
  else
    warn "uv not found; see docs/install.md"
  fi
fi
echo

# ------------------------------------------------------------------ u33pk
say "u33pk (u33pk/mitmproxy-mcp)"
if [ -x "$U33PK_HOME/.venv/bin/mitmproxy-mcp" ] && [ "$FORCE" -eq 0 ]; then
  ok "already installed: $U33PK_HOME/.venv/bin/mitmproxy-mcp"
else
  if [ "$CHECK_ONLY" -eq 0 ]; then
    if command -v uv >/dev/null 2>&1; then
      mkdir -p "$(dirname "$U33PK_HOME")"
      # Install from the vendored tree in this repo, which carries our fixes
      # (map_*_ctl double-unpack bug + the mcp<2 pin). See docs/upstream-fixes.md.
      # Copy over the existing tree instead of deleting it first: the copy is
      # idempotent and there is no window where a half-removed install breaks.
      mkdir -p "$U33PK_HOME"
      cp -R "$REPO_ROOT/u33pk/." "$U33PK_HOME/"
      cd "$U33PK_HOME"
      # --clear: a stale .venv makes uv venv fail, which is exactly what a
      # re-install has to survive.
      uv venv --python 3.13 --clear
      uv pip install -e ".[dev]"
      # Same mcp<2 pin as spectral -- upstream declares "mcp>=1.28.0" unbounded.
      uv pip install "mcp<2"
      if [ "$FORCE" -eq 1 ]; then
        ok "reinstalled from vendored source (patched)"
      else
        ok "installed from vendored source (patched)"
      fi
    else
      warn "uv not found; see docs/install.md"
    fi
  else
    warn "not installed (would copy vendored source + uv pip install -e)"
  fi
fi
echo

# ---------------------------------------------------------------- wrappers
say "wrapper scripts"
if [ "$CHECK_ONLY" -eq 0 ]; then
  mkdir -p "$BIN_DIR" "$STATE_DIR/spectral" "$STATE_DIR/u33pk"
fi
for w in spectral u33pk; do
  src="$REPO_ROOT/scripts/wrappers/mitmproxy-mcp-$w"
  dst="$BIN_DIR/mitmproxy-mcp-$w"
  if [ "$CHECK_ONLY" -eq 0 ]; then
    cp "$src" "$dst"
    chmod +x "$dst"
    ok "installed $dst"
  else
    [ -x "$dst" ] && ok "present $dst" || warn "missing $dst"
  fi
done

# The unified entry: one MCP server exposing both upstreams.
if [ "$CHECK_ONLY" -eq 0 ]; then
  cp "$REPO_ROOT/scripts/mitmproxy_mcp_unified.py" "$BIN_DIR/mitmproxy_mcp_unified.py"
  cp "$REPO_ROOT/scripts/wrappers/mitmproxy-mcp-unified" "$BIN_DIR/mitmproxy-mcp-unified"
  chmod +x "$BIN_DIR/mitmproxy-mcp-unified"
  ok "installed $BIN_DIR/mitmproxy-mcp-unified"

  # Make the upstream executables reachable from the wrappers, regardless of
  # where the upstreams were installed.
  if [ -x "$SPECTRAL_DIR/bin/mitmproxy-mcp" ]; then
    ln -sf "$SPECTRAL_DIR/bin/mitmproxy-mcp" "$BIN_DIR/mitmproxy-mcp-spectral-upstream"
    ok "linked spectral upstream"
  fi
  if [ -x "$U33PK_HOME/.venv/bin/mitmproxy-mcp" ]; then
    ln -sf "$U33PK_HOME/.venv/bin/mitmproxy-mcp" "$BIN_DIR/mitmproxy-mcp-u33pk-upstream"
    ok "linked u33pk upstream"
  fi
else
  [ -x "$BIN_DIR/mitmproxy-mcp-unified" ] && ok "present $BIN_DIR/mitmproxy-mcp-unified" \
    || warn "missing $BIN_DIR/mitmproxy-mcp-unified"
fi
echo

# ------------------------------------------------------------------- skill
say "skill"
skill_src="$REPO_ROOT/skills/mitmproxy-mcp"
skill_dst="$SKILL_DIR/mitmproxy-mcp"
if [ "$CHECK_ONLY" -eq 0 ]; then
  mkdir -p "$SKILL_DIR"
  mkdir -p "$skill_dst"
  cp -R "$skill_src/." "$skill_dst/"
  ok "installed $skill_dst"
else
  [ -d "$skill_dst" ] && ok "present $skill_dst" || warn "missing $skill_dst"
fi
echo

# ------------------------------------------------------------- CA reminder
say "CA certificate"
if [ -f "$HOME/.mitmproxy/mitmproxy-ca-cert.pem" ]; then
  ok "CA exists: $HOME/.mitmproxy/mitmproxy-ca-cert.pem"
  if security dump-trust-settings -d 2>/dev/null | grep -q "mitmproxy"; then
    ok "CA is trusted by the system keychain"
  else
    warn "CA is NOT trusted yet. On macOS run:"
    echo "      sudo security add-trusted-cert -d -r trustRoot -p ssl \"
    echo "        -k /Library/Keychains/System.keychain \"
    echo "        $HOME/.mitmproxy/mitmproxy-ca-cert.pem"
    echo "      (installing into the login keychain does NOT work for Safari)"
  fi
else
  warn "no CA yet - start a proxy once, it is generated automatically"
fi
echo

say "MCP client configuration"
echo
echo "Add this to your MCP client config (e.g. Claude Desktop, MCode, Cursor):"
echo
echo "{"
echo "  \"mcpServers\": {"
echo "    \"mitmproxy-mcp\": {"
echo "      \"command\": \"$BIN_DIR/mitmproxy-mcp-unified\","
echo "      \"args\": []"
echo "    }"
echo "  }"
echo "}"
echo
echo "One entry, 37 tools: spectral_<tool> and u33pk_<tool>."
echo "Ports: spectral=8081, u33pk=8082, u33pk mitmweb=8083."
echo "Always pass the port explicitly when starting a proxy."
echo
