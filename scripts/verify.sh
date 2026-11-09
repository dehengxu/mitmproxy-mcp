#!/usr/bin/env bash
# Post-install self-check. Verifies the wrappers start, both servers answer
# tools/list over stdio JSON-RPC, and the port convention holds.
set -euo pipefail

BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROBE="$SCRIPT_DIR/mcp_probe.py"
fail=0

say()  { printf '\033[1;34m==\033[0m %s\n' "$*"; }
ok()   { printf '  \033[0;32m\xe2\x9c\x93\033[0m %s\n' "$*"; }
bad()  { printf '  \033[0;31m\xe2\x9c\x97\033[0m %s\n' "$*"; fail=1; }
warn() { printf '  \033[0;33m!\033[0m %s\n' "$*"; }

say "wrappers"
for w in spectral u33pk unified; do
  if [ -x "$BIN_DIR/mitmproxy-mcp-$w" ]; then
    ok "$BIN_DIR/mitmproxy-mcp-$w exists and is executable"
  else
    bad "$BIN_DIR/mitmproxy-mcp-$w missing"
  fi
done

# The wrappers locate their upstream through these links.
for u in spectral u33pk; do
  link="$BIN_DIR/mitmproxy-mcp-$u-upstream"
  if [ -x "$link" ]; then
    ok "$link -> $(readlink "$link" 2>/dev/null || echo present)"
  else
    warn "$link missing - re-run scripts/install.sh"
  fi
done
echo

say "tools/list"
for w in unified spectral u33pk; do
  cmd="$BIN_DIR/mitmproxy-mcp-$w"
  if [ ! -x "$cmd" ]; then
    bad "skipped $w (wrapper missing)"
    continue
  fi
  out="$(python3 "$PROBE" "$cmd" 2>/dev/null || true)"
  count="$(printf '%s\n' "$out" | head -1)"
  if [ -n "$count" ] && [ "$count" -gt 0 ] 2>/dev/null; then
    ok "$w: $count tools"
    printf '     %s\n' "$(printf '%s\n' "$out" | tail -1 | tr ',' '\n' | head -6 | tr '\n' ' ')"
  else
    bad "$w: no response to tools/list"
  fi
done
echo

say "ports"
for p in 8081 8082 8083; do
  if lsof -nP -iTCP:$p -sTCP:LISTEN >/dev/null 2>&1; then
    warn "$p already in use (a proxy may be running - that is fine)"
  else
    ok "$p free"
  fi
done
echo

say "CA"
if [ -f "$HOME/.mitmproxy/mitmproxy-ca-cert.pem" ]; then
  ok "CA file present"
  if security dump-trust-settings -d 2>/dev/null | grep -q mitmproxy; then
    ok "CA trusted by system keychain"
  else
    warn "CA not trusted yet - see docs/install.md"
  fi
else
  warn "no CA yet"
fi
echo

say "unified entry (functional)"
if [ -x "$BIN_DIR/mitmproxy-mcp-unified" ] && [ -f "$SCRIPT_DIR/test_unified_entry.py" ]; then
  if python3 "$SCRIPT_DIR/test_unified_entry.py" "$BIN_DIR/mitmproxy-mcp-unified" >/dev/null 2>&1; then
    ok "merged tools, schemas and routing all work"
  else
    bad "unified entry regression test failed (run scripts/test_unified_entry.py for details)"
  fi
else
  warn "skipped (unified entry or test script missing)"
fi
echo

if [ "$fail" -eq 0 ]; then
  printf '\033[0;32mall checks passed\033[0m\n'
else
  printf '\033[0;31msome checks failed\033[0m\n'
  exit 1
fi
