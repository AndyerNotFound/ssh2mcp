#!/data/data/com.termux/files/usr/bin/bash
# Restart ssh2mcp detached (setsid). Args pass through to index.js:
#   ./restart.sh --perm ro --port 6219
set -uo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
STATE="$HOME/.ssh2mcp"
PID="$STATE/ssh2mcp.pid"
LOG="$STATE/ssh2mcp.log"
PORT="${MCP_PORT:-6222}"
mkdir -p "$STATE"
if [ -f "$PID" ] && kill -0 "$(cat "$PID")" 2>/dev/null; then
  kill "$(cat "$PID")" 2>/dev/null; sleep 1
  kill -9 "$(cat "$PID")" 2>/dev/null
fi
setsid nohup node "$DIR/index.js" "$@" >>"$LOG" 2>&1< /dev/null &
echo $! > "$PID"
sleep 1
if [ ! -s "$HOME/.ssh2mcp-token" ]; then
  echo "no token at ~/.ssh2mcp-token"; tail -20 "$LOG"; exit 1
fi
curl -fsS -m 5 -H "Authorization: Bearer $(cat "$HOME/.ssh2mcp-token")" "http://127.0.0.1:$PORT/status" && echo
