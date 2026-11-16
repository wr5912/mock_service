#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
umask 077
mkdir -p .local/logs .local/soc-mocks

declare -A ports=(
  [ai-soc-framework]=18080
  [ai-soc-ingest]=18081
  [ai-soc-response]=18083
  [ai-soc-detect]=18084
  [ai-soc-correlate]=18085
  [ai-soc-master]=18087
  [ai-soc-graph]=18088
  [ai-soc-event]=8083
)

for service in "${!ports[@]}"; do
  port=${ports[$service]}
  pid_file=".local/soc-mocks/$service.pid"
  session="soc-mock-$service"
  if tmux has-session -t "$session" 2>/dev/null; then
    echo "$service already running session=$session port=$port"
    continue
  fi
  rm -f "$pid_file"
  printf -v launch 'cd -- %q && exec env SOC_MOCK_SERVICE_ID=%q %q -m uvicorn app.soc_port_mock:app --host 127.0.0.1 --port %q --no-access-log >>%q 2>&1' \
    "$root" "$service" "$root/.venv/bin/python" "$port" "$root/.local/logs/soc-mock-$service.log"
  tmux new-session -d -s "$session" "$launch"
  pid=$(tmux display-message -p -t "$session" '#{pane_pid}')
  if [ ! -r "/proc/$pid/stat" ]; then echo "warning: $service 启动进程已退出，请查看本地日志" >&2; continue; fi
  stat=$(cat "/proc/$pid/stat")
  read -r -a fields <<< "${stat##*) }"
  printf '%s %s %s\n' "$pid" "${fields[19]}" "$port" >"$pid_file"
  echo "started $service session=$session pid=$pid http://127.0.0.1:$port"
done
