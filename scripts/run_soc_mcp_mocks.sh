#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
umask 077
source "$root/scripts/soc_mcp_mock_common.sh"
mock_host_options "$@"
mkdir -p "$mock_log_dir" "$mock_pid_dir"
exec {mock_lock}>"$mock_pid_dir/.lock"
flock "$mock_lock"

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

failed=0
for service in "${!ports[@]}"; do
  port=${ports[$service]}
  pid_file="$mock_pid_dir/$service.pid"
  session=$(mock_session_name "$service")
  state=already-running
  if ! tmux has-session -t "=$session" 2>/dev/null; then
    printf -v launch 'cd -- %q && exec env SOC_MOCK_SERVICE_ID=%q %q -m uvicorn app.soc_port_mock:app --host %q --port %q --no-access-log >>%q 2>&1' \
      "$root" "$service" "$root/.venv/bin/python" "$mock_host" "$port" "$root/$mock_log_dir/$session.log"
    if ! tmux new-session -d -s "$session" "$launch" {mock_lock}>&-; then failed=1; continue; fi
    state=started
  fi
  pid=$(tmux list-panes -t "=$session" -F '#{pane_pid}' 2>/dev/null || true)
  start=
  if [[ "$pid" =~ ^[0-9]+$ ]]; then start=$(process_start "$pid" || true); fi
  for ((attempt=0; attempt<50; attempt++)); do
    if belongs_to_mock "$pid" "$start" "$port" "$service" || [[ -z "$start" || "$(process_start "$pid")" != "$start" ]]; then break; fi
    sleep 0.1
  done
  if ! belongs_to_mock "$pid" "$start" "$port" "$service"; then
    echo "warning: 无法确认 $service 监听 $mock_host:$port，请查看 $mock_log_dir 或已有 tmux 会话" >&2
    failed=1
    continue
  fi
  printf '%s %s %s\n' "$pid" "$start" "$port" >"$pid_file.$$"
  mv -f -- "$pid_file.$$" "$pid_file"
  echo "$state $service session=$session pid=$pid http://$mock_host:$port"
done
exit "$failed"
