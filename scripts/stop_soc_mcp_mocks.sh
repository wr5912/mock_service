#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
umask 077
shopt -s nullglob
source "$root/scripts/soc_mcp_mock_common.sh"
mock_host_options "$@"
[[ -d "$mock_pid_dir" ]] || exit 0
exec {mock_lock}>"$mock_pid_dir/.lock"
flock "$mock_lock"
failed=0
for pid_file in "$mock_pid_dir/"*.pid; do
  service=$(basename "$pid_file" .pid)
  read -r pid start port extra <"$pid_file" || true
  if [[ ! "$service" =~ ^[a-z0-9-]+$ || ! "${pid:-}" =~ ^[0-9]+$ || ! "${start:-}" =~ ^[0-9]+$ || ! "${port:-}" =~ ^[0-9]+$ || -n "${extra:-}" ]] \
      || ! belongs_to_mock "$pid" "$start" "$port" "$service"; then
    echo "warning: 无法确认 $service 的进程归属，保留记录且未终止进程" >&2
    if [[ "$mock_host" != 127.0.0.1 ]]; then failed=1; fi
    continue
  fi
  if [[ "$(process_start "$pid")" != "$start" ]]; then
    echo "warning: $service 进程已变化，未终止" >&2
    if [[ "$mock_host" != 127.0.0.1 ]]; then failed=1; fi
    continue
  fi
  kill "$pid" 2>/dev/null || true
  for ((attempt=0; attempt<50; attempt++)); do
    [[ "$(process_start "$pid")" == "$start" ]] || break
    sleep 0.1
  done
  if [[ "$(process_start "$pid")" == "$start" ]]; then
    kill -KILL "$pid" 2>/dev/null || true
    for ((attempt=0; attempt<10; attempt++)); do
      [[ "$(process_start "$pid")" == "$start" ]] || break
      sleep 0.1
    done
  fi
  if [[ "$(process_start "$pid")" == "$start" ]]; then
    echo "warning: $service 仍在运行，保留进程记录" >&2
    failed=1
    continue
  fi
  echo "stopped $service pid=$pid http://$mock_host:$port"
  rm -f "$pid_file"
done
exit "$failed"
