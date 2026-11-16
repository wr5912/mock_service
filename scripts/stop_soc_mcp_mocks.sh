#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
shopt -s nullglob
process_start() {
  [ -r "/proc/$1/stat" ] || return 1
  local stat fields
  stat=$(cat "/proc/$1/stat") || return 1
  read -r -a fields <<< "${stat##*) }"
  printf '%s' "${fields[19]:-}"
}
belongs_to_mock() {
  local pid=$1 start=$2 port=$3 service=$4 value item hex inode socket
  local -a arguments inodes
  [ "$(process_start "$pid")" = "$start" ] || return 1
  [ "$(readlink -f "/proc/$pid/cwd")" = "$root" ] || return 1
  while IFS= read -r -d '' item; do arguments+=("$item"); done <"/proc/$pid/cmdline"
  [ "${#arguments[@]}" = 9 ] && [ "${arguments[0]}" = "$root/.venv/bin/python" ] \
    && [ "${arguments[1]} ${arguments[2]} ${arguments[3]}" = '-m uvicorn app.soc_port_mock:app' ] \
    && [ "${arguments[4]} ${arguments[5]} ${arguments[6]} ${arguments[7]} ${arguments[8]}" = "--host 127.0.0.1 --port $port --no-access-log" ] || return 1
  value=false
  while IFS= read -r -d '' item; do [ "$item" != "SOC_MOCK_SERVICE_ID=$service" ] || value=true; done <"/proc/$pid/environ"
  [ "$value" = true ] || return 1
  printf -v hex '%04X' "$port"
  mapfile -t inodes < <(awk -v port="$hex" '$2 ~ ":" port "$" && $4 == "0A" { print $10 }' /proc/net/tcp /proc/net/tcp6 2>/dev/null)
  for socket in /proc/"$pid"/fd/*; do
    value=$(readlink "$socket" 2>/dev/null || true)
    for inode in "${inodes[@]}"; do [ "$value" != "socket:[$inode]" ] || return 0; done
  done
  return 1
}
for pid_file in .local/soc-mocks/*.pid; do
  service=$(basename "$pid_file" .pid)
  read -r pid start port extra <"$pid_file" || true
  if [[ ! "$service" =~ ^[a-z0-9-]+$ || ! "${pid:-}" =~ ^[0-9]+$ || ! "${start:-}" =~ ^[0-9]+$ || ! "${port:-}" =~ ^[0-9]+$ || -n "${extra:-}" ]] \
      || ! belongs_to_mock "$pid" "$start" "$port" "$service"; then
    echo "warning: 无法确认 $service 的进程归属，保留记录且未终止进程" >&2
    continue
  fi
  [ "$(process_start "$pid")" = "$start" ] || { echo "warning: $service 进程已变化，未终止" >&2; continue; }
  kill "$pid" 2>/dev/null || true
  for ((attempt=0; attempt<50; attempt++)); do
    belongs_to_mock "$pid" "$start" "$port" "$service" || break
    sleep 0.1
  done
  if belongs_to_mock "$pid" "$start" "$port" "$service"; then kill -KILL "$pid" 2>/dev/null || true; fi
  echo "stopped $service pid=$pid"
  rm -f "$pid_file"
done

