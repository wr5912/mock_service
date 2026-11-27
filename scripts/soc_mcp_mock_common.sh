# 由 SOC Mock 启停入口加载。

mock_host_options() {
  mock_host=127.0.0.1
  if [[ "$#" == 2 && "$1" == --host ]]; then
    mock_host=$2
  elif [[ "$#" != 0 ]]; then
    echo "用法：${0##*/} [--host IPv4]" >&2
    return 2
  fi
  if [[ ! "$mock_host" =~ ^(0|[1-9][0-9]{0,2})(\.(0|[1-9][0-9]{0,2})){3}$ ]]; then
    echo '监听地址必须为规范的 IPv4 地址' >&2
    return 2
  fi
  local a b c d
  IFS=. read -r a b c d <<< "$mock_host"
  if ((a > 255 || b > 255 || c > 255 || d > 255)); then
    echo '监听地址必须为规范的 IPv4 地址' >&2
    return 2
  fi
  if [[ "$a" != 127 ]]; then
    if ! ((a == 10 || a == 172 && b >= 16 && b <= 31 || a == 192 && b == 168)) ||
      ! ip -o -4 address show dev docker0 2>/dev/null | awk -v host="$mock_host" '
        { split($4, ipv4, "/"); if (ipv4[1] == host) found = 1 } END { exit !found }
      '; then
      echo '监听地址仅支持本机回环或 docker0 已配置的私有 IPv4' >&2
      return 2
    fi
  fi
  mock_pid_dir=.local/soc-mocks
  mock_log_dir=.local/logs
  if [[ "$mock_host" != 127.0.0.1 ]]; then
    mock_pid_dir+=/$mock_host
    mock_log_dir+=/soc-mocks/$mock_host
  fi
  printf -v mock_address_hex '%02X%02X%02X%02X' "$d" "$c" "$b" "$a"
}

mock_session_name() {
  case "$mock_host" in
    127.0.0.1) printf 'soc-mock-%s' "$1" ;;
    127.*) printf 'soc-mock-%s-%s' "${mock_host//./-}" "$1" ;;
    *) printf 'mock-soc-%s-docker' "${1#ai-soc-}" ;;
  esac
}

process_start() {
  local stat
  local -a fields
  stat=$(cat "/proc/$1/stat" 2>/dev/null) || return 1
  read -r -a fields <<< "${stat##*) }"
  [[ "${fields[0]:-}" != Z ]] || return 1
  printf '%s' "${fields[19]:-}"
}

belongs_to_mock() {
  local pid=$1 start=$2 port=$3 service=$4 item value address inode socket
  local -a arguments=() inodes=()
  [[ -n "$start" && "$(process_start "$pid")" == "$start" && "$(readlink -f "/proc/$pid/cwd")" == "$root" ]] || return 1
  while IFS= read -r -d '' item; do arguments+=("$item"); done <"/proc/$pid/cmdline"
  [[ "${#arguments[@]}" == 8 || "${#arguments[@]}" == 9 && "${arguments[8]}" == --no-access-log ]] || return 1
  [[ ( "${arguments[0]}" == "$root/.venv/bin/python" || "${arguments[0]}" == .venv/bin/python )
    && "$(readlink -f "/proc/$pid/exe")" == "$(readlink -f "$root/.venv/bin/python")"
    && "${arguments[1]} ${arguments[2]} ${arguments[3]}" == '-m uvicorn app.soc_port_mock:app'
    && "${arguments[4]} ${arguments[5]} ${arguments[6]} ${arguments[7]}" == "--host $mock_host --port $port" ]] || return 1
  value=false
  while IFS= read -r -d '' item; do [[ "$item" != "SOC_MOCK_SERVICE_ID=$service" ]] || value=true; done <"/proc/$pid/environ"
  [[ "$value" == true ]] || return 1
  printf -v address '%s:%04X' "$mock_address_hex" "$port"
  mapfile -t inodes < <(awk -v address="$address" '$2 == address && $4 == "0A" { print $10 }' /proc/net/tcp)
  for socket in /proc/"$pid"/fd/*; do
    value=$(readlink "$socket" 2>/dev/null || true)
    for inode in "${inodes[@]}"; do [[ "$value" != "socket:[$inode]" ]] || return 0; done
  done
  return 1
}
