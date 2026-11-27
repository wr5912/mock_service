#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
umask 077

session=host-mock
url=https://127.0.0.1:8443
certificate="$root/.local/host-mock/cert.pem"
key="$root/.local/host-mock/key.pem"
log="$root/.local/logs/host-mock.log"
mkdir -p .local/host-mock .local/logs

if ! tmux has-session -t "=$session" 2>/dev/null; then
  # 由持有会话的进程生成证书，避免并发启动时覆盖正在使用的证书文件。
  printf -v launch 'umask 077; {
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 -subj /CN=127.0.0.1 -addext subjectAltName=IP:127.0.0.1 -keyout %q -out %q &&
    exec %q -m uvicorn app.host_mock:app --host 127.0.0.1 --port 8443 --ssl-certfile %q --ssl-keyfile %q --no-access-log;
  } >>%q 2>&1' "$key" "$certificate" "$root/.venv/bin/python" "$certificate" "$key" "$log"
  tmux new-session -d -s "$session" -c "$root" "$launch" || tmux has-session -t "=$session"
fi

for ((attempt=0; attempt<50; attempt++)); do
  if curl --noproxy '*' --silent --fail --max-time 1 --cacert "$certificate" "$url/health" >/dev/null; then
    printf 'Host Mock 已运行：%s/app/v2/api-docs，tmux=%s，日志=%s\n' "$url" "$session" "$log"
    exit 0
  fi
  tmux has-session -t "=$session" 2>/dev/null || break
  sleep 0.1
done

printf 'Host Mock 探活失败，请查看 %s\n' "$log" >&2
exit 1
