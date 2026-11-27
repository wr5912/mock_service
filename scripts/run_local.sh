#!/usr/bin/env bash
set -euo pipefail

if (( $# < 2 )) || [[ ! $1 =~ ^[A-Za-z0-9_-]+$ ]]; then
  echo "用法: scripts/run_local.sh 日志名称 命令 [参数...]" >&2
  exit 2
fi

name=$1
shift
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
umask 077
mkdir -p .local/logs
# 持久服务独立于启动它的验收步骤，其它用户运行参数原样继承。
unset HEP_TEST_PROCESS_SCOPE
exec "$@" >> ".local/logs/$name.log" 2>&1
