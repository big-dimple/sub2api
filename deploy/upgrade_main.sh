#!/usr/bin/env bash
# Sub2API LDAP 主线版 - 生产环境安全升级脚本
#
# 用法：
#   升级（强制备份）:
#     bash upgrade_main.sh
#   恢复最近一次备份:
#     bash upgrade_main.sh --restore latest
#   恢复指定备份目录:
#     bash upgrade_main.sh --restore ../backups/backup_YYYYMMDD_HHMMSS
#
# 可选参数：
#   --branch <branch>           默认 main
#   --compose-file <file>       默认优先 docker-compose.local.yml，否则 docker-compose.yml
#   --image <image:tag>         默认 weishaw/sub2api:latest

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPGRADE_SCRIPT_NAME="$(basename "$0")" exec bash "${SCRIPT_DIR}/upgrade_ldap_prod.sh" "$@"
