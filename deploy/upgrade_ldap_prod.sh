#!/usr/bin/env bash
# Sub2API LDAP 主线版 - 兼容升级脚本
#
# 用法：
#   升级（强制备份）:
#     bash upgrade_ldap_prod.sh
#   恢复最近一次备份:
#     bash upgrade_ldap_prod.sh --restore latest
#   恢复指定备份目录:
#     bash upgrade_ldap_prod.sh --restore ../backups/backup_YYYYMMDD_HHMMSS
#
# 可选参数：
#   --branch <branch>           默认 main
#   --compose-file <file>       默认优先 docker-compose.local.yml，否则 docker-compose.yml
#   --image <image:tag>         默认 weishaw/sub2api:latest

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DEPLOY_DIR="${SCRIPT_DIR}"
ENV_FILE="${DEPLOY_DIR}/.env"
SCRIPT_NAME="${UPGRADE_SCRIPT_NAME:-$(basename "$0")}"

TARGET_BRANCH="main"
IMAGE_TAG="weishaw/sub2api:latest"
COMPOSE_FILE=""
RESTORE_TARGET=""
BACKUP_DIR=""
HEALTH_TIMEOUT_SECONDS=90
BUILD_ROOT=""

usage() {
    cat <<EOF
Sub2API Mainline Upgrade Script

Usage:
  bash ${SCRIPT_NAME} [--branch <branch>] [--compose-file <file>] [--image <image:tag>]
  bash ${SCRIPT_NAME} --restore latest
  bash ${SCRIPT_NAME} --restore <backup_dir>

Examples:
  bash ${SCRIPT_NAME}
  bash ${SCRIPT_NAME} --restore latest
  bash ${SCRIPT_NAME} --restore ../backups/backup_20260304_120000
  bash ${SCRIPT_NAME} --branch main
EOF
}

log() {
    echo "$*"
}

die() {
    echo "ERROR: $*" >&2
    exit 1
}

read_env() {
    local key="$1"
    local default_value="$2"
    local value=""

    if [[ -f "$ENV_FILE" ]]; then
        value="$(grep -E "^${key}=" "$ENV_FILE" | tail -n 1 | cut -d'=' -f2- || true)"
        value="${value%$'\r'}"
        value="${value%\"}"
        value="${value#\"}"
        value="${value%\'}"
        value="${value#\'}"
    fi

    if [[ -z "$value" ]]; then
        echo "$default_value"
    else
        echo "$value"
    fi
}

detect_compose_file() {
    if [[ -n "$COMPOSE_FILE" ]]; then
        [[ -f "$COMPOSE_FILE" ]] || die "compose file not found: $COMPOSE_FILE"
        return
    fi

    if [[ -f "docker-compose.local.yml" ]]; then
        COMPOSE_FILE="docker-compose.local.yml"
    elif [[ -f "docker-compose.yml" ]]; then
        COMPOSE_FILE="docker-compose.yml"
    else
        die "cannot find docker-compose.local.yml or docker-compose.yml in deploy directory."
    fi
}

get_postgres_container() {
    local cid
    cid="$(docker compose -f "$COMPOSE_FILE" ps -q postgres 2>/dev/null || true)"
    [[ -n "$cid" ]] || die "cannot find postgres container from compose file: $COMPOSE_FILE"
    echo "$cid"
}

ensure_postgres_ready() {
    local db_user="$1"
    local db_name="$2"
    local cid
    local tries=30

    docker compose -f "$COMPOSE_FILE" up -d postgres >/dev/null
    cid="$(get_postgres_container)"

    while (( tries > 0 )); do
        if docker exec "$cid" pg_isready -U "$db_user" -d "$db_name" >/dev/null 2>&1; then
            return 0
        fi
        tries=$((tries - 1))
        sleep 2
    done

    die "postgres is not ready."
}

probe_health() {
    local url="$1"
    if command -v curl >/dev/null 2>&1; then
        curl -fsS --max-time 3 "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget -qO- --timeout=3 "$url"
    else
        return 1
    fi
}

wait_for_health() {
    local configured_port
    configured_port="$(read_env SERVER_PORT "8080")"
    local ports=("$configured_port")
    local deadline=$((SECONDS + HEALTH_TIMEOUT_SECONDS))

    if [[ "$configured_port" != "8080" ]]; then
        ports+=("8080")
    fi
    if [[ "$configured_port" != "8081" ]]; then
        ports+=("8081")
    fi

    while (( SECONDS < deadline )); do
        for port in "${ports[@]}"; do
            local resp
            resp="$(probe_health "http://127.0.0.1:${port}/health" 2>/dev/null || true)"
            if [[ "$resp" == *"ok"* || "$resp" == *"OK"* ]]; then
                log "OK: health check passed on port ${port}."
                return 0
            fi
        done
        sleep 3
    done

    return 1
}

print_failure_hints() {
    log "WARN: health check failed. Please inspect containers and logs."
    docker compose -f "$COMPOSE_FILE" ps || true
    docker compose -f "$COMPOSE_FILE" logs --tail=80 sub2api || true
    if [[ -n "$BACKUP_DIR" ]]; then
        log "Backup path: ${BACKUP_DIR}"
    fi
}

perform_backup() {
    BACKUP_DIR="../backups/backup_$(date +%Y%m%d_%H%M%S)"
    local db_user
    local db_name
    local pg_container
    local backup_sql

    db_user="$(read_env POSTGRES_USER "sub2api")"
    db_name="$(read_env POSTGRES_DB "sub2api")"

    log "[1/5] Creating backup at ${BACKUP_DIR} ..."
    mkdir -p "$BACKUP_DIR"
    [[ -f ".env" ]] && cp ".env" "$BACKUP_DIR/"
    [[ -f "config.yaml" ]] && cp "config.yaml" "$BACKUP_DIR/"

    ensure_postgres_ready "$db_user" "$db_name"
    pg_container="$(get_postgres_container)"
    backup_sql="${BACKUP_DIR}/sub2api_db.sql"

    log "Exporting PostgreSQL (${db_name}) ..."
    if ! docker exec "$pg_container" pg_dump --clean --if-exists -U "$db_user" "$db_name" > "$backup_sql"; then
        die "database backup failed, upgrade aborted."
    fi
    [[ -s "$backup_sql" ]] || die "database backup file is empty, upgrade aborted."

    log "Archiving volume directories (optional) ..."
    tar -czf "${BACKUP_DIR}/volumes_data.tar.gz" data/ postgres_data/ redis_data/ 2>/dev/null || true

    log "OK: backup completed -> ${BACKUP_DIR}"
}

resolve_restore_dir() {
    local target="$1"
    if [[ "$target" == "latest" ]]; then
        local latest
        latest="$(ls -dt ../backups/backup_* 2>/dev/null | head -n 1 || true)"
        [[ -n "$latest" ]] || die "no backup found under ../backups."
        echo "$latest"
        return
    fi
    echo "$target"
}

restore_database() {
    local requested="$1"
    local restore_dir
    local backup_sql
    local db_user
    local db_name
    local pg_container

    restore_dir="$(resolve_restore_dir "$requested")"
    [[ -d "$restore_dir" ]] || die "backup directory not found: $restore_dir"
    backup_sql="${restore_dir}/sub2api_db.sql"
    [[ -s "$backup_sql" ]] || die "backup SQL not found or empty: $backup_sql"

    db_user="$(read_env POSTGRES_USER "sub2api")"
    db_name="$(read_env POSTGRES_DB "sub2api")"

    log "[restore] Using backup: ${restore_dir}"
    ensure_postgres_ready "$db_user" "$db_name"
    pg_container="$(get_postgres_container)"

    log "[restore] Restoring database ${db_name} ..."
    if ! docker exec -i "$pg_container" psql -v ON_ERROR_STOP=1 -U "$db_user" -d "$db_name" < "$backup_sql"; then
        die "database restore failed."
    fi

    log "[restore] Restarting sub2api application container ..."
    docker compose -f "$COMPOSE_FILE" up -d --no-deps sub2api

    if wait_for_health; then
        log "OK: restore completed successfully."
        docker compose -f "$COMPOSE_FILE" ps
    else
        print_failure_hints
        die "restore finished but health check failed."
    fi
}

cleanup_build_root() {
    if [[ -n "$BUILD_ROOT" && -d "$BUILD_ROOT" ]]; then
        git -C "$PROJECT_ROOT" worktree remove --force "$BUILD_ROOT" >/dev/null 2>&1 || rm -rf "$BUILD_ROOT"
        BUILD_ROOT=""
    fi
}

prepare_repo() {
    cd "$PROJECT_ROOT"
    git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "project root is not a git repository: $PROJECT_ROOT"
    if [[ -n "$(git status --porcelain)" ]]; then
        log "WARN: git worktree is dirty in ${PROJECT_ROOT}; upgrade will build from a temporary origin/${TARGET_BRANCH} snapshot without touching local changes."
    fi
}

detect_build_version() {
    local build_root="${1:-$PROJECT_ROOT}"
    local version_file="${build_root}/backend/cmd/server/VERSION"
    local latest_tag=""
    local latest_version=""
    local tag_sha=""
    local commits_ahead=""

    latest_tag="$(git -C "$build_root" describe --tags --match 'v[0-9]*' --abbrev=0 2>/dev/null || true)"

    if [[ -n "$latest_tag" ]]; then
        latest_version="${latest_tag#v}"
        tag_sha="$(git -C "$build_root" rev-list -n 1 "$latest_tag" 2>/dev/null || true)"

        if [[ -n "$tag_sha" ]] && git -C "$build_root" merge-base --is-ancestor "$tag_sha" HEAD >/dev/null 2>&1; then
            commits_ahead="$(git -C "$build_root" rev-list --count "${latest_tag}..HEAD" 2>/dev/null || echo 0)"
            if [[ "$commits_ahead" != "0" ]]; then
                latest_version="${latest_version}.${commits_ahead}"
            fi
        fi

        echo "${latest_version}"
        return
    fi

    if [[ -f "$version_file" ]]; then
        tr -d '\r\n' < "$version_file"
        return
    fi

    echo "0.0.0-dev"
}

create_build_root() {
    BUILD_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/sub2api-upgrade.XXXXXX")"
    git -C "$PROJECT_ROOT" worktree add --detach "$BUILD_ROOT" "origin/${TARGET_BRANCH}" >/dev/null
}

upgrade_flow() {
    local build_commit
    local build_version
    local branch_head

    perform_backup
    prepare_repo

    log "[2/5] Syncing source branch ${TARGET_BRANCH} ..."
    git fetch origin "+${TARGET_BRANCH}:refs/remotes/origin/${TARGET_BRANCH}"
    git -C "$PROJECT_ROOT" show-ref --verify --quiet "refs/remotes/origin/${TARGET_BRANCH}" || die "remote branch not found: origin/${TARGET_BRANCH}"
    cleanup_build_root
    create_build_root
    trap cleanup_build_root EXIT

    branch_head="$(git -C "$BUILD_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"
    log "OK: source branch staged from origin/${TARGET_BRANCH} @ ${branch_head}"

    build_version="$(detect_build_version "$BUILD_ROOT")"
    build_commit="$(git -C "$BUILD_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)"

    log "[3/5] Building image ${IMAGE_TAG} (version ${build_version}, commit ${build_commit}) ..."
    docker build \
        --build-arg VERSION="$build_version" \
        --build-arg COMMIT="$build_commit" \
        -t "$IMAGE_TAG" "$BUILD_ROOT"

    log "[4/5] Recreating sub2api container ..."
    cd "$DEPLOY_DIR"
    docker compose -f "$COMPOSE_FILE" up -d --no-deps sub2api

    log "[5/5] Waiting for service health ..."
    if wait_for_health; then
        log "OK: upgrade completed successfully."
        log "Backup path: ${BACKUP_DIR}"
        docker compose -f "$COMPOSE_FILE" ps
        cleanup_build_root
        trap - EXIT
    else
        print_failure_hints
        die "upgrade failed after deployment."
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --restore)
            RESTORE_TARGET="${2:-}"
            [[ -n "$RESTORE_TARGET" ]] || die "--restore requires a value: latest or backup path."
            shift 2
            ;;
        --branch)
            TARGET_BRANCH="${2:-}"
            [[ -n "$TARGET_BRANCH" ]] || die "--branch requires a value."
            shift 2
            ;;
        --compose-file)
            COMPOSE_FILE="${2:-}"
            [[ -n "$COMPOSE_FILE" ]] || die "--compose-file requires a value."
            shift 2
            ;;
        --image)
            IMAGE_TAG="${2:-}"
            [[ -n "$IMAGE_TAG" ]] || die "--image requires a value."
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

cd "$DEPLOY_DIR"
detect_compose_file
log "Using compose file: ${COMPOSE_FILE}"

if [[ -n "$RESTORE_TARGET" ]]; then
    restore_database "$RESTORE_TARGET"
else
    upgrade_flow
fi
