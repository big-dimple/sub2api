#!/usr/bin/env bash
# 本地构建镜像的快速脚本，避免在命令行反复输入构建参数。

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

detect_build_version() {
    local version_file="${REPO_ROOT}/backend/cmd/server/VERSION"
    local latest_tag=""

    latest_tag="$(git -C "${REPO_ROOT}" describe --tags --match 'v[0-9]*' --abbrev=0 2>/dev/null || true)"
    if [[ -n "${latest_tag}" ]]; then
        echo "${latest_tag#v}"
        return
    fi

    if [[ -f "${version_file}" ]]; then
        tr -d '\r\n' < "${version_file}"
        return
    fi

    echo "0.0.0-dev"
}

BUILD_VERSION="$(detect_build_version)"
BUILD_COMMIT="$(git -C "${REPO_ROOT}" rev-parse --short HEAD 2>/dev/null || echo unknown)"

docker build -t sub2api:latest \
    --build-arg VERSION="${BUILD_VERSION}" \
    --build-arg COMMIT="${BUILD_COMMIT}" \
    --build-arg GOPROXY=https://goproxy.cn,direct \
    --build-arg GOSUMDB=sum.golang.google.cn \
    -f "${REPO_ROOT}/Dockerfile" \
    "${REPO_ROOT}"
