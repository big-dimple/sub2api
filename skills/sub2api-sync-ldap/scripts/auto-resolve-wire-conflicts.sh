#!/usr/bin/env bash

set -euo pipefail

if [[ ! -f backend/internal/repository/wire.go || ! -f backend/internal/service/wire.go ]]; then
    echo "ERROR: run this script in sub2api repository root."
    exit 1
fi

resolve_repository_wire() {
    local file="backend/internal/repository/wire.go"
    perl -0pi -e 's{<<<<<<< HEAD\n\tNewSoraAccountRepository,[^\n]*\n\tNewScheduledTestPlanRepository,[^\n]*\n\tNewScheduledTestResultRepository,[^\n]*\n=======\n\tNewSoraAccountRepository,[^\n]*\n\tNewSoraGenerationRepository,[^\n]*\n>>>>>>> [^\n]+\n}{\tNewSoraAccountRepository, \/\/ Sora 账号扩展表仓储\n\tNewSoraGenerationRepository, \/\/ Sora 生成任务仓储\n\tNewScheduledTestPlanRepository,   \/\/ 定时测试计划仓储\n\tNewScheduledTestResultRepository, \/\/ 定时测试结果仓储\n}sg' "$file"
}

resolve_service_wire() {
    local file="backend/internal/service/wire.go"
    perl -0pi -e 's{<<<<<<< HEAD\n\tProvideScheduledTestService,\n\tProvideScheduledTestRunnerService,\n=======\n\tProviderSetExternalAuth,\n>>>>>>> [^\n]+\n}{\tProvideScheduledTestService,\n\tProvideScheduledTestRunnerService,\n\tProviderSetExternalAuth,\n}sg' "$file"
}

echo "Auto-resolve: provider-set merge conflicts"
resolve_repository_wire
resolve_service_wire

if rg -n "^(<<<<<<<|=======|>>>>>>>)" backend/internal/repository/wire.go backend/internal/service/wire.go >/dev/null 2>&1; then
    echo "WARN: conflict markers still present in wire providers."
    exit 1
fi

git add backend/internal/repository/wire.go backend/internal/service/wire.go
echo "OK: resolved known wire provider conflicts."
