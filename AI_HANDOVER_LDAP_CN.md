# Sub2API LDAP 验收接力文档（AI -> WSL）

更新时间：2026-02-14
适用对象：研发验收（非 IT 交付文档）

## 1. 目的
- 本文档只用于你在 WSL Ubuntu 完成“最后验证”。
- IT 对外交付口径请看 `README_ENTERPRISE_LDAP_CN.md`（第 11 节）。

## 2. 当前代码基线
- 已上线提交：
  - `3dbda153`（LDAP 企业能力主实现）
  - `bb86a851`（LDAP 新手引导与中文化增强）
  - `fff58199`（将 IT 交付口径合并进 README）

## 3. WSL 验收步骤（按顺序执行）
1. 拉取最新代码
```bash
git checkout main
git pull origin main
```

2. 校验工具链
```bash
go version
pnpm -v
golangci-lint version
```

3. 后端回归
```bash
cd backend
go test ./...
golangci-lint run ./... --timeout=20m
```

4. 前端回归
```bash
cd ../frontend
pnpm install
pnpm run lint:check
pnpm run typecheck
pnpm run build
```

5. 运行态核验（可选但推荐）
```bash
cd ..
docker ps
docker exec sub2api curl -sS http://127.0.0.1:8080/health
```

## 4. LDAP 功能验收清单（手工）
- 管理员首次进入后台可在引导中看到 LDAP 入口提示。
- `系统设置 -> LDAP / AD 身份接入` 页面中文说明完整可读。
- 测试域账号可登录并自动开通（JIT）。
- 被禁用/离职账号在同步后无法继续登录。
- 本地 `admin` 账号始终可登录。

## 5. 验收完成标准
- 第 3 节全部命令通过。
- 第 4 节手工检查通过。
- 若无新增代码改动，可直接记录“WSL 验收通过”并交付 IT。

