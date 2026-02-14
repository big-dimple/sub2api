# Sub2API LDAP 交接文档（AI -> WSL 接力）

更新时间：2026-02-14

## 1. 当前结论（给 IT 的一句话）
- LDAP 企业接入主功能已落地并已推送到 `origin/main`，服务器运行正常；因当前机器为 2C2G，完整质量回归改由你的 WSL Ubuntu 执行收尾。

## 2. 已完成内容（已入库）
- 企业 LDAP/AD 接入主能力（认证、JIT 开户、同步策略、组映射、管理员配置页）。
- 管理端首次引导补齐 LDAP 路径：
  - 新增“系统设置 -> LDAP”引导步骤。
  - LDAP 设置卡片增加 `data-tour` 标识，支持新手导航。
- LDAP 设置页中文化与新手提示增强：
  - 关键字段中英对照、配置顺序说明、风险提示。
- 企业文档增强：
  - `README_ENTERPRISE_LDAP_CN.md` 已补充依赖清单、部署坑点、fork 跟进 upstream 策略。

关键提交：
- `3dbda153`：LDAP 企业能力主实现
- `bb86a851`：LDAP 新手引导 + 中文说明 + 企业运维文档增强

## 3. 运行状态（当前服务器）
- 容器：
  - `sub2api`（healthy）
  - `sub2api-postgres`
  - `sub2api-redis`
- 健康检查：`docker exec sub2api curl -sS http://127.0.0.1:8080/health` 返回 `{"status":"ok"}`。

## 4. 本机已补齐的宿主机工具
- `go version go1.25.7 linux/amd64`
- `pnpm 10.29.3`
- `golangci-lint 2.7.0`

## 5. 本轮测试执行结果（截至 2026-02-14）
- 已通过：
  - `backend/go test ./...`
  - `frontend/pnpm run lint:check`
  - `frontend/pnpm run typecheck`
- 未完成（本机性能瓶颈 + 用户中断）：
  - `golangci-lint run ./...`（在 2C2G 上耗时异常长）
  - `pnpm --dir frontend run build`（执行中被人工中断，非代码报错结论）

## 6. 你在 WSL Ubuntu 的接力清单（按顺序）
1. 拉最新代码：
   ```bash
   git checkout main
   git pull origin main
   ```
2. 准备依赖：
   ```bash
   go version
   pnpm -v
   ```
3. 回归后端：
   ```bash
   cd backend
   go test ./...
   golangci-lint run ./... --timeout=20m
   ```
4. 回归前端：
   ```bash
   cd ../frontend
   pnpm install
   pnpm run lint:check
   pnpm run typecheck
   pnpm run build
   ```
5. 通过后回传结果（推荐）：
   - 记录命令输出摘要
   - 如无代码变更，仅回报“回归通过”
   - 如有修复，再走 `commit -> push`

## 7. 给 IT 的交付口径
- 这不是“分叉后自走”的私有系统：已制定 upstream 同步策略，见 `README_ENTERPRISE_LDAP_CN.md` 第 10 节。
- 生产运维重点：
  - 仅保留本地 `admin`，员工走 LDAP 登录。
  - 同步策略先每日执行（`1440` 分钟），稳定后再提频。
  - 先小规模灰度，再全员推广。

