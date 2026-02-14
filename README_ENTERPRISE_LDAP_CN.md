# Sub2API 企业域控接入说明（内部版）

> 本文档用于区分当前企业内部版本与开源默认能力，作为 LDAP/AD 身份治理开发与落地基线。

## 1. 目标与范围
- 目标：将 Sub2API 接入企业 LDAP/AD，实现员工账号自动纳管，减少人工开通和离职遗留风险。
- 组织规模：公司约 170 人，预计实际开通 API Key 用户 < 100。
- 策略：优先做简单、稳定、可维护版本，不做过度设计。

## 2. 已确认的业务决策（强约束）
- 账号策略：不允许本地普通用户，仅保留本地 `admin` 管理员账号。
- 冲突策略：LDAP 用户与本地普通用户同邮箱不做合并；按异常处理（本地普通用户应被清理）。
- 权限策略：用户被移出 LDAP 允许组后，系统权限立即覆盖刷新，不保留人工白名单例外。
- 离职策略：按日同步（每天至少一次）处理离职账号，确保离职用户无法继续登录。
- 管理员策略：管理员权限仅本地账号维护，不通过 LDAP 组授予。

## 3. 实施阶段（建议）
1. Phase A：认证接入（MVP）
   - 增加 LDAP 配置（连接、BaseDN、Filter、允许组）。
   - 登录链路增加 LDAP Bind 校验和 JIT 开户。
   - 用户属性同步：昵称、邮箱、部门。
2. Phase B：权限与生命周期
   - 新增 LDAP 组到 Sub2API 权益映射（角色/额度/并发）。
   - 登录时强制刷新组映射结果。
   - 每日同步任务：识别离职/禁用/移组用户并执行禁用或删除流程。
3. Phase C：运营增强（可选）
   - 管理后台提供映射配置和同步任务状态可视化。
   - 部门维度用量统计报表。

## 4. KubePi-nodown 参考边界
- 可参考：LDAP 同步流程、`Test Connect`/`Sync Now` 交互形态、后端同步任务组织方式。
- 不可直接复用：前端页面样式（保持 Sub2API 现有风格）；不安全 TLS 配置（如跳过证书校验）禁止带入。

## 5. 开发与推送说明（本环境）
- 本仓库已配置 SSH 免密推送，可直接使用 `git push`。
- 推荐流程：`git add .` -> `git commit -m "feat: ..."` -> `git push origin <branch>`.
- 本文档为内部基线，后续需求变更请先更新本文件再改代码。

## 6. 开发清单与验收（建议按周推进）

### 6.1 Phase A（认证接入）清单
- [ ] 管理后台可配置 LDAP 连接参数并保存（Host/Port/TLS/BindDN/BaseDN/Filter）。
- [ ] 登录支持“域账号或邮箱 + 密码”，后端 LDAP Bind 鉴权通过。
- [ ] 首次登录自动建档（JIT），并写入 `auth_source=ldap` 与 LDAP Profile。
- [ ] LDAP 模式开启后，普通注册、验证码注册、OAuth 注册入口均关闭。

验收标准：
- 使用测试域账号可登录；禁用账号不可登录；本地 admin 仍可登录。

### 6.2 Phase B（生命周期与权限）清单
- [ ] 组映射规则生效（LDAP 组 -> role/balance/concurrency）。
- [ ] 登录时刷新用户属性（昵称、邮箱、部门）与组映射结果。
- [ ] 定时同步任务按 `ldap_sync_interval_minutes` 执行（默认每日）。
- [ ] 离职/失效账号在同步后自动 `disabled`，并撤销 refresh sessions。

验收标准：
- 人为将测试用户移出允许组后，下次同步后无法继续访问。

### 6.3 Phase C（运营增强，可选）清单
- [ ] 增加“测试连接 / 立即同步”按钮（仅管理员）。
- [ ] 增加 LDAP 同步运行日志与最近同步时间展示。
- [ ] 增加部门维度消耗看板（可放在后续迭代）。

## 7. 规模化落地建议（170 人组织）
- 先灰度 10-20 人（技术团队）一周，确认无误后扩到 80-100 人目标人群。
- 同步周期先设为 `1440` 分钟（每日），稳定后按需要降到 `60-240` 分钟。
- 首月只做“可用 + 可控”，避免同时引入复杂审批流或白名单特例。

## 8. 首次配置 SOP（给 IT 值守）
1. 用本地 `admin` 登录后台，进入 `系统设置 -> LDAP / AD 身份接入`。
2. 按顺序配置：连接参数 -> 用户检索 -> 允许组/组映射 -> 同步策略。
3. 先用测试域账号验证登录，确认能自动建档并拿到正确权限。
4. 开启周期同步，先设 `1440` 分钟（每日一次）。
5. 关闭普通注册入口，仅保留本地 `admin` + LDAP 登录模式。

验收最小闭环：
- 新员工首次登录可自动开通。
- 被禁用/离职账号在次日同步后无法登录。
- 本地 `admin` 始终可应急登录。

## 9. 部署依赖与近期踩坑（务必纳入运维基线）
### 9.1 最小依赖
- 运行环境：Docker Engine、PostgreSQL 15+、Redis 7+。
- 常用工具：`openssl`、`curl`、`git`、`ca-certificates`（企业证书场景）。
- 若用 Compose：需安装 `docker compose` 插件（部分环境默认没有）。

Ubuntu 参考：
```bash
apt-get update
apt-get install -y docker.io docker-compose-plugin openssl curl git ca-certificates
```

### 9.2 已验证坑点（2026-02）
- `TOTP_ENCRYPTION_KEY` 必须是 64 位十六进制：`openssl rand -hex 32`。
- 部分环境没有 `docker compose`，需单容器 `docker run` 或安装 compose 插件。
- 目录权限不对会导致容器启动失败，参考：
  - `data` -> `1000:1000`
  - `postgres_data` -> `70:70`
  - `redis_data` -> `999:1000`
- LDAP 测试期可临时跳过证书校验；生产必须关闭该选项并配置可信 CA。

## 10. Fork 跟进官方更新策略（避免“自研孤岛”）
### 10.1 分支与远程约定
- `origin`：公司 fork（当前生产来源）。
- `upstream`：官方仓库 `Wei-Shaw/sub2api`。
- 分支建议：
  - `main`：公司稳定主线（可发布）。
  - `feat/*`：功能开发分支。
  - `sync/upstream-YYYYMMDD`：每次官方同步分支。

### 10.2 推荐同步节奏
- 常规：每月一次同步官方 `main`。
- 紧急：官方安全修复发布后 24 小时内同步评估。

### 10.3 IT 可执行命令（标准流程）
```bash
# 仅首次执行
git remote add upstream https://github.com/Wei-Shaw/sub2api.git

# 每次同步
git fetch upstream --tags
git checkout -b sync/upstream-$(date +%Y%m%d) origin/main
git merge --no-ff upstream/main -m "merge: sync upstream/main"

# 冲突解决后做最小回归
make test
pnpm --dir frontend run build

# 回灌主线
git checkout main
git merge --no-ff sync/upstream-$(date +%Y%m%d)
git push origin main
```

### 10.4 是否提交到官方仓库
- 可以提交，但只提交“通用能力”（如 LDAP Bug 修复、通用可配置项）。
- 企业特有策略（本地 admin 保留、组织配额规则、内部文档）留在 fork，不直接上游化。
