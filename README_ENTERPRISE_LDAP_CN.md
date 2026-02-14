# Sub2API LDAP 升级与部署指南

本文档只讲 4 件事：改了什么、需要装什么、怎么升级现有环境、怎么新装。

## 1. 本次版本改动
- 新增 LDAP/AD 登录（员工用域账号登录）。
- 新增 LDAP 用户首次登录自动建档（JIT）。
- 新增 LDAP 同步任务（可按周期禁用离职/失效账号）。
- 新增 LDAP 组映射（组 -> 配额/并发/角色）。
- 管理后台新增 LDAP 配置页（中文提示）。
- 保留本地 `admin` 账号作为应急入口。

## 2. 机器依赖（新环境必须安装）
```bash
apt-get update
apt-get install -y docker.io docker-compose-plugin openssl curl git ca-certificates
```

说明：
- 运行服务不需要 `go`/`pnpm`。
- `go`/`pnpm` 只在“源码编译和测试”时需要。

## 3. 生产升级（已有环境，已在用 API Key）

### 3.1 升级前备份（必须）
```bash
# 1) 备份数据库（按你的实际容器/地址调整）
docker exec sub2api-postgres pg_dump -U postgres sub2api > /root/sub2api_$(date +%F_%H%M).sql

# 2) 备份配置与数据目录（按你的实际路径调整）
cp -a .env .env.bak.$(date +%F_%H%M) 2>/dev/null || true
cp -a data data.bak.$(date +%F_%H%M) 2>/dev/null || true
cp -a postgres_data postgres_data.bak.$(date +%F_%H%M) 2>/dev/null || true
cp -a redis_data redis_data.bak.$(date +%F_%H%M) 2>/dev/null || true
```

### 3.2 关键注意项（必须）
- 不要改动历史 `JWT_SECRET`，否则会导致会话失效。
- 不要改动历史 `TOTP_ENCRYPTION_KEY`，否则可能导致 2FA 异常。
- `TOTP_ENCRYPTION_KEY` 必须是 64 位十六进制（`openssl rand -hex 32`）。

### 3.3 执行升级

方式 A：Docker Compose 部署
```bash
git pull origin main
cd deploy
# 使用你当前在跑的 compose 文件（示例：docker-compose.local.yml）
docker compose -f docker-compose.local.yml pull sub2api
docker compose -f docker-compose.local.yml up -d sub2api
```

方式 B：纯 docker run 部署
```bash
git pull origin main
docker pull weishaw/sub2api:latest
# 记录旧容器启动参数后，使用相同的 DB/Redis/ENV/挂载重建 sub2api 容器
# 仅替换应用容器，不重建 postgres/redis
```

### 3.4 升级后验证
```bash
docker ps
# 容器健康检查（名称按实际调整）
docker exec sub2api curl -sS http://127.0.0.1:8080/health
```
预期：返回 `{"status":"ok"}`。

## 4. 升级后 LDAP 配置（后台操作）
1. 本地 `admin` 登录后台。
2. 进入：`系统设置 -> LDAP / AD 身份接入`。
3. 按顺序填写：
   - 连接参数：Host/Port/TLS/Bind DN/Bind Password
   - 用户检索：User Base DN/User Filter/Login Attr/UID Attr
   - 授权：Allowed Group DNs、Group Mappings
   - 同步：先设 `1440` 分钟（每日）
4. 用测试域账号验证登录。
5. 确认离职测试账号在同步后被禁用。

## 5. 全新安装（新服务器）
```bash
# 1) 拉代码
git clone git@github.com:big-dimple/sub2api.git
cd sub2api/deploy

# 2) 配置环境
cp .env.example .env
# 必填：POSTGRES_PASSWORD
# 建议填写：JWT_SECRET、TOTP_ENCRYPTION_KEY、ADMIN_EMAIL、ADMIN_PASSWORD

# 3) 生成密钥（示例）
openssl rand -hex 32   # JWT_SECRET
openssl rand -hex 32   # TOTP_ENCRYPTION_KEY
openssl rand -hex 32   # POSTGRES_PASSWORD

# 4) 启动
mkdir -p data postgres_data redis_data
docker compose -f docker-compose.local.yml up -d
```

## 6. 回滚（升级失败时）
- 立即回滚应用容器到上一个镜像版本。
- 恢复 `.env` 与数据备份。
- 如有数据库结构变更且兼容性问题，回灌第 3.1 节的 SQL 备份。
