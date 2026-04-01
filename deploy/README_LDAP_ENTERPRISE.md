# Sub2API 企业 LDAP - 新架构部署指南

首次部署后，日常只需要管理两件事：
1. 应用 Docker 镜像版本
2. PostgreSQL 数据库备份/恢复

---

## 1. 首次部署（全新环境）

```bash
git clone git@github.com:big-dimple/sub2api.git
cd sub2api

cd deploy
mkdir -p data postgres_data redis_data
# 关键：避免 /app/data 无写权限导致容器重启
sudo chown -R 1000:1000 data
sudo chmod 775 data

cp .env.example .env
sed -i "s/^JWT_SECRET=.*/JWT_SECRET=$(openssl rand -hex 32)/" .env
sed -i "s/^TOTP_ENCRYPTION_KEY=.*/TOTP_ENCRYPTION_KEY=$(openssl rand -hex 32)/" .env
sed -i "s/^POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -hex 16)/" .env

cd ..
docker build -t weishaw/sub2api:latest .
cd deploy
docker compose -f docker-compose.local.yml up -d
```

首次管理员密码：
- 若 `.env` 已有 `ADMIN_PASSWORD`，直接使用该值登录。
- 若 `ADMIN_PASSWORD` 为空，可从日志提取一次性密码：

```bash
docker compose -f docker-compose.local.yml logs sub2api | grep "Generated admin password"
```

---

## 2. 升级（强制备份）

```bash
cd /path/to/sub2api/deploy
bash upgrade_main.sh
```

说明：
- 脚本会先强制备份（`.env`、`config.yaml`、PostgreSQL SQL 导出、卷目录归档），备份成功后才会继续升级。
- 默认拉取并发布 `main`。
- 如需临时切换分支，可使用：`bash upgrade_main.sh --branch <branch>`
- 兼容旧入口：`upgrade_ldap_prod.sh` 仍可使用，但 `upgrade_main.sh` 是新的公开入口。
- 即使你刚用 `curl` 覆盖过升级脚本、导致当前 Git 工作区变脏，脚本也会改为使用临时远端快照构建，不需要再手工 `git stash`。

---

## 3. 回滚（数据库恢复）

### 3.1 数据恢复

恢复最近一次备份：

```bash
cd /path/to/sub2api/deploy
bash upgrade_main.sh --restore latest
```

恢复指定备份目录：

```bash
cd /path/to/sub2api/deploy
bash upgrade_main.sh --restore ../backups/backup_YYYYMMDD_HHMMSS
```

### 3.2 镜像回退（可选）

```bash
cd /path/to/sub2api
git checkout <上一个稳定提交或稳定标签>
docker build -t weishaw/sub2api:latest .
cd deploy
docker compose -f docker-compose.local.yml up -d --no-deps sub2api
```
