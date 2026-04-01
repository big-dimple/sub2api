# Sub2API LDAP 部署与升级

这份文档就是 LDAP 版的唯一运维入口。

对外分支约定：
- `main`：唯一公开可用主线
- `feature/ldap-support`：内部补丁维护分支

日常操作只记住一件事：
- 升级与回滚都走 `deploy/upgrade_main.sh`

## 1. 首次部署

```bash
git clone https://github.com/big-dimple/sub2api.git
cd sub2api/deploy

mkdir -p data postgres_data redis_data
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
- 如果 `.env` 已写 `ADMIN_PASSWORD`，直接用它登录。
- 如果没写，可从日志里拿一次性密码：

```bash
docker compose -f docker-compose.local.yml logs sub2api | grep "Generated admin password"
```

## 2. 已部署服务器如何刷新升级脚本

只需要更新主脚本：

```bash
cd /path/to/sub2api/deploy
curl -fsSLo upgrade_main.sh https://raw.githubusercontent.com/big-dimple/sub2api/main/deploy/upgrade_main.sh
chmod +x upgrade_main.sh
```

说明：
- `upgrade_main.sh` 现在会直接从远端 `main` 拉临时源码快照构建，不再要求你先手工 `git fetch origin`
- 本地仓库脏了也不会阻塞升级
- 旧的 `upgrade_ldap_prod.sh` 只是兼容别名，不再作为公开入口

## 3. 升级

```bash
cd /path/to/sub2api/deploy
bash upgrade_main.sh
```

脚本会自动做这些事：
- 先备份 `.env`、`config.yaml`、PostgreSQL SQL 和卷目录
- 再从远端 `main` 构建最新 LDAP 版镜像
- 最后平滑重建 `sub2api` 容器并做健康检查

明确禁止：
- 不要点击后台左上角的网页在线更新
- 不要对 LDAP 版执行 `docker compose pull`

原因：
- 这两种方式都会偏向官方 upstream release / 官方镜像，可能覆盖掉 LDAP 定制
- 本 fork 的网页在线更新已经改成只提示脚本升级，不再执行在线替换

## 4. 回滚

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

## 5. 给运维的最短口径

以后客户机器只需要记住：

```bash
cd /path/to/sub2api/deploy
bash upgrade_main.sh
```
