#!/bin/bash
# Sub2API 企业 LDAP 版 - 生产环境安全升级脚本
# 用途：供 IT 部门在服务器上一键备份数据、获取最新代码、重构镜像并平滑重启。
# 要求：请在 sub2api/deploy 目录下执行此脚本。

set -e

# --- 1. 环境检查 ---
echo "🔍 [1/5] 环境检查..."
if [ ! -f "docker-compose.yml" ] && [ ! -f "docker-compose.local.yml" ]; then
    echo "❌ 错误: 找不到 docker-compose 文件，请确保在 sub2api/deploy 目录下运行！"
    exit 1
fi
# 优先使用 local 配置文件（如果您在生产用的是 local）
COMPOSE_FILE="docker-compose.local.yml"
[ ! -f "$COMPOSE_FILE" ] && COMPOSE_FILE="docker-compose.yml"
echo "✅ 使用配置文件: $COMPOSE_FILE"

# --- 2. 数据备份 ---
BACKUP_DIR="../backups/backup_$(date +%Y%m%d_%H%M%S)"
echo "📦 [2/5] 开始备份数据至 $BACKUP_DIR ..."
mkdir -p "$BACKUP_DIR"

# 备份配置文件
[ -f ".env" ] && cp .env "$BACKUP_DIR/"
[ -f "config.yaml" ] && cp config.yaml "$BACKUP_DIR/"

# 备份数据库 (PostgreSQL 逻辑备份，最安全)
echo "   正在导出 PostgreSQL 数据库..."
if docker compose -f "$COMPOSE_FILE" ps | grep -q "postgres"; then
    DB_USER=$(grep "POSTGRES_USER=" "$ENV_FILE" | cut -d'=' -f2)
    [ -z "$DB_USER" ] && DB_USER="sub2api"
    docker exec sub2api-postgres pg_dump -U "$DB_USER" sub2api > "$BACKUP_DIR/sub2api_db.sql" || echo "⚠️ 数据库导出可能不完整，请检查运行状态。"
else
    echo "⚠️ PostgreSQL 容器未运行，跳过数据库逻辑备份。"
fi

# 备份物理目录 (可选，仅作双重保险)
echo "   正在打包本地数据目录..."
tar -czf "$BACKUP_DIR/volumes_data.tar.gz" data/ postgres_data/ redis_data/ 2>/dev/null || true
echo "✅ 备份完成！备份文件保存在: $BACKUP_DIR"

# --- 3. 更新代码与镜像 ---
echo "⬇️ [3/5] 更新代码与构建镜像..."
cd ..
git fetch origin feature/ldap-support
git checkout feature/ldap-support
git pull origin feature/ldap-support

echo "🏗️ 正在基于最新代码构建镜像 (包含华为云优化)..."
docker build -t weishaw/sub2api:latest .
cd deploy

# --- 4. 平滑升级 ---
echo "🔄 [4/5] 重建应用容器..."
# 仅重建应用容器，不重启 DB 和 Redis 以减少中断
docker compose -f "$COMPOSE_FILE" up -d --no-deps --build sub2api

# --- 5. 验证状态 ---
echo "🩺 [5/5] 等待服务就绪并执行健康检查..."
sleep 10
if curl -sS http://127.0.0.1:8080/health | grep -q "ok"; then
    echo "🎉 升级成功！服务运行正常。"
else
    if curl -sS http://127.0.0.1:8081/health | grep -q "ok"; then
         echo "🎉 升级成功！服务运行正常 (端口 8081)。"
    else
        echo "❌ 警告: 健康检查失败或服务仍在启动中。"
        echo "回滚指南:"
        echo "1. 查看日志: docker compose -f $COMPOSE_FILE logs --tail=50 sub2api"
        echo "2. 如果需要回滚数据库，请使用刚才备份的: $BACKUP_DIR/sub2api_db.sql"
    fi
fi
