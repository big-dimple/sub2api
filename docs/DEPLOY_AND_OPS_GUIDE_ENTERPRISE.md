# Sub2API 企业 LDAP 专属版 - 全新架构部署与运维指南

为了满足公司内部的安全规范和账号统一管理需求，我们在官方最新版本的基础上，深度定制了 **企业级 LDAP 认证与生命周期管理功能**。

⚠️ **重要架构变更说明**：
本次升级伴随底层架构的全面重构。为了支持高并发和高可用，底层数据库已由原来的单机 SQLite 升级为 **PostgreSQL + Redis** 架构。因此，本次部署需要作为**全新环境**进行起步。旧环境的数据如果需要保留，请提需求给研发评估迁移方案，否则建议直接在新环境中通过 LDAP 重新初始化账号。

---

## 🚀 第一部分：初次部署指南 (全新环境)

请在一台已安装 Docker 和 Docker Compose 的 Linux 服务器上执行以下操作：

### 1. 拉取专属企业分支
```bash
git clone git@github.com:big-dimple/sub2api.git
cd sub2api
```

### 2. 准备配置与挂载目录
```bash
cd deploy

# 创建数据挂载目录 (供 Postgres 和 Redis 使用)
mkdir -p data postgres_data redis_data
# 关键：避免 /app/data 无写权限导致容器重启
sudo chown -R 1000:1000 data
sudo chmod 775 data

# 基于示例生成真实配置文件
cp .env.example .env

# 初始化安全密钥 (必须执行！防止容器重启后用户 Session 失效)
sed -i "s/JWT_SECRET=.*/JWT_SECRET=$(openssl rand -hex 32)/" .env
sed -i "s/TOTP_ENCRYPTION_KEY=.*/TOTP_ENCRYPTION_KEY=$(openssl rand -hex 32)/" .env
sed -i "s/POSTGRES_PASSWORD=.*/POSTGRES_PASSWORD=$(openssl rand -hex 16)/" .env
```
> **提示**：如果您希望更改服务对外的端口，请编辑 `.env` 文件，修改 `SERVER_PORT` 的值（默认配置为 `8080`）。

### 3. 极速构建与启动服务
我们的代码中已内置了华为云镜像源优化，构建速度很快。
```bash
# 返回项目根目录执行镜像构建
cd ..
docker build -t weishaw/sub2api:latest .

# 返回 deploy 目录，一键启动编排
cd deploy
docker compose -f docker-compose.local.yml up -d
```
启动后，系统会自动在内部网络拉起 `sub2api` (应用)、`sub2api-postgres` 和 `sub2api-redis` 三个容器。

### 4. 获取初始管理员密码与配置 LDAP
系统首次启动时，会自动生成一个一次性的管理员密码。请通过日志提取：
```bash
docker compose -f docker-compose.local.yml logs sub2api | grep "Generated admin password"
```
1. 访问系统地址（如 `http://127.0.0.1:8080`）。
2. 使用账号 `admin@sub2api.local` 和您刚刚提取的密码登录。
3. 登录后，请立即进入 **“系统设置 -> LDAP / AD 身份接入”** 填写域控配置。
4. 我们已在页面上提供了 **“测试连接”** 和 **“立即同步”** 按钮，建议配置完成后点击测试，确保与 AD/LDAP 服务器的网络和鉴权正常。

---

## 🛡️ 第二部分：日常运维与安全升级 SOP (极其重要)

随着官方上游不断发布安全补丁（例如提示有 v0.1.86），研发团队会持续将这些补丁合并到我们的企业分支中。请 IT 运维团队**严格按照以下规范进行升级**。

### ❌ 绝对禁止的操作
当您登录管理员后台，看到左上角提示“有新版本可用”时：
**绝对不要点击界面的“更新版本”按钮！**

> **严重后果**：点击该按钮会触发系统拉取官方的“开源纯净版”镜像覆盖现有容器，这会导致我们深度定制的 LDAP 功能瞬间丢失，所有员工无法登录！

### ✅ 标准安全升级流程 (IT SRE 规范)
未来任何时候需要升级系统，只需运行我们为您封装好的全自动安全运维脚本：

```bash
cd /path/to/sub2api/deploy
bash upgrade_main.sh
```

即使运维先用 `curl` 更新了 `deploy/upgrade_main.sh`，导致部署仓库出现本地修改，脚本也会从远端 `main` 建立临时构建快照继续升级，不要求当前工作区 clean。

**该脚本会在后台全自动、安全地执行以下流程：**
1. **自动备份**：将 `docker-compose` 相关的配置文件，以及最核心的 **PostgreSQL 数据库** 导出为 SQL 备份文件（安全存放在 `../backups/` 目录下）。
2. **代码拉取**：自动从公开主线 `main` 获取包含了最新 LDAP 补丁的代码。
3. **静默重构**：利用服务器本地环境和华为云加速源，重新构建带有 LDAP 功能的最新镜像。
4. **平滑重启**：仅重建 `sub2api` 应用容器，**不断开**数据库和缓存，将升级导致的服务中断时间降至最低（通常 < 5秒）。
5. **智能验证**：启动后自动请求健康检查接口，若启动失败，终端会直接输出日志查看方法和数据回滚指南。

---

### ❓ 附：灾难回滚指南
如果在执行升级脚本后发现系统无法访问或状态异常，请按以下步骤回滚：
1. **查看报错**：运行 `docker compose -f docker-compose.local.yml logs --tail=100 sub2api` 定位问题。
2. **恢复数据库（推荐脚本化）**：
   - 恢复最近一次备份：`bash upgrade_main.sh --restore latest`
   - 恢复指定备份目录：`bash upgrade_main.sh --restore ../backups/backup_YYYYMMDD_HHMMSS`
3. **镜像回退**：如有必要，可修改 `docker-compose.local.yml` 中的 `image` 标签退回旧版并重新 `up -d`。

> *如有关于 LDAP 属性映射或配置的问题，请随时与研发团队联系。*
