# Sub2API LDAP

全新部署：

```bash
mkdir -p /home/sub2api && cd /home/sub2api && curl -fsSL https://raw.githubusercontent.com/big-dimple/sub2api/main/deploy/docker-deploy.sh | bash
```

一键更新：

```bash
cd /home/sub2api/deploy && curl -fsSLo upgrade_main.sh https://raw.githubusercontent.com/big-dimple/sub2api/main/deploy/upgrade_main.sh && bash upgrade_main.sh
```

回滚最近一次备份：

```bash
cd /home/sub2api/deploy && bash upgrade_main.sh --restore latest
```

首次管理员密码在 `/home/sub2api/deploy/.env` 的 `ADMIN_PASSWORD`。

不要点后台网页在线更新。
