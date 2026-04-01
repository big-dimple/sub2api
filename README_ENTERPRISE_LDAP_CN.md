# LDAP 版说明

LDAP 版的部署、升级、回滚只看这一份文档：

- [deploy/README_LDAP_ENTERPRISE.md](deploy/README_LDAP_ENTERPRISE.md)

当前对外约定：
- `main` 是唯一公开可用主线
- `feature/ldap-support` 仅用于内部维护
- 客户侧升级统一执行 `deploy/upgrade_main.sh`

网页里的在线更新在这个 fork 中已经禁用，不再作为升级入口。
