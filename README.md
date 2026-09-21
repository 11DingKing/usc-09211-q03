# 航天家书接力站

面向多机构协作的家书接力服务：学校导入孩子写给航天员的信，监护人管理授权，
编辑团队复核与展示，批次操作员封存上行并对账。纯标准库实现，可独立运行。

## 运行与测试

```bash
python3 -m unittest          # 运行全部测试
python3 -m service.main      # 启动服务（默认 127.0.0.1:8000，数据库 ./relay.db）
```

环境变量：`RELAY_DB`（SQLite 路径，默认 `relay.db`）、`RELAY_VAULT_KEY`
（64 位十六进制敏感字段密钥；缺省使用内置开发密钥，仅限本地调试）。

请求通过请求头 `X-Actor` / `X-Role` 标识操作者与角色；正式部署应置于真实认证之后。

## 角色

| 角色 | 职责 |
| --- | --- |
| `intake_officer` | 学校侧导入信件 |
| `guardian` | 监护人，授予/撤回授权 |
| `reviewer` | 内容复核（双人分离） |
| `editor` | 编辑团队，登记公开展示 |
| `batch_operator` | 批次建批、封存、更正、回执 |
| `privacy_officer` | 隐私官，读取保险库身份与原文 |
| `auditor` | 审计员，校验审计链 |

## 接口一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/health` | 健康检查 |
| POST | `/letters/import` | 匿名化收件（幂等键去重，多校重复导入按正文指纹合并） |
| POST | `/consents/grant` / `/consents/revoke` | 授权授予（含有效期）/ 撤回并传播 |
| POST | `/reviews` | 复核（两人、非导入人，两票通过） |
| POST | `/batches` `/batches/stage` `/batches/seal` `/batches/amend` | 建批、候选、封存（可崩溃恢复）、封存后增量更正 |
| POST | `/receipts` | 登记上行回执 |
| GET | `/batches/reconcile?batch_id=` | 回执对账（应发/已发/缺失/失败/异常） |
| POST | `/displays` | 登记公开展示并锚定授权快照 |
| GET | `/displays/proof?display_id=` | 验证展示对应的授权快照证明 |
| POST | `/access/grants` / `/content/read` | 申请短时授权 / 凭授权读取原文 |
| GET | `/letters/locations?letter_id=` | 查询信件当前所在（候选池/批次/展示） |
| GET | `/identities?pseudonym=` | 读取保险库身份（仅隐私官） |
| GET | `/audit/verify` | 校验审计哈希链 |

所有写接口接受 `idempotency_key`，重试返回首次结果，不产生双份记录。

## 代码结构

- `service/relay.py` — 业务核心（收件、授权、复核、批次、回执、展示、访问控制）
- `service/store.py` — SQLite 表结构与哈希链审计
- `service/security.py` — 敏感字段加密与指纹（标准库占位实现，生产应换 KMS/AEAD）
- `service/api.py` / `service/main.py` — HTTP 路由与入口
- `docs/domain.md` — 领域约定与不变量
