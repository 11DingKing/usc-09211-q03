# 航天家书接力站

面向学校、监护人与编辑团队协作的「家书接力」独立服务：匿名化收件、监护授权的
有效期与撤回传播、双人分离复核、批次封存检查点、封存后增量更正、发送回执对账，
以及可举证的公开展示授权快照。

服务只用 Python 标准库实现，`python3 -m service.main` 即可独立运行，数据落
在 `LETTER_RELAY_HOME`（默认 `./data`）目录：

- `events.log`：仅追加的哈希链事件日志（JSONL），每次追加 fsync；
- `master.key`：敏感内容主密钥（生产环境应改由 KMS/HSM 托管）。

## 运行与测试

```bash
python3 -m unittest            # 全部 28 个测试
LETTER_RELAY_HOME=./data python3 -m service.main   # 启动 HTTP 服务（127.0.0.1:8000）
```

## 核心机制如何对应需求

| 需求 | 机制 |
| --- | --- |
| 统一凭据（收件/授权/复核/批次/回执） | 一切状态都是事件，事件同时记录业务事件时间与服务端接收时间；调用方身份随事件入链 |
| 网络重试 / 多校重复导入不得双份 | 三重幂等键：`request_id`、`source_key`、正文内容指纹（NFKC 归一化后 SHA-256），重复导入记录 `DuplicateImportSuppressed` 但返回原信件 ID |
| 匿名化收件 | 正文与 PII 加密入保险库，业务视图只有假名 ID、内容指纹与密文引用 |
| 敏感原文短时访问 | 按角色申请凭据（≤15 分钟），仅限本人使用；授权过期或在凭据有效期内被撤回则拒绝解密 |
| 授权有效期 | 每封信件持有版本化授权（REVIEW/UPLINK/DISPLAY 范围 + 生效/失效时间） |
| 撤回传播 | 撤回一次即自动处置全部副本：开放候选移除、已封存批次生成增量更正、公开展示下架；`propagation` 报告逐处交代副本去向 |
| 双人复核分离 | 一审通过后进入二审，二审人与一审人必须是不同自然人 |
| 封存进度崩溃恢复 | 冻结→核验→清单→封存四阶段事件检查点；重启重放日志后从断点续跑，重复封存幂等 |
| 封存后增量更正 | 原清单与哈希永久不可变；REMOVE/REPLACE 以 `prev_hash` 链式生成新版本清单 |
| 回执对账 | 回执按 `receipt_key` 幂等，并绑定具体清单版本；对账区分已发送/失败/缺失/已发后更正移除/无主回执 |
| 公开展示举证 | 发布时冻结授权快照嵌入展示清单哈希；事后可验证「发布时点授权有效且信件在批次清单中」，事后撤回不影响历史举证 |
| 审计不可覆盖 | 哈希链逐条校验；日志被覆盖或截断时服务拒绝启动 |

> `service/crypto.py` 是仅用标准库实现的演示级 Encrypt-then-MAC 构件，
> 部署到生产前必须替换为经审计的 AEAD（AES-GCM/XChaCha20-Poly1305）与 KMS。

## HTTP 接口（请求体为 JSON，身份放在 `actor: {id, roles}` 字段）

- `POST /letters/import` 匿名化收件（幂等）
- `POST /letters/{id}/consent/grant` · `.../consent/revoke` 授权/撤回
- `GET  /letters/{id}` · `GET /letters/{id}/propagation`
- `POST /letters/{id}/review` 双人复核（两轮，不同复核人）
- `POST /letters/{id}/access` 申请短时原文凭据 · `POST /access/{gid}/reveal`
- `POST /batches` · `POST /batches/{id}/items`
- `POST /batches/{id}/freeze|verify|manifest|seal`
- `GET  /batches/{id}` 批次与当前生效清单
- `POST /batches/{id}/corrections` 封存后 REMOVE/REPLACE 增量更正
- `POST /batches/{id}/receipts` · `GET /batches/{id}/reconcile`
- `POST /batches/{id}/displays` · `GET /displays/{id}` ·
  `GET /displays/{id}/proof/{letterId}` 授权快照举证
- `GET /health`
