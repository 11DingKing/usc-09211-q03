# 航天家书接力站领域约定

## 基础约定

- 服务采用事件时间（`event_time`，调用方提供的业务发生时间）与接收时间
  （`recorded_time`，服务端落盘时间）分离的记录方式；
- 所有业务身份由调用方提供的稳定标识表示（actor: `{id, roles}`）；
- 审计记录只追加、不覆盖。事件日志为哈希链：每条记录包含上一条记录的哈希，
  启动时整体重算校验，任何覆盖/截断都会导致服务拒绝启动；
- 全部业务状态都是事件日志的投影：崩溃恢复即重放日志，不存在第二份真相源；
- 敏感正文与 PII 仅以密文形式进入事件日志，解密必须出示短时访问凭据。

## 角色

SCHOOL_COORDINATOR（学校收件协调人）、GUARDIAN（监护人）、REVIEWER
（复核编辑）、EDITOR（批次与展示编辑）、CARRIER（上行承运人/回执方）、
AUDITOR（只读审计）。

## 统一凭据链

一封家书的生命周期凭据全部留痕、彼此引用：

1. **收件** `LetterReceived`：信件 ID 由 `学校编码|来源键` 派生；内容指纹
   （NFKC 归一化、压缩空白后 SHA-256）用于跨校去重。重复导入只追加
   `DuplicateImportSuppressed`，不产生第二份记录。
2. **授权** `ConsentGranted/Revoked`：版本化，含范围（REVIEW/UPLINK/DISPLAY）、
   有效期窗口与撤回时间；只有绑定监护人本人可撤回；撤回可重复调用且幂等。
3. **复核** `ReviewDecided`：一审、二审两条独立决定；二审人 ≠ 一审人；
   复核当时必须持有有效 REVIEW 授权。
4. **批次** `BatchCreated/ItemAdded/ItemRemoved/StageChanged/Sealed`：
   封存工序为 OPEN→FROZEN→VERIFIED→MANIFEST_READY→SEALED，每个阶段迁移都是
   检查点事件。封存清单逐条内嵌当时的授权快照；任意阶段崩溃后重启，
   `seal` 从当前检查点幂等续跑。
5. **更正** `BatchCorrectionProposed/ManifestRevised`：封存后只能提出更正，
   新版本清单以 `prev_hash` 链接旧版本，历史清单哈希永不变更。
6. **展示** `DisplayPublished/ItemRemoved`：展示项绑定批次清单哈希与授权快照；
   撤回传播会下架。举证接口只回答一个问题：发布时点，DISPLAY 授权是否有效、
   信件是否在当时的批次清单中。
7. **回执** `ReceiptRecorded`：按 `receipt_key` 幂等，必须落在某一版封存清单
   内；对账报告覆盖已发送、失败、缺失、发送后被更正移除、无主回执五类情况。
8. **原文访问** `AccessGranted/AccessRevealed`：凭据按角色限定范围，
   TTL 上限 15 分钟，仅限申请人本人；解密瞬间再次校验授权有效性。
