# 离线安全复核 12804 — 季度轮换接管清单验证

用原生 Windows + Go 标准库 + 本地合成数据，验证「季度轮换时一套备用凭证的授权人被撤回、另一套仍可接管部分服务」情形下的接管清单何时确实有效，并从实际落盘文件独立复验。

题面见 `task/PROMPT.txt`。本仓库不联网、不读取任何真实凭证；所有输入均为确定性合成数据。

## 结论速览（可复现，真实数值）

运行 `go test ./...` 后，`artifacts/headline_numbers.txt` 记录本次实测：

```
GRAPH  48 个穷举用例，2 个有效；Decide 与独立 Reference 判定全一致 (agree=true)
       最小覆盖证据：签核人 [alice bob] + 凭证 [c-merged] 覆盖 [svc-a svc-b]
                     且逐一删除任一元素都失效 → minimal=true
       第一个失效水位：t=500（临时替代权限到期），失效原因
                     [temp_authority_expired, service_coverage_gap]
RECLAIM 50,000 条租户分区凭证，500 个分区
       全量扫描回收 4165 条 (撤销授权人 3750 + 临时权限过期 415)
       局部回收回收 4165 条，仅触达 322/500 个分区（178 个分区未触达）
       逐项核对 50,000 条，差异 0 条，摘要一致 → local == full
       单次撤销的最宽扇出：1 个授权人横跨 81 个分区（跨分区风险真实存在）
VERIFY  从磁盘复验 22 项全部 PASS
```

## 核心判定语义（`internal/model`）

一个「接管决定」当且仅当以下三条**同时**成立才有效：

1. **两名独立人员签核**：≥2 个不同签核人，各自签名绑定 `(signer, requestKey, generation, signedAt)`（HMAC-SHA256），
   签核时刻落在该签核人的授权窗口 `[ValidFrom, ValidTo)` 内、不晚于决定时刻、且签核人未被撤回。
   旧代（generation 不匹配）的签核会被**忽略**——它永远不能“帮”成，但它的存在也**不会污染**一个本来有效的决定。
2. **服务覆盖**：可用凭证合起来覆盖全部必需服务。凭证可用 = 授权人未被撤回，且若借用了临时替代权限，
   该权限在决定时刻仍存活、且从未被墓碑化；借用临时权限的凭证**只能覆盖该权限被授予的服务集**（取交集），
   不能凭自身 `Services` 越权多报服务。
3. **授权代匹配**：请求代、各覆盖凭证代、每条签核代都必须等于该服务当前期望代。

**临时替代权限到期不可同号重投恢复**：权限一旦到期/被墓碑化即永久失效；随后用同一编号重投，
即便数值上 `At < Expires`、签核齐全、代也正确，仍判定为 `temp_authority_replayed_after_expiry` 而拒绝。

`model.Decide` 的 `Valid` 是三条正向条件的严格合取；`Reasons` 仅作诊断。
另有一份独立实现 `model.ReferenceValid`（不同控制流）在 20,000 次随机变异差分测试中与 `Decide` 恒等，
随机样本包含临时权限的部分授权集，从而真正覆盖了交集逻辑。

## 两条工作线程 + 屏障 + 故障点（`internal/harness`）

两条 goroutine（接管 worker / 撤销 worker）由一个**循环屏障**对齐，配合**显式故障点**确定性复现三种情形：

| 场景 | 机制 | 证据要点 |
|------|------|----------|
| `revocation_wins` | 撤销先落盘（rev 1）；接管 worker 仍持旧视图、以 base=0 提交 | 提交因 `ErrStaleRevision` 被拒；事后按已撤销授权重判 → `INVALID(credential_authorizer_revoked, service_coverage_gap)`；日志里**没有** takeover 记录 |
| `lost_response` | 接管先 `fsync` 落盘（rev 1），随后故障点吞掉回应 | 重开日志后同 `RequestKey` 重投 → `Duplicate=true`、返回同一 rev、**不追加第二条**，`Revision` 不变 |
| `old_generation_after_recovery` | 重启后授权代推进到 8，收到代 7 的旧签核 | 旧代签核被拒 (`generation_mismatch` + `too_few_independent_signers`)；换成两条当代签核即有效；上一代记录仍在 |
| `temp_expiry_no_replay` | 临时权限 `T-9`（expires=500）被回收器墓碑化写入日志 | 到期前有效；同号重投在 `At=400 < 500` 下“只看数字”会误判为活，墓碑使其被判 `expired`，并归类为 replay |

每个场景写出 `commit.log`（权威、逐条 `fsync` + 校验和）与 `evidence.json`（有序事件 + 断言）。

## 小图穷举（`internal/graph`）

在 `签核子集 × 代(当期7/过期6) × 签核时间窗(窗内/窗外) × 决定时刻{50,400,600}` 上穷举 48 个用例，
每个用例同时用 `Decide` 与 `ReferenceValid` 判定并核对一致。

- **最小覆盖证据**：找最小有效组合，并做**最小性证明**——逐一删除每个签核、每条凭证，断言结果必失效（`minimal=true`）。
- **第一个失效水位**：沿固定时间线 `{0,100,250,400,499,500,501,750,999,1000,1200}` 保持其余不变推进决定时刻，
  首次由有效翻转为无效的刻度即水位 → **t=500**，触发事件 `temp_authority_expired_at_500`。

## 五万条租户分区凭证：局部回收 vs 全量（`internal/reclaim`）

确定性合成 500 分区 × 100 = 50,000 条凭证。授权人分两类：
- **全局授权人**：跨租户共享，撤销一个会扇出到很多分区——这正是「局部回收」非平凡的根源；
- **每租户本地授权人**：撤销只影响本租户。
另每租户一个临时权限，部分在回收时点已过期。

- `Full()`：扫描全部 500 分区、逐条判定。
- `Local(idx)`：用 `authorizer→partitions`、`temp→partitions` 索引，只触达受影响的分区，返回实际触达分区列表。
- `Compare()`：**逐条**核对全部 50,000 条两法的回收与否及原因，并比较两侧摘要（sha256）。
  另有负向测试证明「只扫一个分区」的伪局部实现会被 `Compare` 判为不一致，比较不是空转。

## 独立复验（`internal/verify` + `cmd/rotationverify`）

`verify` 不信任任何写死的 PASS 标志：
- 经 `store.Open` **重放**每个 `commit.log`（重算校验和、校验 rev 连续 `1..N`），比对修订号与记录类型计数；
- 对图重跑穷举与水位，重判最小证据并**重新做最小性证明**；
- 按参数**重建** 5 万条数据集，重算全量/局部回收与逐项比较、摘要。

篡改测试证明复验确实重读文件：翻转 `commit.log` 中目标值一个字节 → 校验和失败；篡改回收摘要 → 复验失败。

## 目录结构

```
cmd/rotationverify/        CLI：run / verify / summary（dispatch 可在进程内测试）
internal/model/            纯判定逻辑 + 独立参考实现 + 差分模糊测试
internal/store/            追加式 JSONL 提交日志：fsync、校验和、重放、幂等、乐观并发、断尾恢复
internal/harness/          双线程屏障 + 故障点：四种场景与证据
internal/graph/            小图穷举、最小覆盖证据、第一个失效水位
internal/reclaim/          5 万条分区凭证，局部 vs 全量逐项核对
internal/run/              编排全流程、写出 artifacts 树
internal/verify/           从磁盘独立复验
task/PROMPT.txt            题面（已冻结）
```

## 运行

```bash
# 全部单元 + 集成 + 篡改测试；并生成 artifacts/run 证据树与 headline_numbers.txt
go test ./...

# 可选：直接跑 CLI（写证据树，再做独立复验）
go run ./cmd/rotationverify run    -dir artifacts/run
go run ./cmd/rotationverify verify -dir artifacts/run
go run ./cmd/rotationverify summary -dir artifacts/run
```

证据树布局：

```
artifacts/run/manifest.json                       索引（指向各产物）
artifacts/run/faults/<场景>/commit.log            权威提交日志（逐条 fsync + 校验和）
artifacts/run/faults/<场景>/evidence.json         有序事件 + 断言
artifacts/run/graph/enumeration.json              真值表 + 最小证据(含最小性证明) + 水位
artifacts/run/reclaim/summary.json                全量/局部结果 + 逐项比较 + 分区统计
artifacts/headline_numbers.txt                    实测数值速览
```

`artifacts/` 为可确定性再生的生成物，已在 `.gitignore` 中忽略；执行 `go test ./...` 即重建并复验。
