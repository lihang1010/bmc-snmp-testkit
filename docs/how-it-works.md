# bmc-snmp-testkit 白盒说明：这套框架到底做了什么

> 面向读者：不想只看到「通过率 100%」，而想知道**每一步读了什么、发了什么、凭什么判通过、去哪里核对**的人。
>
> 本文所有数字都取自仓库内真实产物：`cases/generated/model.json`、`cases/generated/cases.json`、`runs/verify-a/results.json`、`runs/live-v1-get-01/results.json`。文中出现的 `TC-007a36974e5dea26` 是一条真实用例，可全文检索。
>
> 另一份 `docs/snmp-test-design.md` 讲的是「为什么这样设计」；本文讲的是「实际跑起来发生了什么」。

---

## 1. 先记住五个文件

框架不是常驻服务，没有数据库，没有隐藏状态。**所有中间结果都落盘**，这是去黑盒化的基础：

| 文件 | 谁生成 | 装什么 |
| --- | --- | --- |
| `cases/generated/model.json` | `generate` | 从 MIB 解析出的全部节点、数值 OID、语法、访问权限、表结构、解析统计与告警 |
| `cases/generated/cases.json` | `generate` | 全部用例的**完整定义**（请求参数 + 期望断言），不是摘要 |
| `runs/<run_id>/pdus.jsonl` | `run` | 每条用例实际收发的结构化响应（OID、类型、值、错误状态） |
| `runs/<run_id>/results.json` | `run` | 每条用例的 status / message / expectation / actual |
| `runs/<run_id>/safety-audit.jsonl` | `run` | 每次 SET 的备份值、请求值、还原复核结果 |

换句话说：**用例是数据，期望是数据，实际响应也是数据**。执行引擎只是一个「把 expectation 和 actual 交给断言库比较」的调度器，没有藏在代码里的隐式判定。

---

## 2. 一次 `run` 的完整时间线

以本轮真实命令为例：

```powershell
python -m snmp_test.cli --config config/config.yaml run --allow-live --no-set `
  --versions v1 --ops GET --categories normal --exclude-tags auth,flood --limit 10 `
  --run-id live-v1-get-01
```

| # | 阶段 | 实际动作 | 可核对位置 |
| --- | --- | --- | --- |
| 1 | 配置加载 | 读 `config/config.yaml`，与代码内 `DEFAULT_CONFIG` **深合并**（字典合并、列表整体替换），再做 `${VAR:default}` 环境变量插值 | `config/config.yaml`；`src/snmp_test/config.py` 的 `load_config` |
| 2 | 配置校验 | 检查 mode、MIB 存在、target host/port、版本合法；仅当启用 v3 才要求 USM 五字段 | `Config.validate()` |
| 3 | live 闸口 | `mode: live` 且 CLI 带 `--allow-live` 才继续，否则退出码 2、不发任何包 | `cli.py` 的 `cmd_run` |
| 4 | 加载用例 | 读 `cases/generated/cases.json`（7703 条），按 `--versions/--ops/--categories/--exclude-tags/--limit` 过滤 → 本轮 10 条 | `CaseStore.select()` |
| 5 | 启动运行时 | 建一个事件循环、会话池、`trap` 监听器、结果收集器；**只有 `mode: mock` 才启动本地模拟 Agent** | `Runtime.start()` |
| 6 | 逐用例调度 | 只读用例按 `concurrency` 信号量并发（每批 400 条）；SET 按目标串行加锁；trap 全局串行 | `executor.py` |
| 7 | 安全复核 | 每个 SET 用例再次分级校验；非 SET 直接放行 | `SafetyGateway.check()` |
| 8 | 发 PDU | 按 `(target, version, credential-override)` 复用一个 `SnmpEngine`；构造 varbind → 发 UDP → 归一化响应 | `snmp/transport.py` |
| 9 | 断言 | 把 `TestCase.expectation.assertions` 逐条与 `SnmpResponse` 比较，收集所有失败原因 | `runner/assertions.py` 的 `evaluate()` |
| 10 | 收集 | 每条用例写 `pdus.jsonl` 一行 + `run.log` 一行 + `ResultCollector.results` | `report/collector.py` |
| 11 | 出报告 | 关会话/监听；写 `results.json`、`report.html`、`junit.xml`、脱敏配置快照、MIB 哈希、用例清单 | `report/writers.py` |

**关键点**：第 8 步之前的所有东西都能在磁盘上看到。即使完全不看代码，比对 `cases.json` 与 `pdus.jsonl` 就能知道「框架打算问什么」和「设备实际答了什么」。

---

## 3. 用例是怎么从 MIB 变出来的

### 3.1 解析：先把 MIB 变成 OID 表

MIB 文件本身**只读，绝不修改**。`generate` 用自研容错解析器（不用 pysmi，因为这份 MIB 不是合法 SMIv2）做两遍扫描：先剥注释，再按 `OBJECT-TYPE / OBJECT IDENTIFIER / SEQUENCE` 分块。

真实基线（`model.json.stats`）：

| 项 | 值 |
| --- | --- |
| 源文件行数 | 11414 |
| 模块名 | `TTY-T4XDG-v1-4-MIB`（与文件名不一致，唯一一条解析告警 `MODULE_FILENAME_MISMATCH`） |
| 企业根 OID | `1.3.6.1.4.1.52305` |
| 解析出的节点 | 1159（全部成功解析，`unresolved_nodes: 0`） |
| 分类 | 列 941、标量 111、表 39、行 39、组 29 |
| 访问权限 | read-only 940、read-write 137、not-accessible 46、write-only 7 |
| 内联枚举块 | 91 |
| 被注释掉的定义 | 71 个 OBJECT-TYPE + 9 个 OBJECT IDENTIFIER（**跳过，不参与 OID 编号**） |
| `NOTIFICATION-TYPE` | **0**（所以 trap 期望只能写在配置文件里） |

### 3.2 OID 是算出来的，不是抄的

`model.json` 里每个节点都带数值 OID。以本轮真实读到值的 `fruProductName[2]` 为例，父子链是：

```
ttyRoot          ::= { enterprises 52305 }        -> 1.3.6.1.4.1.52305
serverAssetInfo  ::= { ttyRoot 2 }                -> 1.3.6.1.4.1.52305.2
fruTable         ::= { serverAssetInfo 2 }        -> 1.3.6.1.4.1.52305.2.2
fruEntry         ::= { fruTable 1 }               -> 1.3.6.1.4.1.52305.2.2.1
fruProductName   ::= { fruEntry 10 }              -> 1.3.6.1.4.1.52305.2.2.1.10   （列）
实例行索引 INDEX { fruIndex } = 2                 -> 1.3.6.1.4.1.52305.2.2.1.10.2
```

标量追加 `.0`，表列追加 `.<行号>`（行数由 `execution.rows_per_table` 控制，当前 2）。解析器迭代求解 `::= { 父名 数字 }`，支持前向引用；无法解析的父节点会记入 `parse-warnings.json` 并排除，不会静默丢。

### 3.3 用例编号是稳定的

```
case_id = "TC-" + sha256(
    mib_sha256 | 用例名 | OID | 操作 | 版本 | 类别 | 判别码
)[:16]
```

同一份 MIB + 同一套生成参数，重复 `generate` 得到的 `cases.json` **字节一致**（已验证）。改了 MIB 或生成参数，编号整体变化，避免旧用例与新期望错配。

### 3.4 当前用例仓库的真实构成（7703 条）

| 维度 | 分布 |
| --- | --- |
| 操作 | GET 5993、SET 1532、GETNEXT 141、GETBULK 31、TRAP 4、INFORM 2 |
| 版本 | v1 2557、v2c 2573、v3 2573 |
| 类别 | normal 6522、invalid 729、boundary 393、access 52、trap 6、compat 1 |
| 安全分级 | safe 7562、guarded 93、blocked 48 |
| 优先级 | 1 → 760 条、2 → 789 条、3 → 6153 条、5 → 1 条 |

为什么要这么多：GET 对**每个标量实例和每个表列行**都生成一条，覆盖全部 OID；SET/GETNEXT/GETBULK 按 `max_cases_per_table: 8` 限量，避免组合爆炸。`compat: 1` 是那条「v1 不支持 GETBULK」的显式跳过用例。

---

## 4. 把一条用例拆开看（黑盒 → 白盒）

下面这条是从 `cases.json` 原样摘出的真实用例，不是示意：

```json
{
  "case_id": "TC-007a36974e5dea26",
  "name": "GET fruProductName[2]",
  "oid": "1.3.6.1.4.1.52305.2.2.1.10.2",
  "operation": "GET", "version": "v1", "category": "normal",
  "module": "serverAssetInfo", "safety": "safe", "priority": 3,
  "tags": ["get", "v1", "normal", "column", "serverAssetInfo", "fruTable"],
  "payload": {
    "varbinds": [{"oid": "1.3.6.1.4.1.52305.2.2.1.10.2", "asn1": "Null", "value": null}]
  },
  "expectation": {
    "assertions": [
      {"kind": "no_error"},
      {"kind": "varbind_count", "min": 1},
      {"kind": "value_type", "allowed": ["OctetString", "DisplayString", "Opaque", "Bits"]},
      {"kind": "oid_equals", "oid": "1.3.6.1.4.1.52305.2.2.1.10.2"}
    ]
  }
}
```

**执行时发生了什么**

1. `payload.varbinds` 的 `asn1: Null` 表示「只问不写」，`transport.py` 用 `ObjectType(ObjectIdentity(oid))` 构造 GetRequest-PDU。
2. v1 认证用 `CommunityData(<配置的 v1 团体字>, mpModel=0)`；`timeout_s: 3.0`、`retries: 0`。
3. 设备回答后，`_to_varbind()` 把 ASN.1 对象转成 `{oid, type, value, exception}`：整数转 `int`，其余取 `prettyPrint()`；`NoSuchObject` 等异常对象会带 `exception` 标记。
4. 响应归一化成 `SnmpResponse(error_indication, error_status, error_index, varbinds[])`。v1 的 `noSuchName`、v2c/v3 的异常变量绑定在这里被统一语义化。
5. 断言库逐条比对，真实结果（来自 `runs/live-v1-get-01/results.json`）：

```json
{
  "case_id": "TC-007a36974e5dea26",
  "status": "passed",
  "message": "all assertions passed",
  "actual": {
    "error_indication": null,
    "error_status": "noError",
    "varbinds": [{
      "oid": "1.3.6.1.4.1.52305.2.2.1.10.2",
      "type": "OctetString",
      "value": "CRPS2000D2  ",
      "exception": null
    }],
    "target": "bmc-lab-01",
    "elapsed_ms": 1632.94
  }
}
```

4 条断言全部成立：`noError` ✓、1 个 varbind ✓、`OctetString` 在允许集合 ✓、回显 OID 相同 ✓ → `passed`。

**失败长什么样**：同一轮 `raidPhysicalInfoSize[2]` 断言里同样有 `no_error`，但设备回 `error_status: noSuchName` + `NoSuchObject` 异常 → 断言 `no_error` 失败，status 判 `failed`，message 是 `expected no error, got indication=None status='noSuchName'`。**失败原因就写在结果里，不需要猜**。

断言种类是固定的一批（`no_error` / `rejected` / `no_such` / `end_of_mib` / `auth_rejected` / `value_type` / `value_in` / `value_in_range` / `value_length` / `oid_gt` / `oid_order` / `trap_*` 等），全部由 `expectation` 数据驱动，执行引擎里没有「按用例名做特殊处理」的分支。

---

## 5. SET 到底会不会动我的设备

这是最需要透明的部分。分三层：

**第一层：生成期分级**（写进用例的 `safety` 字段）

- `blocked`（48 条）：`serverPowerStatusControl`（电源开关/重启）、`addBmcUser` / `delBmcUser` 等，命中 `config/safety-policy.yaml` 的 `hard_block`，**任何开关都不执行**。
- `guarded`（93 条）：IP 地址/网关、口令与团体字、用户与会话增删、`write-only` 节点。需要 `--allow-guarded` **且**节点名出现在 `whitelist.names` 才会放行。
- `safe`（7562 条）：普通 read-write 配置节点。

**第二层：执行期复核**。`SafetyGateway.check()` 对每个 SET 再查一次；`enable_set: false` 或 `--no-set` 会让所有 SET 直接判 `blocked`，一个 SET PDU 都不会发。当前 `config/config.yaml` 里 `enable_set: false`、`allow_guarded: false`，且 `whitelist.names: []`。

**第三层：即使放行也强制回滚**。`guarded_set()` 的真实顺序：

```
GET 备份  ->  若备份失败/带异常：直接拒绝 SET（不写）
SET      ->  成功后 GET 读回校验
finally:
   若 SET 成功：SET 还原原值 -> GET 复核；还原失败抛 SafetyAbort，
                该目标剩余所有 SET 用例判 ERROR 并停止（防止状态漂移）
   若 SET 被拒绝：跳过还原（本来就没改成，也不会误报还原失败）
写 safety-audit.jsonl：备份值 / 请求值 / set_ok / restore_verified
```

备份时按 ASN.1 类型归一化（`Integer32`/`OctetString`/`IpAddress`），不支持的类型直接拒绝 SET。

**本轮实证**：`runs/live-v1-get-01/pdus.jsonl` 与 `live-v1-get-02/pdus.jsonl` 的 operation 统计分别是 `{'GET': 10}` 和 `{'GET': 3}` —— **13 个 PDU 全是 GET，没有任何 SET**。

---

## 6. 报告里的数字怎么算

**五种 status**

| status | 含义 |
| --- | --- |
| `passed` | 所有断言成立 |
| `failed` | 至少一条断言不成立（期望 vs 实际不符） |
| `error` | 框架层异常（超时未归类、还原中止、代码异常） |
| `skipped` | 设计性跳过（如 v1 不支持 GETBULK、`--dry-run`） |
| `blocked` | 安全策略拦截，**是策略生效的证据，不是漏测** |

**两个通过率**

```
pass_rate            = 100 * passed / total
effective_pass_rate  = 100 * passed / (passed + failed + error)
```

后者把 `skipped` / `blocked` 从分母剔除，衡量「真正跑了的用例里有多少通过」。分组统计有 4 个维度：`by_version` / `by_operation` / `by_module` / `by_target`。

真实对照：

| 运行 | total | passed | failed | error | skipped | blocked | pass_rate | effective |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `verify-a`（模拟 Agent 全量） | 7703 | 7561 | 0 | 0 | 1 | 141 | 98.16% | 100% |
| `live-v1-get-01`（真实 BMC 探活） | 10 | 9 | 1 | 0 | 0 | 0 | 90% | 90% |
| `live-v1-get-02`（复核 RAID 表） | 3 | 0 | 3 | 0 | 0 | 0 | 0% | 0% |

> 注意：`summary.overall.duration_ms` 是**各用例耗时之和**（并发时含排队等待），会远大于真实墙钟时间；真实耗时看 `summary.duration_s`。

**每次运行的产物**（`runs/<run_id>/`）

`report.html`（自包含、可搜索筛选）、`results.json`、`junit.xml`（CI）、`run.log`（用例级日志）、`pdus.jsonl`（收发明细）、`config-snapshot.yaml`（脱敏配置）、`mib.sha256`（输入哈希 + 解析统计）、`case-manifest.json`（本次 case_id 清单）、`safety-policy.json`、`safety-audit.jsonl`。

历史运行目录互不覆盖；`snmp-test report <run_dir>` 可从已有 `results.json` 重渲染报告。

---

## 7. 自查手册：不用信我，自己核对

```powershell
# 1) 用例仓库里到底有哪些用例、期望是什么
python -c "import json;d=json.load(open('cases/generated/cases.json',encoding='utf-8'));print(d['total'],d['meta'])"

# 2) 定位某条用例的完整定义（含期望断言）
python -c "import json;d=json.load(open('cases/generated/cases.json',encoding='utf-8'));print(next(c for c in d['cases'] if c['case_id']=='TC-007a36974e5dea26'))"

# 3) 某次运行到底发了什么类型的 PDU（确认没有 SET）
python -c "import json,collections;print(collections.Counter(json.loads(l)['operation'] for l in open('runs/live-v1-get-01/pdus.jsonl',encoding='utf-8')))"

# 4) 某条用例的「期望 vs 实际」
python -c "import json;d=json.load(open('runs/live-v1-get-01/results.json',encoding='utf-8'));r=next(x for x in d['results'] if x['case_id']=='TC-007a36974e5dea26');print(r['expectation'],r['actual'])"

# 5) 凭据是否泄漏
Select-String -Path runs/live-v1-get-01/* -Pattern '<替换为你的团体字>' -SimpleMatch

# 6) 只调度、不发任何包（验证筛选结果）
python -m snmp_test.cli --config config/config.yaml run --allow-live --no-set --dry-run --limit 20

# 7) 只重跑失败用例
python -m snmp_test.cli --config config/config.yaml run --allow-live --no-set --rerun runs/live-v1-get-01/results.json

# 8) 重复执行一致性（两次全量运行的 case_id 与 status 逐条相同）
python -c "import json;a=json.load(open('runs/verify-a/results.json',encoding='utf-8'));b=json.load(open('runs/verify-b/results.json',encoding='utf-8'));print({r['case_id']:r['status'] for r in a['results']}=={r['case_id']:r['status'] for r in b['results']})"
```

**脱敏范围**：`collect_secrets()` 从配置里收集所有键名含 `community / auth_key / priv_key / password / secret / token / key` 的值，`CredentialMaskingFilter` 在 `run.log` 与控制台替换；`config-snapshot.yaml` 用 `mask_secrets()` 输出；`pdus.jsonl` 压根不记录团体字/密钥，只记 OID、类型、值、错误状态。已实测真实团体字在快照与日志中均不可见。

---

## 8. 坦白讲清当前边界（这些地方还不是「全自动」）

| 边界 | 现状 | 影响 |
| --- | --- | --- |
| MIB 声明 ≠ 实机实现 | GET 用例默认断言 `no_error`，设备回 `noSuchName` / `NoSuchObject` 就判 `failed` | 真实 BMC 上未实现的表/行会集中报 failed。**这不是协议缺陷**。本轮 `raidPhysicalInfoTable` 整表 4 个 OID 全 NoSuchObject 即属此类。目前**没有 OID 基线机制**去区分「预期缺失」与「真实缺陷」 |
| trap/inform 在 live 下跑不通 | 监听器用专用关联 varbind `1.3.6.1.4.1.52305.9.1.0`（值=case_id）匹配，只有本地模拟 Agent 会注入；`trap-expectations.yaml` 6 条期望都是 `type: mock_event`，live 下没有模拟 Agent | 真实 BMC 的 trap 不会带该 varbind，用例会超时失败。需改为按 `version + pdu_type + trap_oid + source + 时间窗` 匹配，并把 trigger 改成 `passive` |
| trap 监听器凭据来源 | `TrapListener.start()` 读的是 `mock.communities` / `mock.v3`，不是 `targets[]` | live 下要收 v3 trap，必须把 BMC 的 trap 凭据也填进 `mock` 段 |
| GETNEXT/GETBULK 起点 | 起点基于 MIB 声明的列 OID，未做实机 OID 树发现 | 实机 OID 树与 MIB 不一致时，顺序断言可能失败 |
| `--ops` / `--modules` 等筛选 | 精确字符串匹配，不是模糊匹配 | 写错大小写会筛出 0 条 |
| `--config` 参数位置 | 是**全局参数**，必须写在子命令之前 | `run --config ...` 会报 unrecognized arguments |

---

## 9. 本轮真实环境实测记录

| 项 | 值 |
| --- | --- |
| 目标 | 管理网内一台 BMC（SNMPv1，端口 161）；IP 与团体字写在本地 `config/config.yaml`，该文件已被 `.gitignore` 排除 |
| 授权范围 | **仅只读 GET**；`config/config.yaml` 中 `enable_set: false`，CLI 加 `--no-set --allow-live` |
| 排除项 | 第一轮 `--ops GET --categories normal --exclude-tags auth,flood --limit 10`（不打错误凭据、不发 21 varbind 的 flood 包）；第二轮仅按 `--ids` 指定 3 条同表只读 GET |
| 实际 PDU | 10 + 3 = **13 个 GET，0 个其它操作** |
| 结果 | 9 通过 / 1 失败；读到 `CRPS2000D2`、`6020 Rpm`、`P5V_SYS`、`12VPSU0_IIN`、`0x8040`、`10` 等真实值 |
| 失败结论 | `raidPhysicalInfoTable` 整表未实现（3 条复核 GET 全 NoSuchObject），属 MIB 与实机差距 |
| 产物 | `runs/live-v1-get-01/`、`runs/live-v1-get-02/` |

**尚未执行且需要另行授权**：SET、错误凭据用例、GETNEXT/GETBULK、trap/inform、v2c/v3、以及任何其它设备。

---

## 10. 常见误解

- **「100% 通过率说明设备完全正常」** → 只说明「在模拟 Agent 上、按当前断言集合」全部成立。`verify-a` 的 100% 是有效通过率，同时有 141 条 `blocked` 和 1 条 `skipped` 根本没跑。
- **「blocked 是漏测」** → 恰恰相反，是安全策略生效。想跑这些用例需要显式白名单 + `--allow-guarded`，硬阻断项永远不放行。
- **「failed 一定是设备坏了」** → 看 `results.json` 的 `message` 和 `actual`。真实环境里最常见的是 MIB 声明了但设备没实现。
- **「改用例要改代码」** → 不需要。`cases.json` 就是用例仓库，按 `case_id` 检索；筛选、跳过、重跑都走 CLI 参数。要长期调整期望，改 `config/trap-expectations.yaml` 或生成参数后重新 `generate`。
- **「报告是框架自己算的，没法验」** → 用第 7 节的命令，从 `cases.json` + `pdus.jsonl` 可以独立复算任何一条用例的结论。

---

## 11. Web 服务版本（多人 / 只读 / 多 MIB）

服务层不重写测试内核，只是在外面加了「多用户隔离 + 串行调度 + 报告分发」。

### 11.1 新增了什么，改了什么

| 新增 | 作用 |
| --- | --- |
| `src/snmp_test/security.py` | **把 live 闸口从 CLI 下沉到 `Runtime`**：`SecurityPolicy.enforce()` 校验 `allow_live` 与 `allowed_targets`；`readonly_only` 强制 `enable_set=False` 并拒绝非只读操作；`AuthStore` 提供轻量 per-user token/RBAC |
| `src/snmp_test/service/mibs.py` | 按内容 SHA-256 分目录 `work/mibs/<id>/`，每个 MIB 存原文件 + `model.json` + `cases.json` + `parse-warnings.json` + `meta.json` |
| `src/snmp_test/service/jobs.py` | 单 worker 串行队列、`JobStore`（`work/jobs/jobs.jsonl` + `audit.jsonl`）、内存注入凭据、只读用例筛选、写出报告 |
| `src/snmp_test/service/app.py` | FastAPI 路由、会话 cookie、鉴权、报告分发、`/api/config` 能力查询 |
| `config/web.example.yaml` | 多用户 token、live 白名单配置模板 |

**改动**：`executor.py` 的 `Runtime` 现在接受 `SecurityPolicy` 并在构造时就调用 `enforce()`；`cli.py` 把 `--allow-live` 转成同一策略对象；`config.py` 默认配置回退到 `config/config.example.yaml`（避免不加 `--config` 时误读 live 配置）；`pytest_plugin.py` 固定使用模拟配置。

### 11.2 一次 Web 任务的完整链路（照样可核对）

```
POST /api/mibs  -> work/mibs/<id>/{原MIB, model.json, cases.json, meta.json}
POST /api/jobs  -> work/jobs/jobs.jsonl（public_dict，无凭据）
               -> runner.queue（单 worker）
               -> load_config(web.yaml, overrides={目标/版本/凭据/端口/只读策略})
               -> 筛选用例：operations={GET}, categories={normal},
                  exclude_tags={auth,flood,negative,guarded,blocked}, limit
               -> run_batch(..., security=SecurityPolicy(readonly_only=True))
               -> runs/web-<job_id>/{report.html, results.json, pdus.jsonl, ...}
GET /api/jobs/{id}           -> 状态与通过率
GET /runs/{run_id}/report.html -> 带鉴权的静态报告
```

每一步产物都在磁盘上：`work/mibs/<id>/cases.json` 是这次任务用的用例定义，`runs/web-<job_id>/pdus.jsonl` 是实际收发，`work/jobs/audit.jsonl` 记录谁在何时提交了什么。

### 11.3 多人场景的安全边界（与单人 CLI 的差异）

| 约束 | CLI 单人版 | Web 多人版 |
| --- | --- | --- |
| live 确认 | 命令行 `--allow-live` | admin 角色 + `security.allow_live` + 目标白名单，三层同时满足 |
| 闸口位置 | 曾在 `cli.py`（Python API 可绕过） | 下沉到 `Runtime.__init__`，API 与 CLI 共用 |
| SET | 可用（有备份/还原/黑名单） | **不可达**：`readonly_only=True` 强制关闭，且只提交 GET 用例 |
| 凭据 | `config/config.yaml` 明文（输出脱敏） | 每次任务提交时在内存注入，不写入任何文件 |
| 并发 | 单进程单任务 | 单 worker 串行，队列排队 |
| MIB | 唯一全局 `cases/generated/` | 每人/每项目内容寻址隔离 |
| 报告 | 本地文件 | 带鉴权的 HTTP 路由 |

### 11.4 已验证与仍是 MVP 的部分

已验证（`tests/test_service_security.py`、`tests/test_web_api.py` 共 13 项）：API 无法绕过 live 确认、白名单拒绝、只读策略生效、两份不同 MIB 的 `case_id` 集合完全不重叠、同内容 MIB 去重、凭据不落盘、`pdus.jsonl` 只有 GET、报告需鉴权、真实 uvicorn 进程 `/health` 与首页可访问。

仍是 MVP、生产前需替换：

- `AuthStore` 是轻量 token/RBAC 占位（常量时间比较 + HttpOnly cookie），应换成 OIDC/LDAP 与真实会话签名；
- trap/inform 与 SET 暂未通过 Web 开放；
- 任务状态存在单机 JSONL，多实例部署需要换成共享存储；
- `live` 只读 GET 仍需按第 8 节所述补 OID 基线，否则未实现的 MIB 表会集中报 failed。
