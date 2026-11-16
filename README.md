# bmc-snmp-testkit

MIB 驱动的 BMC SNMP 自动化测试框架，附带多人使用的只读 Web 服务。

以目录内 `TTY-T1ZDG-v1.0_20261026.mib` 为默认输入（Web 服务支持各项目上传自己的 MIB）。自动解析 MIB 生成用例，覆盖 `GET / GETNEXT / GETBULK / SET` 与 `SNMP v1 / v2c / v3`，校验 OID 读写、数据类型、取值范围、访问权限、异常输入，以及 trap/inform 的触发条件与上报内容；支持批量执行、用例管理、结果断言与多格式报告。

> **安全声明（务必先读）**
> - 默认 `mode: mock`，**只连接本机 127.0.0.1 的模拟 Agent**，不连接任何真实 BMC。
> - 连接真实设备必须同时设置 `mode: live` 和 CLI `--allow-live`，二者缺一即拒绝启动。
> - `SET` 默认只对可读写配置类 OID 执行，并且 **GET 备份 → SET → 读回 → finally 还原 → 复核**。
> - 电源控制（`serverPowerStatusControl`）、用户增删（`addBmcUser` / `delBmcUser`）、网络 IP 配置、会话删除等节点默认硬阻断或列入黑名单；`--allow-guarded` 还需配合 `config/safety-policy.yaml` 的显式白名单。
> - 框架不会下发 IPMI/Redfish 状态变更命令；trap 触发只允许内存模拟事件与被动监听。
> - 所有凭据在日志、配置快照与报告中脱敏。

---

## 1. 安装

```powershell
python -m pip install -r requirements.txt
# 可选：注册 snmp-test 命令
python -m pip install -e .
```

已验收组合：Python 3.10.11 + `pysnmp==7.1.21` + `pyasn1==0.6.5` + pytest 9.1.1 + PyYAML 6.0.3 + Jinja2 3.1.6。
若未执行 `pip install -e .`，可用 `python -m snmp_test.cli ...`（需设置 `PYTHONPATH=src`），下文两种写法等价。

## 2. 快速开始（全程离线）

```powershell
$env:PYTHONPATH = "d:/AI/SNMP/src"

# 1) 解析 MIB，生成模型与用例仓库
python -m snmp_test.cli generate

# 2) 快速冒烟（只跑 120 条）
python -m snmp_test.cli run --limit 120

# 3) 全量执行（约 7700 条，本地模拟 Agent）
python -m snmp_test.cli run

# 4) 从历史结果重跑失败用例
python -m snmp_test.cli run --rerun runs/<run_id>/results.json

# 5) 重新生成报告
python -m snmp_test.cli report runs/<run_id>

# 6) 单独启动模拟 Agent（手工联调用）
python -m snmp_test.cli mock-agent --seconds 60
```

四个子命令：`generate`、`run`、`mock-agent`、`report`。

`run` 常用参数：

| 参数 | 说明 |
| --- | --- |
| `--config PATH` | 配置文件（全局参数，写在子命令前） |
| `--ids / --tags / --exclude-tags` | 按用例 ID、标签筛选 |
| `--versions / --ops / --modules / --categories` | 按版本、操作、模块、类别筛选 |
| `--limit N` | 只执行前 N 条（优先级 + 稳定 ID 排序） |
| `--rerun PATH` | 重跑历史 `results.json`（或 run 目录）中的 failed/error 用例 |
| `--run-id NAME` | 指定运行 ID，便于两次结果对比 |
| `--dry-run` | 只调度不发送任何 PDU |
| `--no-set` | 本次完全禁用 SET |
| `--allow-guarded` | 显式放行白名单内的高危 SET（危险） |
| `--mode live --allow-live` | 显式连接真实 BMC（危险，默认拒绝） |
| `--oid-baseline` | live 执行前先 WALK 目标，MIB 已声明但设备未实现的 GET OID 直接判 `unsupported`（也可用 `execution.oid_baseline: true` 持久开启） |

通过 pytest 运行（CI / marker 过滤 / `--lf`）：

```powershell
python -m snmp_test.cli generate
python -m pytest -m "v2c and get" -q
# 控制生成的 pytest 用例数量
$env:SNMP_TEST_PYTEST_LIMIT = "40"
python -m pytest -q
```

## 3. 配置

复制 `config/config.example.yaml` 为 `config/config.yaml` 后修改。

| 配置段 | 内容 |
| --- | --- |
| `mode` | `mock`（默认）/ `live` |
| `mib` | 输入 MIB 路径（只读，框架绝不修改） |
| `targets[]` | 多目标批量：名称、host、port、versions、v1/v2c 团体字（读写 + 只读各一套）、v3 USM 用户与 auth/priv 协议密钥、错误凭据样本 |
| `mock` | 模拟 Agent 绑定地址/端口、trap 目的端口、每表行数、只读/读写团体字、v3 用户 |
| `trap` | 监听地址/端口、接收超时、期望文件 |
| `execution` | 并发数、超时/重试、每表行数与用例上限、max-varbinds、GETBULK max-repetitions、SET 开关、`allow_guarded`、`limit`、随机种子 |
| `safety.policy_file` | 安全策略文件 |
| `report` | 输出目录、PDU 采样率、日志级别、trap 期望文件 |

凭据通过环境变量注入，例如 `${SNMP_V3_AUTH_KEY:authpass123}`；未定义环境变量时使用冒号后的默认值（仅用于本地模拟）。

v3 协议取值：`MD5 / SHA / SHA224 / SHA256 / SHA384 / SHA512 / NONE`（认证），`DES / 3DES / AES128 / AES192 / AES256 / NONE`（加密），安全级别 `noAuthNoPriv / authNoPriv / authPriv`。

## 4. 目录结构

```
TTY-T1ZDG-v1.0_20261026.mib   # 输入 MIB（只读）
config/
  config.example.yaml         # 主配置模板（CLI 默认走这份离线模拟配置）
  config.yaml                 # 真实环境配置（需显式 --config 指定）
  web.example.yaml            # Web 服务配置模板（多用户 token / live 白名单）
  safety-policy.yaml          # 高危 OID 黑名单 / 白名单 / 硬阻断
  trap-expectations.yaml      # trap/inform 触发条件与内容期望
src/snmp_test/
  cli.py                      # 四个 CLI 子命令
  config.py                   # 配置、环境变量插值、脱敏、校验
  model/                      # 容错 MIB 解析器 + 归一化 OID 模型
  generator/                  # 值工厂、用例矩阵展开、trap 用例
  snmp/                       # PySNMP 适配层、错误归一化、监听器、触发器、模拟 Agent
  runner/                     # 用例仓库、安全网关、断言库、执行引擎、pytest 桥接
  report/                     # 结果聚合、JSON/HTML/JUnit 输出
  security.py                 # live 闸口 / 目标白名单 / 只读强制 / 轻量 RBAC
  service/                    # FastAPI 应用、多 MIB 库、串行任务队列、Web 页面
cases/generated/              # model.json / cases.json / parse-warnings.json
work/mibs/<id>/               # 每个上传 MIB 的独立模型与用例仓库
work/jobs/                    # 任务持久化与审计日志
runs/<run_id>/                # 每次运行的全部产物
tests/                        # 单元 + 端到端测试
docs/snmp-test-design.md      # 方案设计文档（为什么这样设计）
docs/how-it-works.md          # 白盒说明（实际跑起来发生了什么、怎么自查）
```

## 5. 报告产物

每次运行写入独立目录 `runs/<run_id>/`：

| 文件 | 内容 |
| --- | --- |
| `report.html` | 自包含可视化报告：总体/按版本/按操作/按模块/按目标通过率、失败详情（期望 vs 实际）、可筛选全量用例表、日志片段 |
| `results.json` | 机器可读的 summary + 每条用例结果 + 失败明细 |
| `junit.xml` | CI 可直接消费的 JUnit XML |
| `run.log` | 用例级日志（凭据脱敏） |
| `pdus.jsonl` | 收发 PDU 明细（含错误状态、varbind 类型与值） |
| `config-snapshot.yaml` | 脱敏后的运行配置快照 |
| `mib.sha256` | MIB 哈希 + 解析统计基线 |
| `case-manifest.json` | 本次执行的稳定用例 ID 清单 |
| `safety-policy.json` / `safety-audit.jsonl` | 安全策略与 SET 备份/还原审计 |

**可重复执行**：`case_id` 由 `MIB SHA-256 + 节点名 + OID + 操作 + 版本 + 类别 + 判别码` 派生；相同 MIB 与配置重复 `generate` 得到完全相同的用例集；`--rerun` 固化失败集合；`run_id` 目录隔离，历史产物不覆盖。

## 6. 验收基线（本地模拟 Agent）

| 指标 | 值 |
| --- | --- |
| 有效 OBJECT-TYPE | 1130 |
| OBJECT IDENTIFIER / 表 / 行 / 列 / 标量 | 29 / 39 / 39 / 941 / 111 |
| 访问权限 | read-only 940、read-write 137、write-only 7、not-accessible 46 |
| 被注释掉的定义 | 71（解析时跳过） |
| NOTIFICATION-TYPE | 0（故 trap 期望放在配置文件） |
| 全量用例 | 约 7700 条 |
| 全量结果 | 0 failed / 0 error，有效通过率 100%，另有设计性 skip 与安全阻断 |

示例报告位于 `runs/<run_id>/report.html`（每次全量运行生成，例如仓库内的 `runs/full-*` 目录）；若目录被清理，重新执行 `python -m snmp_test.cli run` 即可生成。

## 7. Web 服务（邮箱账号 / 任务队列 / MIB 浏览器与交互探测）

面向多人分发的 Web 控制台，复用同一套解析、用例、执行与报告内核。批量任务保持只读；MIB 浏览器中的交互探测单独放宽 SET 边界。

```powershell
python -m pip install -r requirements.txt
# 可选：编辑 config/web.yaml（从 config/web.example.yaml 复制）调整 live 白名单
python -m snmp_test.service.app --host 0.0.0.0 --port 8080
# 若已执行 pip install -e .，也可直接用： snmp-test-web --host 0.0.0.0 --port 8080
```

浏览器打开 `http://<服务地址>:8080`，未登录会跳转到 `/login`：

- **注册**：邮箱 + 邮箱验证码 + 密码（至少 8 位），注册成功自动登录；
- **登录**：密码登录，或邮箱验证码登录；
- **权限**：所有注册账号完全一致，没有角色区分；
- **MIB 库共享**：所有账号看到同一份 MIB 列表，都能上传，按内容哈希去重；
- **任务队列隔离**：每个账号只能看到自己的任务、报告和通过率。

**邮件配置**：设置 `SNMP_TEST_SMTP_HOST`、`SNMP_TEST_SMTP_PORT`、`SNMP_TEST_SMTP_USER`、`SNMP_TEST_SMTP_PASSWORD`、`SNMP_TEST_SMTP_FROM`（可选 `SNMP_TEST_SMTP_TLS` / `SNMP_TEST_SMTP_SSL`）后真发邮件。未配置时进入开发模式：验证码写入 `work/mail-dev.log` 并直接显示在登录页。账号、验证码与会话保存在 `work/auth.db`（SQLite），密码用 PBKDF2-HMAC-SHA256 加盐存储，会话为服务端随机 token + HttpOnly Cookie（默认 7 天）。

**MIB 浏览器**（`/mib-browser`）：导入 MIB 后左侧是可展开的 OID 树（组 / 表 / 表项 / 列；WALK 之后还会挂出动态发现的实例行），右侧是结果区。填目标 IP 后单击节点即可即时 `GET` / `WALK`，结果默认按 MIB 表结构聚合成二维表格（行 = 实例、列 = 表列），可切换「Table View / 仅表格 / Raw（原始 OID）」。支持枚举值→文本、OID→节点名、点击行查看完整实例详情、CSV 导出、自动刷新、右键菜单与 `SET`（二次确认）。WALK 按 `cursor` 自动续页取全整表，不受单页 200 条限制；所有操作写入 `work/probe-audit.jsonl`。

主页面「提交只读任务」与探测面板同样固定 `live` 直连真实 BMC，目标 IP 必填；Web 界面不再提供「本地自测」开关。模拟 Agent 仅供 CLI `snmp-test run` / `mock-agent` 与 pytest 离线回归使用——它验证解析 / 生成 / 断言 / SNMP 适配层，**不能证明真机兼容性**。

**内网信任模型与审计**：

- 内网系统，Web 层默认直连真实 BMC（填 IP 即可），不设 `allow_live` / 目标白名单等前置门槛；需要收紧时在 `config/web.yaml` 的 `security.web` 段配置 `allow_live` / `allowed_targets` / `readonly_only` / `live_set_enabled` / `hard_block_enabled`（示例见 `config/web.example.yaml`）。
- `SET` 可用，页面保留二次确认；服务端对 live SET 应用 `config/safety-policy.yaml` 的 `hard_block` / `blacklist` 硬阻断，被策略拒绝的操作同样写入审计（`policy_denied`）。
- **批量任务仍只读**：任务队列只跑 GET，SET 用例、`--allow-guarded`、错误凭据探测与 flood 用例不可达。
- **审计溯源**：MIB 上传 / 删除与任务生命周期写入 `work/jobs/audit.jsonl`，交互探测写入 `work/probe-audit.jsonl`（含 SET 值，不记录团体字 / v3 密钥）。独立页面 `/audit` 把两类日志聚合成统一时间线，覆盖 MIB、任务、探测三类操作，支持按类型 / 账号筛选；`GET /api/audit` 提供同样数据，`GET /api/snmp/audit` 仅查询探测记录。主页面与 MIB 浏览器顶栏都有「操作记录」入口。

**其他默认值**：

- Web 层默认不设 live 白名单（`security.web.allowed_targets: []`），需要收紧时在 `config/web.yaml` 配置；CLI 的 `--allow-live` 与 `Runtime` 的 `SecurityPolicy.enforce` 闸口保持不变，只约束命令行调用。
- 团体字 / v3 密钥只在任务提交或即时探测时经内存注入，不写入任何配置或任务文件；日志、报告、快照全部脱敏。
- 任务队列默认 2 个 worker 并发（`SNMP_TEST_WEB_WORKERS`，上限 4），按目标互斥：同一台 live BMC 同时只跑一个批次，后到的任务标记「等待中」并自动排队。CLI / pytest 的模拟 Agent 端口 `11811 + slot*10`、trap 监听 `11812 + slot*10`（与 CLI `11611/11612`、测试 `11711/11712` 错开）。

**主要接口**

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| GET | `/login` | 登录 / 注册页面（已登录时跳转 `/`） |
| POST | `/api/auth/code` | 发送邮箱验证码（`purpose`: `register` / `login`） |
| POST | `/api/auth/register` | 邮箱 + 验证码 + 密码注册，成功即建会话 |
| POST | `/api/auth/login` | 登录（`method`: `password` / `code`） |
| POST | `/api/auth/logout` | 退出并清除会话 |
| GET | `/api/auth/me` | 当前账号 |
| GET | `/api/config` | 服务能力、白名单、队列状态 |
| POST | `/api/mibs` | 上传 MIB（原始字节 + `X-MIB-Filename`），所有账号共享 |
| GET | `/api/mibs` / `/api/mibs/{id}` | MIB 列表 / 详情（共享） |
| GET | `/api/mibs/{id}/nodes` / `/api/mibs/{id}/cases` | 节点 / 用例浏览，支持搜索、过滤、分页 |
| GET | `/api/mibs/{id}/tree` | 一次返回整棵节点树（MIB 浏览器使用），含父子关系、表列与语法 |
| GET | `/api/mibs/{id}/warnings` | 解析告警、`IMPORTS` 依赖与 SMIv2 严格语法检查结果 |
| DELETE | `/api/mibs/{id}` | 删除 MIB 及其模型与用例（共享库，任何登录账号可删） |
| GET | `/audit` | 操作记录页面（需登录） |
| GET | `/api/audit` | 统一审计时间线，可按 `user` / `category` / `event` / `limit` 查询 |
| GET | `/mib-browser` | MIB 浏览器页面（需登录） |
| GET | `/api/snmp/capabilities` | 探测能力：可用操作、SET 开关、策略状态、审计开关 |
| GET | `/api/snmp/audit` | 审计记录，可按 `user` / `operation` / `limit` 查询 |
| POST | `/api/snmp/probe` | 即时 GET/GETNEXT/WALK/SET，返回 varbind 并写审计 |
| POST | `/api/jobs` | 提交只读任务（归属当前账号） |
| GET | `/api/jobs` / `/api/jobs/{id}` | 仅返回自己的任务 |
| DELETE | `/api/jobs/{id}` | 删除自己已完成的任务及其报告 |
| GET | `/runs/{run_id}/report.html` | 报告，仅任务所有者可访问 |
| GET | `/runs/{run_id}/results.json` | 机器可读结果，仅任务所有者可访问 |

> `SNMP_TEST_DEV_BYPASS=1` 可跳过登录，仅用于本地调试。内网部署请保留登录并依赖 `work/probe-audit.jsonl` 做溯源。批量 trap/inform 用例仍未通过 Web 开放。详见 `docs/how-it-works.md` 第 11 节。

## 8. 常见问题

- **clone 仓库后跑不起来**：`config/config.yaml`、`config/web.yaml`、`cases/generated/`、`work/`、`runs/` 均被 `.gitignore` 排除（含凭据或为生成产物）。先从 `config/*.example.yaml` 复制出本地配置，再执行 `python -m snmp_test.cli generate` 生成用例仓库；MIB 原文件已入库。
- **Web 服务连不上设备**：确认服务端能访问管理网，且 `security.allowed_targets` 已列出目标 IP；未列出会被 403 拒绝。
- **`pysnmp` 导入失败**：执行 `pip install -r requirements.txt`；不要单独升级 `pyasn1`，7.x 分支与 4.4.x 的 API/依赖不兼容。
- **端口被占用**：修改 `config.example.yaml` 中 `mock.port` / `trap.listen_port` 与 `targets[].port`，三者需一致。
- **想验证真实 BMC**：先复制配置、填写目标与凭据，再使用 `--config config/config.yaml --mode live --allow-live` 形式的命令；建议先 `--no-set --dry-run` 试跑。
- **用例太多**：调小 `execution.max_cases_per_table`（GET 始终覆盖全部 OID），或使用 `--limit` / `--tags` 筛选。
- 更多设计细节见 `docs/snmp-test-design.md`。
- **觉得框架像黑盒子**：读 `docs/how-it-works.md`，它用一条真实用例串起「MIB → 用例 → PDU → 断言 → 报告」全过程，并给出可直接复制的自查命令。
