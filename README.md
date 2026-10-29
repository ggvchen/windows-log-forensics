# windows-log-forensics

一个 **Windows 日志取证技能**：把一份 `.evtx` 讲成「谁、什么时候、用什么手法、留下了什么证据」。

不装 Splunk、不装 ELK、不写 Python 解析二进制 EVTX —— 只用 Windows 自带的 PowerShell + .NET，
一条命令把散落在上万条事件里的攻击链串成时间线。

面向入侵回溯 / 应急响应 / CTF 日志题 / 内网事件排查。

## 它解决什么问题

拿到一个 `.evtx`，常见困境是：打开事件查看器一条条翻，4720 找到了但不知道是谁干的，
4624 有几百条但分不清哪条是攻击者的 RDP，4698 里的任务 XML 要手动找 `<Command>`。

更麻烦的是**判断**：`WIN-XXXX$` 建了个用户，到底是攻击者还是系统？
4732 里成员名显示 `-`，怎么知道加的是哪个账户？

这个技能把整套排查路径沉淀成一条命令和一个决策框架，并固化成可被 AI 助手直接调用的 WorkBuddy Skill。

## 安装

### 作为 WorkBuddy 技能

```bash
git clone https://github.com/ggvchen/windows-log-forensics.git ~/.workbuddy/skills/windows-log-forensics
```

之后在会话里说「分析这个日志」「攻击者 IP 是多少」即可自动触发。

### 只当命令行工具用

```powershell
git clone https://github.com/ggvchen/windows-log-forensics.git
powershell -File windows-log-forensics/scripts/parse_evtx.ps1 -Path 你的日志.evtx -Mode summary
```

要求：Windows + PowerShell 5.1（系统自带，无第三方依赖）。`.evtx` 需先解压，`-Path` 也支持整个目录。

### macOS / Linux

```bash
python3 -m pip install --user python-evtx
git clone https://github.com/ggvchen/windows-log-forensics.git
python3 windows-log-forensics/scripts/parse_evtx.py -Path 你的日志.evtx -Mode summary
```

参数与 ps1 版完全一致：`-Path / -Mode / -Ids / -Out / -MaxEvents`，另有 `-Utc`。
差异见下文「本机适配」。

## 快速开始

```powershell
# 1. 定盘子：事件总量、时间范围、主机名、EventID 直方图
.\parse_evtx.ps1 -Path Security.evtx -Mode summary

# 2. 锁定施控源：只看带真实远端 IP 的登录（自动排除 127.0.0.1 / ::1 / -）
.\parse_evtx.ps1 -Path Security.evtx -Mode netlogons

# 3. 账户全生命周期：4720/4722/4724/4732/4738 正文全文
.\parse_evtx.ps1 -Path Security.evtx -Mode accounts

# 4. 持久化：4698 自动解析 TaskContent XML，直出 Command / Trigger / RunAs
.\parse_evtx.ps1 -Path Security.evtx -Mode tasks

# 5. 精读任意事件（多个 ID 用逗号或空格分隔）
.\parse_evtx.ps1 -Path Security.evtx -Mode dump -Ids 4624,4648,4688
.\parse_evtx.ps1 -Path Security.evtx -Mode dump -Ids "4624 4648 4688"

# 6. 一键全量导出（CSV + TXT 落到 analysis_out\）
.\parse_evtx.ps1 -Path C:\case -Mode all -Out C:\case\out
```

## 七种模式

| 模式 | 作用 | 输出 |
|---|---|---|
| `summary` | 事件量、时间跨度、主机、EventID/通道直方图 | 控制台 |
| `logons` | 4624/4625 结构化表（登录类型、账户、源 IP、端口、进程） | 控制台 + `logons.csv` |
| `netlogons` | 仅带远端 IP 的登录，按 IP+类型+账户聚合出首末时间 | 控制台 + `netlogons.csv` |
| `accounts` | 账户/组变更事件全量正文 | 控制台 + `accounts.txt` |
| `tasks` | 计划任务与服务安装，解析任务 XML | 控制台 + `tasks.txt` |
| `dump` | 按 `-Ids` 精读任意事件正文 | 控制台 |
| `all` | 以上全部导出 | `analysis_out\` |

## 本机适配（macOS / Linux）

`scripts/parse_evtx.py` 是 ps1 的等价移植，七种模式与参数一一对应：

| 差异点 | ps1（Windows） | py（macOS / Linux） |
|---|---|---|
| 依赖 | PowerShell 5.1 | `python-evtx` |
| 事件正文 | `FormatDescription()` 原句 | 结构化字段块 + 解析后的任务 XML |
| 时区 | 本机时区 | 本机时区，`-Utc` 可强制 UTC |
| 单模式 `-Out` | 仅 `all` 生效 | 任意模式均可落盘 |
| 损坏日志 | 读到坏记录为止 | 额外做 `4096 + N*65536` 结构校验，截断即告警 `PARTIAL results` |
| 性能 | 9707 条约 1.2s | 9707 条约 16–17s（纯 Python，约 1.6 ms/事件） |

## 测试（本机全量回归）

```bash
python3 tests/test_modules.py          # 自动寻找 ../*.zip 或 *.evtx 作为样本
WLF_CASE=/path/to/case.evtx python3 tests/test_modules.py
```

首次运行会把 System / TerminalServices 通道样本下载到 `tests/.cache/`（不入库）；
离线时相关用例自动 SKIP。用例分六类：功能、边界、数据质量、多通道、性能、交叉验证。

本机实测（macOS 14 / Python 3.9）：**48 个用例全部通过，总耗时约 5 分钟**；
9707 条 Security 日志 `summary` 17.2s、`all` 16.1s。

## 实测

对一份 5.3MB / 9707 条 Security 日志（单通道，跨 2009–2021）跑 `summary`，耗时 **1.2 秒**，
`netlogons` 直接给出结论：

```
Count Ip                        EventId LogonType User             Domain  First               Last
   19 fe80::ddc8:84a4:f475:6091    4624 3         WIN-WH8G5MDPHE5$ ADOFLMB 2021-09-16 18:27:20 2021-09-16 18:27:31
    6 192.168.222.100              4624 3         WIN-WH8G5MDPHE5$ ADOFLMB 2020-04-15 12:57:19 2021-09-16 18:27:24
    2 192.168.222.200              4624 10        attack$          ADOFLMB 2020-07-22 10:52:06 2020-07-22 10:52:06
   58 fe80::9928:4a51:962d:d7fa    4624 3         WIN-WH8G5MDPHE5$ ADOFLMB 2020-04-15 12:55:54 2020-07-22 10:51:56
    2 192.168.222.200              4625 3                          .       2020-07-22 10:50:16 2020-07-22 10:50:31
    1 192.168.222.141              4625 3                          .       2020-03-28 15:02:11 2020-03-28 15:02:11
```

一眼可判：`.100` 是域控机器账户流量、`fe80::` 是本地链路、`.141` 只有一次失败（扫描）、
**`.200` 既发起失败登录，又是唯一一条 LogonType=10 的 RDP 源** —— 施控源即 `192.168.222.200`。

`tasks` 模式自动把 4698 的 XML 拆成可读字段：

```
========== ID=4698  Time=2020-07-22 10:51:15 ==========
任务名称:  \callback
  --- parsed TaskContent ---
  Command : c:\windows\system32\windows_attack.exe
  Trigger : 2020-07-22T10:51:00  interval=PT1M
  Author  : SYSTEM
  RunAs   : ADOFLMB\WIN-WH8G5MDPHE5$
```

完整攻击链（8 个事件、2 分钟）还原：

| 时间 | ID | 内容 |
|---|---|---|
| 10:50:16 | 4625/5140 | 匿名访问 `IPC$`，主机名随机 16 位 |
| 10:50:31 | 5140 | 访问 `ADMIN$` |
| 10:50:32 | 4697 | 装服务 `VaiGekem` → `%SYSTEMROOT%\VupeAjNm.exe`，LocalSystem |
| 10:50:42 | 4688 | `cmd.exe`（主体为机器账户） |
| 10:50:57 | 4720/4722 | 创建并启用用户 `attack$` |
| 10:51:07 | 4732 | 加入 `Administrators` |
| 10:51:15 | 4698 | 计划任务 `\callback`，`PT1M` 循环 |
| 10:52:06 | 4624 T10 | `attack$` 从 `192.168.222.200` RDP 登录成功 |

## 设计取舍

- **为什么不用 `Get-WinEvent`**：它在管道里会渲染每条事件的消息正文，而 `FormatDescription`
  比解析 XML 慢约 **300 倍**。同一份 9707 条的日志，`Get-WinEvent` 要 135 秒，改用
  `EventLogReader` + 按需渲染后是 1.2 秒。这是整个工具里最反直觉的性能坑。
- **为什么先跑 `netlogons` 而不是直接搜 4720**：4720 只告诉你"有个用户被建了"，
  不告诉你谁建的。先锁定源 IP，再看该 IP 的全部动作，顺序反过来会漏掉横向移动。
- **为什么要按 IP+类型+账户聚合**：几百条 4624 里绝大部分是机器账户的 Kerberos 噪声，
  聚合后剩下的通常不到 10 行，人眼可判。
- **为什么任务 XML 要解析而不是正则**：`<Command>` 里的路径可能带引号、参数、
  甚至嵌套在 `Arguments` 里，正则容易截断。
- **为什么不追求覆盖所有 EventID**：聚焦"账户 → 登录 → 提权 → 持久化"这条主链，
  覆盖绝大多数 Windows 单机应急场景。AD 域内攻击（DCSync、Golden Ticket）留给专项。

## 测试

用 41 个用例做过一轮完整验证，覆盖功能、边界、数据质量、性能四类：

| 类别 | 用例数 | 覆盖内容 |
|---|---|---|
| 功能 | 8 | 七种模式各自的输出数量与内容（4698 的 Command/Trigger/RunAs 是否被正确解析） |
| 边界 | 16 | dump 缺 `-Ids`、路径不存在、空目录、垃圾文件、`-MaxEvents`、目录批量、中文路径、嵌套 `-Out`、非法 `-Mode`、重复执行确定性、无效 EventID、**截断/中段损坏的 evtx** |
| 多通道 | 4 | System 通道 55072 条事件不崩、accounts 返回 0、7045 服务安装可提取 |
| 数据质量 | 6 | CSV 表头/行数/UTF-8 BOM、`Import-Csv` 往返、账号正文完整、netlogons 已剔除回环 |
| 性能 | 3 | 9707 条 1.5s；21MB/55072 条 6.0s；`all` 模式 14.0s |
| 交叉验证 | 4 | 与 `wevtutil qe`（独立解析器）逐 ID 比对计数，4624=273、4625=12、总数 9707 全部一致 |

性能那一栏的 `all` 模式比单独跑慢，是因为它要渲染约 800 条事件的消息正文 —— 正是上面说的那个 300 倍开销，
属于设计上的取舍：宁可慢 10 秒，也要把证据正文落盘。

测试中发现并修复了两个真实缺陷：

- `-Ids 4720,4732` 在 `powershell -File` 调用方式下无法绑定 `[int[]]`，直接退出码 1（已改为 `[string[]]` + 内部拆分）
- 中段损坏的 evtx 会让 `ReadEvent` 抛异常并丢弃已读的全部事件（已改为捕获后保留部分结果并显式告警 `PARTIAL`）

## 已知边界

- 只读 `.evtx`，不解析内存镜像、注册表 hive、`$MFT`。
- 中段损坏的 `.evtx` 只能读到第一条坏记录之前（会显式告警 `PARTIAL results`）；完全截断的文件会优雅退出（exit 2），不会静默返回空结果。
- 未开审计策略的日志里没有 4688，此时无法证明"后门是否真的执行过"，只能证明"任务被创建了"。
- 时间按本机时区显示，EVTX 原始记录为 UTC；跨时区取证需自行标注。
- `-Mode all` 的 `dump` 默认导出 4624 全量（可能数百条），超大日志建议改用 `-Ids` 精确抽取。
- 不合并多台主机的日志做横向关联，一主机一跑。

## 目录结构

```
SKILL.md                          # 技能主流程、七类问题映射、判读陷阱
scripts/parse_evtx.ps1            # 单文件解析工具（七种模式，无依赖）
references/eventids.md            # 安全日志事件 ID 速查与关键字段
references/playbooks.md           # 五种攻击链模式、噪声排除清单
references/report-template.md     # 中文取证报告模板
```

## License

MIT
