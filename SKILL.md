---
name: windows-log-forensics
description: 分析 Windows 日志（EVTX：Security、System、Sysmon、PowerShell、TerminalServices），完成入侵溯源与取证问答。当用户提供 .evtx 文件或压缩包内的日志，或提出"确定攻击者 IP / 恶意用户 / 加入的用户组 / 计划任务名 / 后门程序路径 / RDP 登录时间与账户""日志分析""事件 ID 分析""入侵溯源""应急响应取证""4624/4625/4720/4698 是什么"等问题时使用。也适用于 Windows 横向移动、账户持久化、计划任务后门、暴力破解的日志判定。
---

# Windows 日志取证分析

把 EVTX 二进制日志变成"可回答的结论 + 可复核的证据链"。核心不是读事件，而是**按攻击链把散落的事件串成一条时间线**。

## 一、开工前

1. **确认输入**：`.evtx` 必须先解压（zip/rar 里不能直接读）。单文件通常是一个通道（Security / System / Sysmon），也可能是多通道合并导出。
2. **确认通道与体量**：先跑 `summary`，看 `LogName` 直方图 + 时间跨度 + 主机名。不同通道关注点不同：
   - **Security**：账户、登录、组、计划任务、服务、共享 —— 主战场
   - **System**：7045 服务安装、1074 关机、启动失败
   - **Microsoft-Windows-Sysmon/Operational**：进程创建、网络连接（比 4688 更全）
   - **Microsoft-Windows-TerminalServices-***：RDP 连接明细（客户端 IP、用户名）
3. **日志被清空过？** 查 1102（Security 日志清除）、104（System 日志清除）。有 1102 说明攻击者清痕，缺失时段要标注为"证据缺口"而不是"没发生"。

## 二、标准工作流

```
① summary      → 通道/时间跨度/EventID 直方图，建立全局印象
② netlogons    → 所有带真实远端 IP 的登录，锁定施控源（先排除回环与机器账户）
③ accounts     → 4720/4722/4724/4732/4738 全量正文，找后门账户与提权动作
④ tasks        → 4698/4697/4702/7045，解析任务 XML 拿 Command / Trigger / RunAs
⑤ dump         → 用 -Ids 精读关键事件正文（4624、4648、4688 等）
⑥ 拼时间线    → 以分钟级排序，验证"前一动作是否为后一动作的前提"
```

**不要只按单个问题去查单个 EventID。** 先取全量时间线，再回答具体问题——攻击者的动作有严格因果顺序（探测 → 执行 → 建号 → 提权 → 持久化 → 登录），顺序对不上就是误判。

## 三、脚本用法

```powershell
# 总览
powershell -File scripts/parse_evtx.ps1 -Path C:\case\Security.evtx -Mode summary

# 只看远端登录（自动排除 127.0.0.1 / ::1 / -）
powershell -File scripts/parse_evtx.ps1 -Path C:\case\Security.evtx -Mode netlogons

# 账户全生命周期
powershell -File scripts/parse_evtx.ps1 -Path C:\case\Security.evtx -Mode accounts

# 计划任务与服务（自动解析 4698 的 TaskContent XML）
powershell -File scripts/parse_evtx.ps1 -Path C:\case\Security.evtx -Mode tasks

# 精读任意事件
powershell -File scripts/parse_evtx.ps1 -Path C:\case\Security.evtx -Mode dump -Ids 4624,4648,4688

# 一键全量导出（CSV + TXT 落到 analysis_out\）
powershell -File scripts/parse_evtx.ps1 -Path C:\case -Mode all -Out C:\case\out
```

`-Path` 支持目录（批量读该目录下所有 .evtx）。CSV 出来后直接用 Read/Grep 复核，比反复调 `Get-WinEvent` 快得多。

脚本用 `EventLogReader` 枚举 + `ToXml()` 解析，**消息正文只在要打印时才渲染**——`FormatDescription` 全量渲染比解析 XML 慢约 300 倍，是唯一会拖垮运行时间的地方。9700 条 Security 日志实测约 1 秒。

日志极大时先加 `-MaxEvents 50000` 快速分诊，再对目标时间段全量跑。

## 四、七类高频问题的取证映射

| 问题 | 事件 ID | 判定要点 |
|---|---|---|
| 攻击者 IP | 4625 / 4624(T3,T10) / 5140 / 5145 | 看**后续动作**：只有产生建号、装服务、RDP 的 IP 才是施控源；单条 4625 多为扫描 |
| 恶意用户 | 4720 → 4722/4724/4738 | `TargetUserName` 与 `SAM Account Name` 双字段核对；SID 尾号用于跨事件关联（4732 里常只显示 `-`） |
| 加入的用户组 | 4732 / 4735 / 4728 / 4756 | `GroupName` + `GroupSID`；`S-1-5-32-544` = Administrators，`-555` = Remote Desktop Users |
| 计划任务名 | 4698 / 4702 | `TaskName`（带前导 `\`），正文 `TaskContent` 里取 `Command` 即后门路径 |
| 后门程序路径 | 4698 `TaskContent` / 4688 / 4697 | 任务定义优先；再交叉 4688 看是否真执行过（未开进程审计则只有任务定义） |
| RDP 成功登录时间 | 4624 `LogonType=10` | 一次会话产生**两条**记录（LogonId 不同），按时间去重，勿当两次登录 |
| RDP 登录账户 | 4624 `TargetUserName` | 结合 `IpAddress`+`IpPort` 与 4648 的显式凭据记录互相印证 |

完整字段与扩展事件 ID 见 `references/eventids.md`。

## 五、判读陷阱（最容易答错的地方）

1. **`WIN-XXXX$` 机器账户 + `0x3E7` 登录 ID = 远程服务执行**。建号、改组、装服务这类"人"的操作若发起者是机器账户，说明攻击者通过 SMB/服务/计划任务远程以 SYSTEM 身份执行，而非本地交互登录。这是 PsExec / Impacket / wmiexec 的指纹。
2. **账户名带 `$` 后缀**是隐蔽手段：`net user` 默认不列出以 `$` 结尾的账户。别把 `attack$` 误写成 `attack`。
3. **4732 里成员名常显示 `-`**，因为事件生成时账户名未解析。用 `MemberSid` 与 4720 的 `TargetSid` 对齐。
4. **时间统一**：EVTX 内是 UTC，`Get-WinEvent` 已按本机时区转换。报告里只写一种时区并注明。
5. **噪声源**：域控（机器账户 Kerberos T3）、本机 `explorer.exe` 触发的 Guest 失败、`127.0.0.1` 回环、IPv6 链路本地地址（`fe80::`）—— 这些不应算外部攻击者。
6. **空用户名 + 随机 16 位主机名 + NTLM 的 4625** 是自动化扫描/爆破工具特征（如主机名 `5rXE9kA1upFYmuOs`）。
7. **只有 4698 没有 4688** 不代表没执行：可能未开进程审计，或任务创建后主机被隔离。
8. **同一事件多条**：RDP（4624 T10）、4648、4672 常成对/成组出现，统计"次数"前先按 LogonId 去重。

攻击链模式与场景化路径见 `references/playbooks.md`。

## 六、输出规范

回答时**先给结论表，再给时间线，最后给原文证据**——顺序不能倒。用户要的是"IP 是多少"，不是"我查了哪些事件"。

- 结论表：一问一行，答案加粗
- 时间线：`时间 | 事件ID | 关键内容 | 含义`，只保留构成因果链的事件
- 原文证据：贴关键事件正文的精简版（保留字段名与值）
- 排除项：说明哪些候选被排除及原因（体现结论可靠性）

模板见 `references/report-template.md`。多问题取证（如题目式 7 问）严格按用户编号逐条作答，不要合并。

## 七、资源索引

- `scripts/parse_evtx.ps1` — 解析脚本（summary/logons/netlogons/accounts/tasks/dump/all）
- `references/eventids.md` — 安全日志事件 ID 速查与关键字段
- `references/playbooks.md` — 攻击链模式、场景化取证路径、排除规则
- `references/report-template.md` — 中文取证报告模板
