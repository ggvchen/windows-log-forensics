# Windows 安全日志事件 ID 速查

只列取证实战高频事件。字段名为 EVTX XML 中的 `EventData/Data@Name`。

## 一、登录与认证

| ID | 含义 | 关键字段 | 取证价值 |
|---|---|---|---|
| 4624 | 登录成功 | `LogonType` `TargetUserName` `TargetDomainName` `IpAddress` `IpPort` `WorkstationName` `ProcessName` `TargetLogonId` `AuthenticationPackageName` | 主证据。先看 LogonType |
| 4625 | 登录失败 | 同上 + `Status` `SubStatus` `FailureReason` | 爆破、探测。`SubStatus=0xC000006A` 密码错，`0xC0000064` 用户不存在 |
| 4634 / 4647 | 注销 / 用户主动注销 | `TargetLogonId` | 与 4624 配对算会话时长 |
| 4648 | 使用显式凭据登录 | `TargetUserName` `IpAddress` `ProcessName` | `runas`、计划任务、横向密码传递 |
| 4672 | 授予特殊权限 | `SubjectUserName` `PrivilegeList` | 管理员登录必带，非管理员出现=提权成功 |
| 4776 | NTLM 凭据验证 | `TargetUserName` `Workstation` `Status` | 域环境爆破来源 |
| 4768 / 4769 / 4771 | TGT / TGS / Kerberos 失败 | `TargetUserName` `IpAddress` `ServiceName` `TicketEncryptionType` | Kerberoasting：`TicketEncryptionType=0x17` |

**LogonType 取值**：2=交互(控制台)、3=网络(SMB/共享)、4=批处理、5=服务、7=解锁、8=网络明文、9=NewCredentials、**10=远程桌面(RDP)**、11=缓存凭据。

> 4624 T10 一次会话产生两条记录（LogonId 不同，如 `0x12a329` / `0x12a334`），是正常现象。

## 二、账户与组

| ID | 含义 | 关键字段 |
|---|---|---|
| 4720 | 创建用户 | `TargetUserName` `TargetSid` + 正文 `SAM Account Name` `New UAC Value` |
| 4722 / 4725 | 启用 / 禁用账户 | `TargetUserName` `TargetSid` |
| 4723 / 4724 | 用户改密 / 重置密码 | `TargetUserName` `SubjectUserName` |
| 4726 | 删除用户 | `TargetUserName` |
| 4738 | 修改用户账户 | 正文含新旧 UAC 值、上次设密时间 |
| 4732 / 4733 | 加入 / 移出本地组 | `MemberName` `MemberSid` `GroupName` `GroupSid` |
| 4728 / 4729 | 加入 / 移出全局组 | 同上（域组） |
| 4756 / 4757 | 加入 / 移出通用组 | 同上 |
| 4740 | 账户被锁定 | `TargetUserName` `CallerComputerName` | 爆破副作用 |
| 4781 | 账户名被更改 | `OldTargetUserName` `NewTargetUserName` |

**常用组 SID**：`S-1-5-32-544`=Administrators、`S-1-5-32-545`=Users、`S-1-5-32-555`=Remote Desktop Users、`S-1-5-32-562`=Distributed COM Users、`S-1-5-32-580`=Remote Management Users。

> 4732 的 `MemberName` 常为 `-`（未解析）。用 `MemberSid` 与 4720 的 `TargetSid` 对齐；这是跨事件关联账户身份的关键。

## 三、执行与持久化

| ID | 含义 | 关键字段 |
|---|---|---|
| 4688 | 创建进程 | `NewProcessName` `CommandLine` `ParentProcessName` `SubjectUserName` `TokenElevationType` |
| 4697 | 安装服务（Security） | `ServiceName` `ServiceFileName` `ServiceType` `ServiceStartType` `ServiceAccount` |
| 7045 | 安装服务（System） | 同上，正文形式 | 4688 未开时的主要补充 |
| 4698 | 创建计划任务 | `TaskName` + `TaskContent`（完整 XML） |
| 4699 | 删除计划任务 | `TaskName` |
| 4700 / 4701 | 启用 / 禁用计划任务 | `TaskName` |
| 4702 | 修改计划任务 | `TaskName` `TaskContent` |
| 106 | 注册计划任务（TaskScheduler） | `TaskName` `UserContext` |
| 200 / 201 | 任务动作启动 / 完成 | `TaskName` `ActionName` `EnginePID` | **证明后门真的跑了** |
| 4103 / 4104 | PowerShell 模块日志 / 脚本块 | `ScriptBlockText` | 无文件攻击的主要证据 |

## 四、横向移动与访问

| ID | 含义 | 关键字段 |
|---|---|---|
| 5140 | 访问网络共享 | `ShareName` `IpAddress` `SubjectUserName` |
| 5145 | 详细文件共享访问 | `ShareName` `RelativeTargetName` `IpAddress` | 看到 `ADMIN$\Temp\xxx.exe` 基本等于 PsExec |
| 5156 / 5157 | 允许 / 阻止的网络连接 | `SourceAddress` `DestAddress` `DestPort` |
| 5142 / 5143 | 添加 / 修改共享 | `ShareName` |
| 4673 / 4674 | 调用特权服务 / 特权对象操作 | `Service` `ObjectName` `PrivilegeList` |

## 五、防御规避

| ID | 含义 |
|---|---|
| 1102 | Security 日志被清除（**强烈告警**） |
| 104 | System 日志被清除 |
| 4719 | 审核策略被更改 |
| 4907 | 审核策略更改（对象访问） |
| 4713 / 4716 | Kerberos 策略变更 |
| 4616 | 系统时间被更改 |
| 4779 | 会话被断连（RDP 强制踢出） |

> 1102 之后出现的时间空白必须标注为"证据缺口"，不能写成"未发生"。

## 六、RDP 专项（Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational）

| ID | 含义 | 字段 |
|---|---|---|
| 1149 | 用户认证成功（RDP 网络层） | `Param1`=用户名 `Param2`=域 `Param3`=源 IP |
| 21 | 会话登录成功 | `SessionID` `AccountName` `AccountDomain` |
| 24 / 25 | 会话断连 / 重连 | `SessionID` |
| 1148 | 认证失败 | `Param1` 用户名、`Param3` 源 IP |

Security 日志里 4624 T10 与这里 1149/21 交叉验证，可确认"是否真的是 RDP 而非其他远程交互"。
