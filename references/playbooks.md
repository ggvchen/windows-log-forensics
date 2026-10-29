# 攻击链模式与场景化取证

## 一、通用判定原则

**事件本身没有意义，顺序才有意义。** 判断一条事件是否恶意，看它是否满足三个条件：

1. **时序合理**：出现在探测之后、登录之前/之后，符合因果
2. **主体异常**：发起者是机器账户（`HOST$`）、`SYSTEM`、或新出现的账户，而非日常管理员
3. **组合完整**：单个事件可能是误报，但"装服务 → cmd → net user → net localgroup → schtasks"这一串不可能是正常运维

## 二、五种典型攻击链

### 1. 远程服务执行 + 建号提权 + 计划任务后门（最常见）

```
4625(空用户,随机主机名,源IP)      ← 匿名/半匿名探测 IPC$
5140(ADMIN$, 同一源IP)            ← 尝试管理共享
4697(随机服务名, %SYSTEMROOT%\随机.exe, LocalSystem)  ← 远程建服务拿 SYSTEM
4688(cmd.exe, 主体=HOST$)
4720(新用户, 名字常带 $ 后缀)
4722/4724/4738(启用+设密)
4732(加入 Administrators)
4698(任务名如 \callback, Command=随机.exe, PT1M 循环)
4624 T10(新账户, 同一源IP)        ← RDP 登录
```

判定要点：4697 的服务名通常是 8 位随机字母，文件名也是随机的；4698 的 `Author` 为 `SYSTEM`，`RunAs` 为机器账户，触发间隔极短（`PT1M`/`PT5M`）。
工具指纹：PsExec（服务名 `PSEXESVC`）、Impacket smbexec/wmiexec（随机 8 位服务名）、Cobalt Strike（服务名随机 + `%COMSPEC%` 启动）。

### 2. 暴力破解 → 成功登录

```
大量 4625(同一 TargetUserName, 不同/相同源IP, SubStatus=0xC000006A)
4740(账户锁定)                    ← 可选
4624(该账户, 源IP=爆破源)          ← 爆破成功
4672(该账户获得特殊权限)           ← 说明是管理员账户
```

判定要点：4625 的 `IpPort` 每次不同说明是新连接（非重放）；成功后要立刻看该 LogonId 后续做了什么（4688/5140）。

### 3. Pass-the-Hash / 横向移动

```
4624 T3(NTLM, 账户=管理员, IpAddress=内网主机, WorkstationName 与 IP 不匹配)
4648(显式凭据, ProcessName=非交互进程)
5145(ADMIN$\Temp\*.exe 或 ADMIN$\PSEXESVC.exe)
```

判定要点：`AuthenticationPackageName=NTLM` 且源是内网工作站、目标账户是域管 —— 典型哈希传递。域内多台主机出现相同序列即为横向扩散。

### 4. Kerberoasting / 域内提权

```
4769(ServiceName=目标SPN, TicketEncryptionType=0x17(RC4), 大量不同服务)
```
`0x17` 是降级加密请求的标志，正常域环境应为 `0x12`(AES256)。

### 5. 日志清除掩盖

```
1102 / 104                        ← 清日志
(时间空白)                         ← 证据缺口
4616(系统时间被改)                 ← 篡改时间线
4719(审核策略被改)                 ← 关闭审计
```

## 三、七类问题的最短取证路径

| 问题 | 最短路径 | 交叉验证 |
|---|---|---|
| 攻击者 IP | `netlogons` → 找产生后续动作的 IP | 5145 共享访问 IP、4648 的 `IpAddress`、TerminalServices 1149 的 `Param3` |
| 恶意用户 | `accounts` → 4720 的 `TargetUserName` | 与 `SAM Account Name` 比对；确认 4722 已启用 |
| 用户组 | 4732 的 `GroupName` | `GroupSid`；若无 4732 查 4735/4738 的 `Primary Group ID` |
| 计划任务名 | 4698 的 `TaskName` | 4702（修改）、106（注册）、200/201（实际执行） |
| 后门路径 | 4698 `TaskContent` 的 `<Command>` | 4688 是否出现该路径；4697 的 `ServiceFileName` 可能是另一个组件 |
| RDP 时间 | 4624 `LogonType=10` 的 `TimeCreated` | TerminalServices 21/1149；多条时取最晚 |
| RDP 账户 | 同一 4624 的 `TargetUserName`+`TargetDomainName` | 4648 的 `TargetUserName`；5140 的 `SubjectUserName` |

## 四、噪声排除清单

回答"攻击者 IP"时若不做排除，很容易把域控或扫描器当攻击者。逐项检查：

| 噪声 | 特征 | 处理 |
|---|---|---|
| 域控认证流量 | 源 IP=域控，账户=`HOST$`，`AuthenticationPackageName=Kerberos`，T3 | 排除，这是机器账户正常拉取策略 |
| 本机回环 | `IpAddress=127.0.0.1` 或 `::1`，`ProcessName=winlogon.exe/lsass.exe` | 排除，本地登录 |
| IPv6 链路本地 | `fe80::` 开头 | 若无对应动作则排除 |
| 本机 Guest 失败 | 无 `IpAddress`，`ProcessName=C:\Windows\explorer.exe` | 排除，用户误操作/凭据缓存 |
| 单次扫描 | 仅 1 条 4625，空用户名，随机 16 位 `WorkstationName`，之后无任何动作 | 判为探测，不作为施控源 |
| 系统维护任务 | 4698 但 `Author=Microsoft`、路径在 `%SystemRoot%\System32\` 且文件名合法（如 `MpCmdRun.exe`） | 排除 |
| 服务安装 | 4697 但 `ServiceFileName` 指向已签名的正规软件、时间与其他运维动作成组 | 需结合基线判断 |

## 五、时间线重建技巧

1. 用 `-Mode all` 把 `logons.csv` 与 `accounts.txt`/`tasks.txt` 落到同一目录，按 `Time` 列合并排序。
2. 以**分钟级窗口**聚合：真实攻击的动作间隔通常 5 秒 ~ 5 分钟；跨越数小时的"相关事件"多半是巧合。
3. 一次性核对：**每一个"创建"事件，都应有对应的"使用"事件**。建了用户却没登录 = 可能被发现中断；建了任务却没 200/201 = 可能未执行。
4. 报告中的时间线只保留**构成因果链**的事件（通常 6~10 条），噪声事件放"排除项"。

## 六、证据完整性表述

结论里应体现证据强度，避免过度断言：

- 强：4720 + 4732 + 4698 + 4624 T10 全部存在且时序吻合
- 中：只有 4698，无 4688/200 —— 只能证明"创建了任务"，不能证明"执行成功"
- 弱：仅 4625 —— 只能证明"尝试过"，不能证明"得手"

缺什么就说什么，比编一个完整故事更有价值。
