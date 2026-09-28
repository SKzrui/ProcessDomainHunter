# ProcessDomainHunter

用于 Windows 应急响应：输入关键字后，查找当前可访问进程的可读内存，以及进程当前 TCP 连接对应的反向 DNS 主机名。

## 编译版部署

优先使用 `ProcessDomainHunter.exe`。现场机器不需要安装 C# 编译器，编译器只在制作工具时使用。当前 exe 是 64 位 .NET Framework 编译版，Windows 10/11 和大多数 Windows Server 通常已经具备所需运行环境。

如果目标是精简系统或老系统，启动时若提示缺少 .NET Framework，需要提前安装 .NET Framework 4.x；这可能需要管理员权限或重启。若现场不能安装任何运行库，应另外制作自带 .NET 运行库的 self-contained 版本，或改用原生 C++ 版本。

PowerShell 版 `ProcessDomainHunter.ps1` 保留作为兼容和源码版本，但大规模内存扫描速度较慢。

编译版示例：

```powershell
.\ProcessDomainHunter.exe -Keyword "artificialanalysis.ai" -FullScan -ThrottleLimit 4
```

默认会在当前目录实时生成 `ProcessDomainHunter-年月日-时分秒-毫秒.json`。扫描过程中发现的内存命中、网络命中和读取错误会立即写入；`-JsonPath` 仍可用于覆盖默认路径。

## 使用

建议使用“以管理员身份运行”的 PowerShell：

优先使用 64 位 PowerShell；32 位 PowerShell 可能无法读取 64 位进程的完整内存。

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\ProcessDomainHunter.ps1 -Keyword "evil-example.com"
```

只检查指定进程：

```powershell
.\ProcessDomainHunter.ps1 -Keyword "evil-example.com" -ProcessId 1234
.\ProcessDomainHunter.ps1 -Keyword "evil-example.com" -ProcessName chrome
```

需要完整扫描可读内存区域时：

```powershell
.\ProcessDomainHunter.ps1 -Keyword "evil-example.com" -FullScan
```

如需自定义 JSON 路径：

```powershell
.\ProcessDomainHunter.ps1 -Keyword "evil-example.com" -JsonPath .\result.json
```

如果只想做内存排查、不读取网络连接，可加 `-NoReverseDns`。

扫描默认显示一条总体固定进度条；如果检测到输出被重定向到日志、管道或采集器，工具会自动关闭动态进度，避免把进度刷成滚动字幕；也可使用 `-NoProgress` 主动关闭。

内存扫描默认使用 2 个并发扫描槽位；可根据机器负载调整，例如 `-ThrottleLimit 4`。建议应急现场先使用 2～4，过高可能增加 CPU、内存和目标进程访问压力；使用 `-ThrottleLimit 1` 可退回串行模式。

## 结果解释

- `Memory`：在进程可读内存中发现 ASCII/UTF-8 或 UTF-16LE 形式的关键字。结果按进程汇总，每个进程只保留一条记录；`MemoryMatchCount` 是记录到的匹配位置数量，`MemoryAddress` 和 `MemorySample` 是首个有效样本。
- `NetworkReverseDns`：当前 TCP 连接的远端 IP 反向解析出的主机名包含关键字。
- 无法打开受保护进程、进程在扫描期间退出、或远端没有反向 DNS 时，结果可能不完整。

内存命中的 `Notes` 会明确说明证据性质：命中 URL、翻译参数、浏览器分区、Cookie、缓存或历史数据时，只能作为页面/历史数据线索，不能证明进程当前正在访问该域名。扫描器自身的命令文本会过滤掉，避免把本次扫描操作当成有效命中。

## 限制

活动连接接口通常只提供远端 IP，不一定保留进程实际访问的原始域名；HTTPS、CDN、代理和共享出口 IP 尤其如此。因此，反向 DNS 命中是线索，不是对原始域名的绝对证明。内存命中同样可能是缓存、历史字符串或配置内容。

默认每个进程最多扫描 256 MiB、每个内存区域最多扫描 64 MiB，以降低现场机器负载；可通过 `-MaxBytesPerProcess` 和 `-MaxRegionBytes` 调整，或使用 `-FullScan` 扫描完整的可读区域。

工具只读系统状态，不注入、不终止进程、不修改系统。

扫描器自身会自动跳过，避免把命令行参数中的关键字误报为内存命中。
