# ProcessDomainHunter / 进程域名排查工具

## English

ProcessDomainHunter is a Windows incident-response utility. It searches readable process memory for a keyword and checks active TCP connections whose reverse-DNS hostnames contain that keyword.

### Deployment

Use `ProcessDomainHunter.exe` when possible. Target machines do not need a C# compiler; the compiler is only required when building the tool. The bundled executable is a 64-bit .NET Framework build.

- Windows 7 SP1: install .NET Framework 4.8 if the runtime is missing. The current executable requires a 64-bit operating system.
- Windows 10/11 and most supported Windows Server systems: the required .NET Framework runtime is commonly already installed.
- 32-bit Windows: use a separately built x86 executable; the included executable is x64.
- If the host cannot install any runtime, build a native C++ version or provide a self-contained build for newer Windows versions.

The PowerShell version, `ProcessDomainHunter.ps1`, is included as a source-compatible alternative. It is slower for large memory scans.

### Quick start

```powershell
.\ProcessDomainHunter.exe -Keyword "artificialanalysis.ai" -FullScan -ThrottleLimit 4
```

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\ProcessDomainHunter.ps1 -Keyword "evil-example.com"
```

The tool automatically creates a live JSON report in the current directory. The filename uses this format:

```text
ProcessDomainHunter-yyyyMMdd-HHmmss-fff.json
```

The report is updated when a memory hit, network hit, or read error is found. Use `-JsonPath` only when a custom output path is needed:

```powershell
.\ProcessDomainHunter.exe -Keyword "evil-example.com" -JsonPath .\result.json
```

### Common options

```text
-ProcessId 1234,5678       Scan only the specified process IDs
-ProcessName chrome         Scan only matching process names
-FullScan                   Remove the default memory scan limits
-MaxBytesPerProcess 268435456
-MaxRegionBytes 67108864
-ThrottleLimit 4            Number of concurrent memory-scan workers
-NoReverseDns               Perform memory scanning only
-NoProgress                 Disable the overall progress display
-JsonPath result.json       Override the automatically generated JSON path
```

Run the tool from an elevated 64-bit PowerShell when possible. A 32-bit PowerShell process may not be able to read 64-bit target processes completely.

### Result interpretation

- `Memory`: the keyword was found as ASCII/UTF-8 or UTF-16LE bytes in readable process memory. Results are grouped by process; one memory record is retained per process. `MemoryMatchCount` is the number of recorded match locations, while `MemoryAddress` and `MemorySample` show the first useful sample.
- `NetworkReverseDns`: the reverse-DNS hostname of an active TCP connection contains the keyword.
- `Notes`: explains the evidence level. A memory hit proves only that a copy of the string exists in readable process memory; it does not prove that the process is currently accessing the domain. URL parameters, translation URLs, browser partition keys, cookies, cache entries, history, command lines, and configuration data may all produce memory hits.
- Scanner command text is filtered to reduce self-induced false positives.

### Progress and performance

The compiled version displays one overall progress bar when attached to a real Windows console. When output is redirected to a pipe, log collector, IDE, or other non-interactive stream, dynamic progress is disabled to prevent scrolling output.

Memory scanning uses two concurrent workers by default. Use `-ThrottleLimit 2` to `-ThrottleLimit 4` for normal incident-response work. Higher values may increase CPU, memory, and target-process access pressure. Use `-ThrottleLimit 1` for serial scanning.

By default, each process is scanned up to 256 MiB and each memory region up to 64 MiB. Adjust these values with `-MaxBytesPerProcess` and `-MaxRegionBytes`, or use `-FullScan` to scan all readable committed regions.

### Limitations

Active connection tables normally expose a remote IP address rather than the original hostname. HTTPS, CDNs, proxies, shared egress IPs, and recent or closed connections can prevent the original domain from being identified. Reverse-DNS matches are indicators, not proof of the original domain requested by the process.

Protected processes may be inaccessible, processes may exit during scanning, and network reverse DNS may be unavailable. Results can therefore be incomplete. The tool reads system state only; it does not inject into or terminate processes and does not modify the target system.

## 中文说明

ProcessDomainHunter 是一个 Windows 应急响应工具：输入关键字后，在可读取的进程内存中进行匹配，并检查当前 TCP 连接对应的反向 DNS 主机名是否包含该关键字。

### 部署说明

优先使用 `ProcessDomainHunter.exe`。目标机器不需要安装 C# 编译器，编译器只在制作工具时使用。当前附带的 EXE 是 64 位 .NET Framework 版本。

- Windows 7 SP1：如果缺少运行库，需要安装 .NET Framework 4.8；当前 EXE 要求 64 位操作系统。
- Windows 10/11 和大多数受支持的 Windows Server：通常已经具备所需的 .NET Framework 运行环境。
- 32 位 Windows：需要另外制作 x86 EXE；当前附带版本是 x64。
- 如果现场不能安装任何运行库，需要制作原生 C++ 版本，或为较新的 Windows 系统提供 self-contained 版本。

目录中同时保留 PowerShell 版本 `ProcessDomainHunter.ps1`，可作为源码和兼容版本使用，但大规模内存扫描速度较慢。

### 快速开始

```powershell
.\ProcessDomainHunter.exe -Keyword "artificialanalysis.ai" -FullScan -ThrottleLimit 4
```

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\ProcessDomainHunter.ps1 -Keyword "evil-example.com"
```

工具会自动在当前目录生成实时 JSON 报告，文件名格式如下：

```text
ProcessDomainHunter-yyyyMMdd-HHmmss-fff.json
```

发现内存命中、网络命中或读取错误时，报告会立即更新。如需指定自定义路径，再使用 `-JsonPath`：

```powershell
.\ProcessDomainHunter.exe -Keyword "evil-example.com" -JsonPath .\result.json
```

### 常用参数

```text
-ProcessId 1234,5678       只扫描指定 PID
-ProcessName chrome         只扫描指定进程名
-FullScan                   取消默认的内存扫描上限
-MaxBytesPerProcess 268435456
-MaxRegionBytes 67108864
-ThrottleLimit 4            内存扫描并发槽位
-NoReverseDns               只做内存扫描
-NoProgress                 关闭总体进度显示
-JsonPath result.json       覆盖自动生成的 JSON 路径
```

建议在管理员权限的 64 位 PowerShell 中运行。32 位 PowerShell 可能无法完整读取 64 位目标进程。

### 结果解释

- `Memory`：在进程可读内存中发现 ASCII/UTF-8 或 UTF-16LE 形式的关键字。结果按进程汇总，每个进程只保留一条内存记录；`MemoryMatchCount` 是记录到的匹配位置数量，`MemoryAddress` 和 `MemorySample` 是首个有效样本。
- `NetworkReverseDns`：当前 TCP 连接的远端 IP 反向解析出的主机名包含关键字。
- `Notes`：说明证据性质。内存命中只能证明该字符串副本存在于进程可读内存中，不能证明进程当前正在访问该域名。URL 参数、翻译 URL、浏览器分区键、Cookie、缓存、历史记录、命令行和配置数据都可能造成内存命中。
- 工具会过滤扫描器自身的命令文本，以减少由本次扫描操作造成的伪命中。

### 进度与性能

编译版连接到真实 Windows 控制台时显示一条总体进度条。如果输出被重定向到管道、日志采集器、IDE 或其他非交互输出流，工具会自动关闭动态进度，避免滚动刷屏。

内存扫描默认使用 2 个并发槽位。应急现场通常建议使用 `-ThrottleLimit 2` 到 `-ThrottleLimit 4`。并发过高可能增加 CPU、内存和目标进程访问压力；使用 `-ThrottleLimit 1` 可退回串行扫描。

默认每个进程最多扫描 256 MiB、每个内存区域最多扫描 64 MiB。可通过 `-MaxBytesPerProcess` 和 `-MaxRegionBytes` 调整，或使用 `-FullScan` 扫描全部可读已提交内存区域。

### 限制

活动连接表通常只提供远端 IP，不一定保留进程实际访问的原始域名。HTTPS、CDN、代理、共享出口 IP，以及已经结束的连接，都可能导致原始域名无法识别。因此，反向 DNS 命中是线索，不是进程访问原始域名的绝对证明。

受保护进程可能无法打开，进程也可能在扫描期间退出，网络反向 DNS 也可能不可用，因此结果可能不完整。工具只读取系统状态，不注入、不终止进程，也不修改目标系统。
