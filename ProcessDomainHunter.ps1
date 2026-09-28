#requires -Version 5.1

<##
.SYNOPSIS
    Windows 进程内存与网络端点应急排查工具。

.DESCRIPTION
    输入一个关键字，扫描当前可访问进程的可读内存，并检查进程的活动 TCP
    连接的反向 DNS 主机名。工具只读系统状态，不注入、不终止进程、不修改系统。

    注意：Windows 活动连接通常只包含远端 IP。反向 DNS 主机名不一定等于进程
    实际访问的原始域名，尤其是 HTTPS/CDN 场景；内存命中可作为更直接的线索。
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string]$Keyword,

    [int[]]$ProcessId,

    [string[]]$ProcessName,

    [ValidateRange(1, 9223372036854775807)]
    [int64]$MaxBytesPerProcess = 268435456,

    [ValidateRange(1, 9223372036854775807)]
    [int64]$MaxRegionBytes = 67108864,

    [ValidateRange(1, 8)]
    [int]$ThrottleLimit = 2,

    [switch]$FullScan,

    [switch]$NoReverseDns,

    [switch]$NoProgress,

    [string]$JsonPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($JsonPath)) {
    $JsonPath = Join-Path (Get-Location) ('ProcessDomainHunter-{0}.json' -f (Get-Date).ToString('yyyyMMdd-HHmmss-fff'))
}

if (-not ([System.Management.Automation.PSTypeName]'ProcessDomainHunter.NativeMethodsV2').Type) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

namespace ProcessDomainHunter {
    public static class NativeMethodsV2 {
        [Flags]
        public enum ProcessAccessFlags : uint {
            QueryInformation = 0x0400,
            VirtualMemoryRead = 0x0010
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct MEMORY_BASIC_INFORMATION {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public UIntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            ProcessAccessFlags desiredAccess,
            bool inheritHandle,
            uint processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern int VirtualQueryEx(
            IntPtr process,
            IntPtr address,
            out MEMORY_BASIC_INFORMATION buffer,
            uint length);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool ReadProcessMemory(
            IntPtr process,
            IntPtr baseAddress,
            [Out] byte[] buffer,
            UIntPtr size,
            out UIntPtr numberOfBytesRead);

        public static byte[] ToAsciiLower(byte[] bytes) {
            if (bytes == null) {
                return null;
            }
            byte[] result = new byte[bytes.Length];
            Buffer.BlockCopy(bytes, 0, result, 0, bytes.Length);
            for (int i = 0; i < result.Length; i++) {
                if (result[i] >= 65 && result[i] <= 90) {
                    result[i] = (byte)(result[i] + 32);
                }
            }
            return result;
        }

        public static int FindBytePattern(byte[] buffer, byte[] pattern, int startAt) {
            if (buffer == null || pattern == null || pattern.Length == 0 || pattern.Length > buffer.Length) {
                return -1;
            }

            int[] shifts = new int[256];
            for (int i = 0; i < shifts.Length; i++) {
                shifts[i] = pattern.Length;
            }
            for (int i = 0; i < pattern.Length - 1; i++) {
                shifts[pattern[i]] = pattern.Length - 1 - i;
            }

            int offset = Math.Max(0, startAt);
            int last = pattern.Length - 1;
            while (offset <= buffer.Length - pattern.Length) {
                int patternIndex = last;
                while (patternIndex >= 0 && buffer[offset + patternIndex] == pattern[patternIndex]) {
                    patternIndex--;
                }
                if (patternIndex < 0) {
                    return offset;
                }
                offset += shifts[buffer[offset + last]];
            }
            return -1;
        }
    }
}
'@
}

function Find-BytePattern {
    param(
        [byte[]]$Buffer,
        [byte[]]$Pattern,
        [int]$StartAt = 0
    )

    return [ProcessDomainHunter.NativeMethodsV2]::FindBytePattern($Buffer, $Pattern, $StartAt)
}

function Convert-ToAsciiLowerBytes {
    param([byte[]]$Bytes)

    return [ProcessDomainHunter.NativeMethodsV2]::ToAsciiLower($Bytes)
}

function Get-MemorySnippet {
    param(
        [byte[]]$Buffer,
        [int]$Offset,
        [int]$PatternLength,
        [bool]$Unicode
    )

    $start = [Math]::Max(0, $Offset - 64)
    $end = [Math]::Min($Buffer.Length, $Offset + $PatternLength + 96)
    $count = $end - $start
    if ($count -le 0) {
        return ''
    }

    $snippetBytes = New-Object byte[] $count
    [Array]::Copy($Buffer, $start, $snippetBytes, 0, $count)
    if ($Unicode) {
        $text = [Text.Encoding]::Unicode.GetString($snippetBytes)
    }
    else {
        $text = [Text.Encoding]::UTF8.GetString($snippetBytes)
    }

    $text = $text -replace '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '.'
    $text = $text.Trim()
    if ($text.Length -gt 220) {
        return $text.Substring(0, 220)
    }
    return $text
}

function Test-ReadableProtection {
    param([uint32]$Protection)

    if (($Protection -band 0x100) -ne 0 -or $Protection -eq 0x01) {
        return $false
    }

    return $Protection -in @(
        0x02, 0x04, 0x08,
        0x20, 0x40, 0x80
    )
}

function Get-ProcessPathSafe {
    param([System.Diagnostics.Process]$Process)

    try {
        return $Process.Path
    }
    catch {
        try {
            return $Process.MainModule.FileName
        }
        catch {
            return ''
        }
    }
}

function Invoke-MemoryScan {
    param(
        [System.Diagnostics.Process]$Process,
        [hashtable]$Patterns,
        [int64]$PerProcessLimit,
        [int64]$PerRegionLimit,
        [string]$SearchKeyword
    )

    $hits = New-Object System.Collections.ArrayList
    $access = [ProcessDomainHunter.NativeMethodsV2+ProcessAccessFlags]::QueryInformation -bor [ProcessDomainHunter.NativeMethodsV2+ProcessAccessFlags]::VirtualMemoryRead
    $handle = [ProcessDomainHunter.NativeMethodsV2]::OpenProcess(
        $access,
        $false,
        [uint32]$Process.Id)

    if ($handle -eq [IntPtr]::Zero) {
        return @{
            Hits  = @()
            Error = "无法打开进程，Win32 错误码 $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }
    }

    try {
        $address = [IntPtr]::Zero
        $scannedBytes = [int64]0
        $querySize = [uint32][Runtime.InteropServices.Marshal]::SizeOf([Type][ProcessDomainHunter.NativeMethodsV2+MEMORY_BASIC_INFORMATION])
        $patternLengths = @($Patterns.Values | ForEach-Object { $_.Bytes.Length })
        $overlap = [Math]::Max(0, ([int]($patternLengths | Measure-Object -Maximum).Maximum) - 1)

        while ($true) {
            $memoryInfo = New-Object ProcessDomainHunter.NativeMethodsV2+MEMORY_BASIC_INFORMATION
            $queryResult = [ProcessDomainHunter.NativeMethodsV2]::VirtualQueryEx(
                $handle,
                $address,
                [ref]$memoryInfo,
                $querySize)

            if ($queryResult -eq 0) {
                break
            }

            $regionSize = [int64]$memoryInfo.RegionSize.ToUInt64()
            if ($regionSize -le 0) {
                break
            }

            $nextAddressValue = $address.ToInt64() + $regionSize
            if ($nextAddressValue -le $address.ToInt64()) {
                break
            }

            $isCommitted = $memoryInfo.State -eq 0x1000
            $isReadable = Test-ReadableProtection -Protection $memoryInfo.Protect
            if ($isCommitted -and $isReadable -and $scannedBytes -lt $PerProcessLimit) {
                $bytesInRegion = [Math]::Min($regionSize, $PerRegionLimit)
                $bytesInRegion = [Math]::Min($bytesInRegion, $PerProcessLimit - $scannedBytes)
                $regionOffset = [int64]0
                [byte[]]$carry = @()

                while ($regionOffset -lt $bytesInRegion -and $hits.Count -lt 20) {
                    $readLength = [int][Math]::Min(1048576, $bytesInRegion - $regionOffset)
                    $buffer = New-Object byte[] $readLength
                    $bytesRead = [UIntPtr]::Zero
                    $readAddress = [IntPtr]::new($address.ToInt64() + $regionOffset)
                    $readOk = [ProcessDomainHunter.NativeMethodsV2]::ReadProcessMemory(
                        $handle,
                        $readAddress,
                        $buffer,
                        [UIntPtr]::new([uint32]$readLength),
                        [ref]$bytesRead)
                    $actualBytes = [int][Math]::Min($readLength, $bytesRead.ToUInt64())

                    if ($readOk -and $actualBytes -gt 0) {
                        $combined = New-Object byte[] ($carry.Length + $actualBytes)
                        if ($carry.Length -gt 0) {
                            [Array]::Copy($carry, 0, $combined, 0, $carry.Length)
                        }
                        [Array]::Copy($buffer, 0, $combined, $carry.Length, $actualBytes)
                        $lowerCombined = Convert-ToAsciiLowerBytes -Bytes $combined

                        foreach ($patternName in $Patterns.Keys) {
                            $pattern = $Patterns[$patternName]
                            $matchAt = Find-BytePattern -Buffer $lowerCombined -Pattern $pattern.Bytes
                            if ($matchAt -ge 0) {
                                $absoluteAddress = $address.ToInt64() + $regionOffset - $carry.Length + $matchAt
                                $null = $hits.Add([ordered]@{
                                    Keyword         = $SearchKeyword
                                    Encoding        = $patternName
                                    Address         = ('0x{0:X}' -f $absoluteAddress)
                                    Sample          = Get-MemorySnippet -Buffer $combined -Offset $matchAt -PatternLength $pattern.Bytes.Length -Unicode ($patternName -eq 'UTF-16LE')
                                })
                            }
                        }

                        if ($combined.Length -gt $overlap) {
                            $carry = New-Object byte[] $overlap
                            [Array]::Copy($combined, $combined.Length - $overlap, $carry, 0, $overlap)
                        }
                        else {
                            $carry = $combined
                        }
                    }

                    if ($actualBytes -le 0) {
                        break
                    }
                    $regionOffset += $actualBytes
                    $scannedBytes += $actualBytes
                }
            }

            $address = [IntPtr]::new($nextAddressValue)
            if ($PerProcessLimit -gt 0 -and $scannedBytes -ge $PerProcessLimit) {
                break
            }
        }

        return @{
            Hits  = @($hits)
            Error = ''
        }
    }
    catch {
        return @{
            Hits  = @($hits)
            Error = $_.Exception.Message
        }
    }
    finally {
        [void][ProcessDomainHunter.NativeMethodsV2]::CloseHandle($handle)
    }
}

function Get-MemoryScanWorkerScript {
    $functionNames = @(
        'Find-BytePattern',
        'Convert-ToAsciiLowerBytes',
        'Get-MemorySnippet',
        'Test-ReadableProtection',
        'Invoke-MemoryScan'
    )
    $parts = New-Object System.Collections.ArrayList
    $null = $parts.Add(@'
param(
    [int]$ProcessId,
    [hashtable]$Patterns,
    [int64]$PerProcessLimit,
    [int64]$PerRegionLimit,
    [string]$SearchKeyword
)
'@)

    foreach ($functionName in $functionNames) {
        $definition = (Get-Command $functionName -CommandType Function -ErrorAction Stop).Definition
        $null = $parts.Add("function $functionName {")
        $null = $parts.Add($definition)
        $null = $parts.Add('}')
    }

    $null = $parts.Add(@'
$process = Get-Process -Id $ProcessId -ErrorAction Stop
Invoke-MemoryScan -Process $process -Patterns $Patterns -PerProcessLimit $PerProcessLimit -PerRegionLimit $PerRegionLimit -SearchKeyword $SearchKeyword
'@)
    return ($parts -join [Environment]::NewLine)
}

function Get-MemoryMatchNote {
    param(
        [string]$Sample,
        [int]$MatchCount
    )

    if ($Sample -match '(?i)translate|u=https://') {
        $note = '内存中命中翻译 URL 或 URL 参数上下文，属于浏览器页面、历史记录或缓存线索；不能证明当前正在访问该域名'
    }
    elseif ($Sample -match '(?i)partitionKey|cookie|cache|history') {
        $note = '内存中命中浏览器分区、Cookie、缓存或历史数据上下文，属于历史/页面数据线索；不能证明当前正在访问该域名'
    }
    elseif ($Sample -match '(?i)https?://') {
        $note = '内存中命中包含 URL 的字符串上下文；这只能证明该 URL 副本存在于进程内存，不能证明当前正在访问该域名'
    }
    else {
        $note = '内存中命中该字符串，但当前样本没有足够的 URL 或请求上下文；不能证明当前正在访问该域名'
    }
    if ($MatchCount -ge 20) {
        $note += '；该进程至少还有 20 个匹配位置，结果已截取'
    }
    return $note + '。'
}

function Test-ScannerCommandSample {
    param([string]$Sample)

    return ($Sample -match '(?i)ProcessDomainHunter|inHunter\.exe|-FullScan|-JsonPath') -and
        ($Sample -match '(?i)-Keyword|-FullScan|-JsonPath')
}

function Add-MemoryScanResults {
    param(
        [System.Collections.ArrayList]$ResultList,
        [object]$ProcessRecord,
        [object]$Scan
    )

    if ($null -eq $Scan) {
        return
    }

    $hits = @($Scan.Hits | Where-Object {
        -not (Test-ScannerCommandSample -Sample ([string]$_.Sample))
    })
    foreach ($hit in @($hits | Select-Object -First 1)) {
        $null = $ResultList.Add([ordered]@{
            ProcessId       = $ProcessRecord.ProcessId
            ProcessName     = $ProcessRecord.ProcessName
            Path            = $ProcessRecord.Path
            MatchType       = 'Memory'
            Keyword         = $hit.Keyword
            Encoding        = $hit.Encoding
            MemoryAddress   = $hit.Address
            MemorySample    = $hit.Sample
            MemoryMatchCount = $hits.Count
            LocalAddress    = ''
            LocalPort       = ''
            RemoteAddress   = ''
            RemotePort      = ''
            State           = ''
            ResolvedHost    = ''
            Notes           = Get-MemoryMatchNote -Sample ([string]$hit.Sample) -MatchCount $hits.Count
        })
    }
}

function Get-ReverseDnsSafe {
    param(
        [string]$Address,
        [hashtable]$Cache
    )

    if ($Cache.ContainsKey($Address)) {
        return $Cache[$Address]
    }

    $hostName = ''
    try {
        $parsedAddress = [System.Net.IPAddress]::Parse($Address)
        if (-not $parsedAddress.IsLoopback -and -not $parsedAddress.Equals([System.Net.IPAddress]::Any) -and -not $parsedAddress.Equals([System.Net.IPAddress]::IPv6Any)) {
            $hostName = [System.Net.Dns]::GetHostEntry($parsedAddress).HostName
        }
    }
    catch {
        $hostName = ''
    }

    $Cache[$Address] = $hostName
    return $hostName
}

function Get-ProcessRecordSafe {
    param(
        [int]$Id,
        [hashtable]$Cache
    )

    if ($Cache.ContainsKey($Id)) {
        return $Cache[$Id]
    }

    try {
        $process = Get-Process -Id $Id -ErrorAction Stop
        $record = [ordered]@{
            ProcessId   = $Id
            ProcessName = $process.ProcessName
            Path        = Get-ProcessPathSafe -Process $process
        }
    }
    catch {
        $record = [ordered]@{
            ProcessId   = $Id
            ProcessName = '<已退出或不可见>'
            Path        = ''
        }
    }

    $Cache[$Id] = $record
    return $record
}

function Write-JsonSnapshot {
    param(
        [string]$Path,
        [string]$KeywordValue,
        [System.Collections.ArrayList]$MemoryResultsValue,
        [System.Collections.ArrayList]$NetworkResultsValue,
        [System.Collections.ArrayList]$ErrorsValue
    )

    if ([string]::IsNullOrWhiteSpace($Path)) {
        return
    }

    $results = @($MemoryResultsValue + $NetworkResultsValue | ForEach-Object { [pscustomobject]$_ })
    $payload = [ordered]@{
        GeneratedAt = (Get-Date).ToString('o')
        Keyword     = $KeywordValue
        Results     = $results
        Errors      = @($ErrorsValue)
    }
    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $tempPath = '{0}.{1}.tmp' -f $fullPath, $PID
    $json = $payload | ConvertTo-Json -Depth 8
    try {
        [System.IO.File]::WriteAllText($tempPath, $json, (New-Object System.Text.UTF8Encoding($false)))
        if (Test-Path -LiteralPath $fullPath) {
            try {
                [System.IO.File]::Replace($tempPath, $fullPath, $null)
            }
            catch {
                [System.IO.File]::Copy($tempPath, $fullPath, $true)
                [System.IO.File]::Delete($tempPath)
            }
        }
        else {
            [System.IO.File]::Move($tempPath, $fullPath)
        }
    }
    finally {
        if (Test-Path -LiteralPath $tempPath) {
            Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        }
    }
}

$asciiBytes = [Text.Encoding]::ASCII.GetBytes($Keyword)
$utf8Bytes = [Text.Encoding]::UTF8.GetBytes($Keyword)
$unicodeBytes = [Text.Encoding]::Unicode.GetBytes($Keyword)
$patterns = [ordered]@{}
if ($asciiBytes.Length -gt 0) {
    $patterns['ASCII/UTF-8'] = @{ Bytes = Convert-ToAsciiLowerBytes -Bytes $asciiBytes }
}
$asciiEqualsUtf8 = $asciiBytes.Length -eq $utf8Bytes.Length
if ($asciiEqualsUtf8) {
    for ($i = 0; $i -lt $asciiBytes.Length; $i++) {
        if ($asciiBytes[$i] -ne $utf8Bytes[$i]) {
            $asciiEqualsUtf8 = $false
            break
        }
    }
}
if (-not $asciiEqualsUtf8) {
    $patterns['UTF-8'] = @{ Bytes = Convert-ToAsciiLowerBytes -Bytes $utf8Bytes }
}
$patterns['UTF-16LE'] = @{ Bytes = Convert-ToAsciiLowerBytes -Bytes $unicodeBytes }

$processCache = @{}
$errors = New-Object System.Collections.ArrayList
$memoryResults = New-Object System.Collections.ArrayList
$networkResults = New-Object System.Collections.ArrayList

if ($JsonPath) {
    Write-JsonSnapshot -Path $JsonPath -KeywordValue $Keyword -MemoryResultsValue $memoryResults -NetworkResultsValue $networkResults -ErrorsValue $errors
}

try {
    if ($ProcessId) {
        $processes = @($ProcessId | ForEach-Object { Get-Process -Id $_ -ErrorAction Stop })
    }
    elseif ($ProcessName) {
        $processes = @($ProcessName | ForEach-Object { Get-Process -Name $_ -ErrorAction SilentlyContinue })
    }
    else {
        $processes = @(Get-Process)
    }
}
catch {
    throw ('获取进程列表失败：{0}' -f $_.Exception.Message)
}

$processes = @($processes | Sort-Object Id -Unique)
Write-Verbose "准备扫描 $($processes.Count) 个进程的可读内存。"
Write-Host "实时 JSON：$JsonPath"

$scannerProcessId = $PID
$scanProcessLimit = $MaxBytesPerProcess
$scanRegionLimit = $MaxRegionBytes
if ($FullScan) {
    $scanProcessLimit = [int64]::MaxValue
    $scanRegionLimit = [int64]::MaxValue
}

$scanTargets = @($processes | Where-Object {
    $_.Id -gt 4 -and $_.Id -ne $scannerProcessId
})
$scanTotal = $scanTargets.Count
$memoryProgressWeight = if ($NoReverseDns) { 100 } else { 90 }

if ($ThrottleLimit -le 1 -or $scanTotal -le 1) {
    $processIndex = 0
    foreach ($process in $scanTargets) {
        $processRecord = Get-ProcessRecordSafe -Id $process.Id -Cache $processCache
        $processIndex++
        if (-not $NoProgress) {
            $processPercent = [int][Math]::Min(100, [Math]::Round((($processIndex - 1) * 100) / [Math]::Max(1, $scanTotal)))
            $overallPercent = [int][Math]::Round(($processPercent * $memoryProgressWeight) / 100)
            Write-Progress -Id 1 -Activity '扫描进度' -Status "内存扫描：已完成 $($processIndex - 1)/$scanTotal 个进程；累计命中 $($memoryResults.Count)" -PercentComplete $overallPercent
        }

        $scan = Invoke-MemoryScan -Process $process -Patterns $patterns -PerProcessLimit $scanProcessLimit -PerRegionLimit $scanRegionLimit -SearchKeyword $Keyword
        if ($scan.Error) {
            $null = $errors.Add("PID $($process.Id) $($processRecord.ProcessName)：$($scan.Error)")
        }
        Add-MemoryScanResults -ResultList $memoryResults -ProcessRecord $processRecord -Scan $scan
        if ($JsonPath -and ($scan.Hits.Count -gt 0 -or $scan.Error)) {
            Write-JsonSnapshot -Path $JsonPath -KeywordValue $Keyword -MemoryResultsValue $memoryResults -NetworkResultsValue $networkResults -ErrorsValue $errors
        }

        if (-not $NoProgress) {
            $processPercent = [int][Math]::Min(100, [Math]::Round(($processIndex * 100) / [Math]::Max(1, $scanTotal)))
            $overallPercent = [int][Math]::Round(($processPercent * $memoryProgressWeight) / 100)
            Write-Progress -Id 1 -Activity '扫描进度' -Status "内存扫描：已完成 $processIndex/$scanTotal 个进程；累计命中 $($memoryResults.Count)" -PercentComplete $overallPercent
        }
    }
}
else {
    $workerScript = Get-MemoryScanWorkerScript
    $runspacePool = $null
    $jobs = New-Object System.Collections.ArrayList
    try {
        $workerCount = [Math]::Min($ThrottleLimit, $scanTotal)
        $runspacePool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $workerCount)
        $runspacePool.Open()

        foreach ($process in $scanTargets) {
            $processRecord = Get-ProcessRecordSafe -Id $process.Id -Cache $processCache
            $pipeline = [System.Management.Automation.PowerShell]::Create()
            $pipeline.RunspacePool = $runspacePool
            $null = $pipeline.AddScript($workerScript)
            $null = $pipeline.AddArgument([int]$process.Id)
            $null = $pipeline.AddArgument($patterns)
            $null = $pipeline.AddArgument($scanProcessLimit)
            $null = $pipeline.AddArgument($scanRegionLimit)
            $null = $pipeline.AddArgument($Keyword)

            try {
                $asyncResult = $pipeline.BeginInvoke()
                $null = $jobs.Add([pscustomobject]@{
                    Pipeline      = $pipeline
                    AsyncResult   = $asyncResult
                    Process       = $process
                    ProcessRecord = $processRecord
                })
            }
            catch {
                $pipeline.Dispose()
                $null = $errors.Add("PID $($process.Id) $($processRecord.ProcessName)：提交并行扫描失败：$($_.Exception.Message)")
            }
        }

        $completedCount = 0
        while ($jobs.Count -gt 0) {
            foreach ($job in @($jobs)) {
                if (-not $job.AsyncResult.IsCompleted) {
                    continue
                }

                try {
                    $scanOutput = @($job.Pipeline.EndInvoke($job.AsyncResult))
                    if ($scanOutput.Count -gt 0) {
                        $scan = $scanOutput[-1]
                    }
                    else {
                        $scan = @{ Hits = @(); Error = '并行扫描没有返回结果' }
                    }
                }
                catch {
                    $scan = @{ Hits = @(); Error = "并行扫描失败：$($_.Exception.Message)" }
                }

                if ($scan.Error) {
                    $null = $errors.Add("PID $($job.Process.Id) $($job.ProcessRecord.ProcessName)：$($scan.Error)")
                }
                Add-MemoryScanResults -ResultList $memoryResults -ProcessRecord $job.ProcessRecord -Scan $scan
                if ($JsonPath -and ($scan.Hits.Count -gt 0 -or $scan.Error)) {
                    Write-JsonSnapshot -Path $JsonPath -KeywordValue $Keyword -MemoryResultsValue $memoryResults -NetworkResultsValue $networkResults -ErrorsValue $errors
                }

                $completedCount++
                $null = $jobs.Remove($job)
                $job.Pipeline.Dispose()
                if (-not $NoProgress) {
                    $processPercent = [int][Math]::Min(100, [Math]::Round(($completedCount * 100) / [Math]::Max(1, $scanTotal)))
                    $overallPercent = [int][Math]::Round(($processPercent * $memoryProgressWeight) / 100)
                    Write-Progress -Id 1 -Activity '扫描进度' -Status "内存扫描：已完成 $completedCount/$scanTotal 个进程；累计命中 $($memoryResults.Count)" -PercentComplete $overallPercent
                }
            }

            if ($jobs.Count -gt 0) {
                Start-Sleep -Milliseconds 100
            }
        }
    }
    finally {
        foreach ($job in @($jobs)) {
            $job.Pipeline.Dispose()
        }
        if ($runspacePool) {
            $runspacePool.Close()
            $runspacePool.Dispose()
        }
    }
}

if (-not $NoProgress) {
    Write-Progress -Id 1 -Activity '扫描进度' -Status '内存扫描完成，准备检查网络连接' -PercentComplete $memoryProgressWeight
}

$reverseDnsCache = @{}
if (-not $NoReverseDns) {
    try {
        $connections = @(Get-NetTCPConnection -ErrorAction Stop | Where-Object {
            $_.RemoteAddress -and
            $_.RemoteAddress -notin @('0.0.0.0', '::', '127.0.0.1', '::1') -and
            $_.RemotePort -gt 0
        })

        $connectionIndex = 0
        foreach ($connection in $connections) {
            $connectionIndex++
            if (-not $NoProgress) {
                $connectionPercent = [int][Math]::Min(100, [Math]::Round(($connectionIndex * 100) / [Math]::Max(1, $connections.Count)))
                $overallPercent = [int][Math]::Round($memoryProgressWeight + (($connectionPercent * (100 - $memoryProgressWeight)) / 100))
                Write-Progress -Id 1 -Activity '扫描进度' -Status "网络检查：已检查 $connectionIndex/$($connections.Count) 个连接" -PercentComplete $overallPercent
            }

            $resolvedHost = Get-ReverseDnsSafe -Address ([string]$connection.RemoteAddress) -Cache $reverseDnsCache
            if ($resolvedHost -and $resolvedHost.IndexOf($Keyword, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $processRecord = Get-ProcessRecordSafe -Id ([int]$connection.OwningProcess) -Cache $processCache
                $null = $networkResults.Add([ordered]@{
                    ProcessId       = $processRecord.ProcessId
                    ProcessName     = $processRecord.ProcessName
                    Path            = $processRecord.Path
                    MatchType       = 'NetworkReverseDns'
                    Keyword         = $Keyword
                    Encoding        = ''
                    MemoryAddress   = ''
                    MemorySample    = ''
                    LocalAddress    = [string]$connection.LocalAddress
                    LocalPort       = [int]$connection.LocalPort
                    RemoteAddress   = [string]$connection.RemoteAddress
                    RemotePort      = [int]$connection.RemotePort
                    State           = [string]$connection.State
                    ResolvedHost    = $resolvedHost
                    Notes           = '命中的是远端 IP 的反向 DNS 主机名；不一定是原始访问域名，也不能单独证明当前访问了该域名。'
                })
                if ($JsonPath) {
                    Write-JsonSnapshot -Path $JsonPath -KeywordValue $Keyword -MemoryResultsValue $memoryResults -NetworkResultsValue $networkResults -ErrorsValue $errors
                }
            }
        }
    }
    catch {
        $null = $errors.Add("读取 TCP 连接失败：$($_.Exception.Message)")
    }
}

if (-not $NoProgress) {
    Write-Progress -Id 1 -Activity '扫描进度' -Completed
}

$results = @($memoryResults + $networkResults | ForEach-Object { [pscustomobject]$_ })
if ($JsonPath) {
    Write-JsonSnapshot -Path $JsonPath -KeywordValue $Keyword -MemoryResultsValue $memoryResults -NetworkResultsValue $networkResults -ErrorsValue $errors
    Write-Host "JSON 报告已写入：$JsonPath"
}

Write-Host "关键字：$Keyword"
Write-Host "内存扫描并发槽位：$ThrottleLimit"
Write-Host "内存命中：$($memoryResults.Count)；网络反向 DNS 命中：$($networkResults.Count)"
if ($results.Count -gt 0) {
    $results |
        Select-Object ProcessId, ProcessName, MatchType, Path, Encoding, ResolvedHost, RemoteAddress, RemotePort, MemoryAddress, MemorySample, Notes |
        Format-Table -AutoSize
}
else {
    Write-Host '未发现匹配项。'
}

if ($errors.Count -gt 0) {
    Write-Warning "有 $($errors.Count) 个进程或数据源未能完整读取；常见原因是权限不足或进程已退出。"
    $errors | Select-Object -First 20 | ForEach-Object { Write-Warning $_ }
}
