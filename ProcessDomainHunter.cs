using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Web.Script.Serialization;

namespace ProcessDomainHunter
{
    internal sealed class Options
    {
        public string Keyword;
        public List<int> ProcessIds = new List<int>();
        public List<string> ProcessNames = new List<string>();
        public long MaxBytesPerProcess = 268435456L;
        public long MaxRegionBytes = 67108864L;
        public int ThrottleLimit = 4;
        public bool FullScan;
        public bool NoReverseDns;
        public bool NoProgress;
        public string JsonPath;
    }

    internal sealed class ProcessRecord
    {
        public int Id;
        public string Name;
        public string Path;
    }

    internal sealed class Pattern
    {
        public string Encoding;
        public byte[] Bytes;
        public int[] Shifts;
    }

    internal sealed class MemoryHit
    {
        public string Keyword;
        public string Encoding;
        public string Address;
        public string Sample;
    }

    internal sealed class ScanResult
    {
        public List<MemoryHit> Hits = new List<MemoryHit>();
        public bool HitLimitReached;
        public string Error;
    }

    internal sealed class TcpConnectionRecord
    {
        public int ProcessId;
        public string LocalAddress;
        public int LocalPort;
        public string RemoteAddress;
        public int RemotePort;
        public string State;
    }

    public sealed class Detection
    {
        public int ProcessId { get; set; }
        public string ProcessName { get; set; }
        public string Path { get; set; }
        public string MatchType { get; set; }
        public string Keyword { get; set; }
        public string Encoding { get; set; }
        public string MemoryAddress { get; set; }
        public string MemorySample { get; set; }
        public int MemoryMatchCount { get; set; }
        public string LocalAddress { get; set; }
        public int LocalPort { get; set; }
        public string RemoteAddress { get; set; }
        public int RemotePort { get; set; }
        public string State { get; set; }
        public string ResolvedHost { get; set; }
        public string Notes { get; set; }
    }

    internal sealed class Report
    {
        public string GeneratedAt { get; set; }
        public string Keyword { get; set; }
        public List<Detection> Results { get; set; }
        public List<string> Errors { get; set; }
    }

    internal static class Native
    {
        [Flags]
        internal enum ProcessAccess : uint
        {
            QueryInformation = 0x0400,
            VirtualMemoryRead = 0x0010
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct MemoryBasicInformation
        {
            public IntPtr BaseAddress;
            public IntPtr AllocationBase;
            public uint AllocationProtect;
            public UIntPtr RegionSize;
            public uint State;
            public uint Protect;
            public uint Type;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct TcpRowOwnerPid
        {
            public uint State;
            public uint LocalAddress;
            public uint LocalPort;
            public uint RemoteAddress;
            public uint RemotePort;
            public uint OwningPid;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr OpenProcess(ProcessAccess access, bool inheritHandle, uint processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool CloseHandle(IntPtr handle);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern IntPtr GetStdHandle(int standardHandle);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool GetConsoleMode(IntPtr handle, out uint mode);

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern int VirtualQueryEx(IntPtr process, IntPtr address, out MemoryBasicInformation information, uint length);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        internal static extern bool ReadProcessMemory(IntPtr process, IntPtr address, [Out] byte[] buffer, UIntPtr size, out UIntPtr bytesRead);

        [DllImport("iphlpapi.dll", SetLastError = true)]
        internal static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int addressFamily, int tableClass, uint reserved);
    }

    internal static class Program
    {
        private const int ErrorInsufficientBuffer = 122;
        private const int AfInet = 2;
        private const int TcpTableOwnerPidAll = 5;
        private const uint MemCommit = 0x1000;
        private const int PageGuard = 0x100;
        private const int PageNoAccess = 0x01;
        private const int ChunkSize = 1024 * 1024;
        private const int MaxHitsPerProcess = 20;
        private static readonly object ConsoleLock = new object();
        private static readonly object JsonLock = new object();
        private static long LastProgressTicks;
        private static bool ProgressActive;

        private static int Main(string[] args)
        {
            Options options;
            try
            {
                options = ParseOptions(args);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine("参数错误：" + ex.Message);
                PrintUsage();
                return 2;
            }

            if (options == null)
            {
                PrintUsage();
                return 2;
            }

            if (IntPtr.Size != 8)
            {
                Console.Error.WriteLine("警告：当前不是 64 位进程，读取 64 位目标进程可能不完整。");
            }

            List<Pattern> patterns = BuildPatterns(options.Keyword);
            List<ProcessRecord> targets = GetTargetProcesses(options);
            if (targets.Count == 0)
            {
                Console.WriteLine("没有找到符合条件的进程。");
                return 0;
            }

            Console.WriteLine("实时 JSON：" + options.JsonPath);
            long processLimit = options.FullScan ? long.MaxValue : options.MaxBytesPerProcess;
            long regionLimit = options.FullScan ? long.MaxValue : options.MaxRegionBytes;
            var detections = new ConcurrentBag<Detection>();
            var errors = new ConcurrentBag<string>();
            List<Detection> networkDetections = new List<Detection>();
            int completed = 0;
            int matchedProcesses = 0;

            if (!String.IsNullOrEmpty(options.JsonPath))
            {
                TryWriteJsonSnapshot(options.JsonPath, options.Keyword, detections, networkDetections, errors);
            }

            ReportProgress(options, "内存扫描", 0, targets.Count, 0);
            var parallelOptions = new ParallelOptions { MaxDegreeOfParallelism = options.ThrottleLimit };
            Parallel.ForEach(targets, parallelOptions, target =>
            {
                ScanResult scan = ScanProcess(target, patterns, processLimit, regionLimit, options.Keyword);
                if (!String.IsNullOrEmpty(scan.Error))
                {
                    errors.Add("PID " + target.Id + " " + target.Name + "：" + scan.Error);
                }

                List<MemoryHit> usefulHits = scan.Hits
                    .Where(hit => !IsScannerCommandSample(hit.Sample))
                    .ToList();
                if (usefulHits.Count > 0)
                {
                    MemoryHit firstHit = usefulHits[0];
                    Interlocked.Increment(ref matchedProcesses);
                    detections.Add(new Detection
                    {
                        ProcessId = target.Id,
                        ProcessName = target.Name,
                        Path = target.Path,
                        MatchType = "Memory",
                        Keyword = firstHit.Keyword,
                        Encoding = firstHit.Encoding,
                        MemoryAddress = firstHit.Address,
                        MemorySample = firstHit.Sample,
                        MemoryMatchCount = usefulHits.Count,
                        Notes = BuildMemoryNote(firstHit, scan.HitLimitReached && usefulHits.Count >= MaxHitsPerProcess)
                    });
                }

                if (usefulHits.Count > 0 || !String.IsNullOrEmpty(scan.Error))
                {
                    WriteJsonSnapshotIfRequested(options, detections, networkDetections, errors);
                }

                int done = Interlocked.Increment(ref completed);
                ReportProgress(options, "内存扫描", done, targets.Count, matchedProcesses);
            });

            if (!options.NoReverseDns)
            {
                try
                {
                    List<TcpConnectionRecord> connections = GetTcpConnections();
                    Dictionary<string, string> dnsCache = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    for (int i = 0; i < connections.Count; i++)
                    {
                        TcpConnectionRecord connection = connections[i];
                        ReportProgress(options, "网络检查", i, connections.Count, detections.Count + networkDetections.Count);
                        string host = ReverseDns(connection.RemoteAddress, dnsCache);
                        if (!String.IsNullOrEmpty(host) && host.IndexOf(options.Keyword, StringComparison.OrdinalIgnoreCase) >= 0)
                        {
                            ProcessRecord record = GetProcessRecord(connection.ProcessId);
                            networkDetections.Add(new Detection
                            {
                                ProcessId = record.Id,
                                ProcessName = record.Name,
                                Path = record.Path,
                                MatchType = "NetworkReverseDns",
                                Keyword = options.Keyword,
                                LocalAddress = connection.LocalAddress,
                                LocalPort = connection.LocalPort,
                                RemoteAddress = connection.RemoteAddress,
                                RemotePort = connection.RemotePort,
                                State = connection.State,
                                ResolvedHost = host,
                                Notes = "命中的是远端 IP 的反向 DNS 主机名；不一定是原始访问域名，也不能单独证明当前访问了该域名。"
                            });
                            WriteJsonSnapshotIfRequested(options, detections, networkDetections, errors);
                        }
                    }
                }
                catch (Exception ex)
                {
                    errors.Add("读取 TCP 连接失败：" + ex.Message);
                }
            }

            List<Detection> results = detections.ToList();
            results.AddRange(networkDetections);
            results = results.OrderBy(r => r.ProcessId).ThenBy(r => r.MatchType).ToList();
            ReportProgress(options, "扫描完成", 1, 1, detections.Count + networkDetections.Count, true);
            FinishProgressLine(options);
            Console.WriteLine("关键字：" + options.Keyword);
            Console.WriteLine("内存扫描并发槽位：" + options.ThrottleLimit);
            Console.WriteLine("内存命中进程：" + detections.Count + "；网络反向 DNS 命中：" + networkDetections.Count);

            if (results.Count == 0)
            {
                Console.WriteLine("未发现匹配项。");
            }
            else
            {
                foreach (Detection result in results)
                {
                    Console.WriteLine(String.Format(
                        "PID={0} Process={1} Type={2} Encoding={3} Host={4} Remote={5}:{6} Address={7} Path={8}",
                        result.ProcessId,
                        result.ProcessName,
                        result.MatchType,
                        result.Encoding ?? String.Empty,
                        result.ResolvedHost ?? String.Empty,
                        result.RemoteAddress ?? String.Empty,
                        result.RemotePort,
                        result.MemoryAddress ?? String.Empty,
                        result.Path ?? String.Empty));
                }
            }

            if (errors.Count > 0)
            {
                Console.Error.WriteLine("有 " + errors.Count + " 个进程或数据源未能完整读取：");
                foreach (string error in errors.Take(20))
                {
                    Console.Error.WriteLine("  " + error);
                }
            }

            if (!String.IsNullOrEmpty(options.JsonPath))
            {
                if (TryWriteJsonSnapshot(options.JsonPath, options.Keyword, detections, networkDetections, errors))
                {
                    Console.WriteLine("JSON 报告已写入：" + options.JsonPath);
                }
            }
            return 0;
        }

        private static void WriteJsonSnapshotIfRequested(
            Options options,
            IEnumerable<Detection> memoryDetections,
            IEnumerable<Detection> networkDetections,
            IEnumerable<string> errors)
        {
            if (!String.IsNullOrEmpty(options.JsonPath))
            {
                TryWriteJsonSnapshot(options.JsonPath, options.Keyword, memoryDetections, networkDetections, errors);
            }
        }

        private static bool TryWriteJsonSnapshot(
            string path,
            string keyword,
            IEnumerable<Detection> memoryDetections,
            IEnumerable<Detection> networkDetections,
            IEnumerable<string> errors)
        {
            try
            {
                WriteJsonSnapshot(path, keyword, memoryDetections, networkDetections, errors);
                return true;
            }
            catch (Exception ex)
            {
                const string prefix = "实时写入 JSON 失败：";
                var errorList = errors as ConcurrentBag<string>;
                if (errorList != null && !errorList.Any(error => error.StartsWith(prefix, StringComparison.Ordinal)))
                {
                    errorList.Add(prefix + ex.Message);
                }
                else
                {
                    Console.Error.WriteLine(prefix + ex.Message);
                }
                return false;
            }
        }

        private static void WriteJsonSnapshot(
            string path,
            string keyword,
            IEnumerable<Detection> memoryDetections,
            IEnumerable<Detection> networkDetections,
            IEnumerable<string> errors)
        {
            lock (JsonLock)
            {
                List<Detection> results = memoryDetections.ToList();
                results.AddRange(networkDetections);
                results = results.OrderBy(result => result.ProcessId).ThenBy(result => result.MatchType).ToList();
                Report report = new Report
                {
                    GeneratedAt = DateTimeOffset.Now.ToString("o"),
                    Keyword = keyword,
                    Results = results,
                    Errors = errors.ToList()
                };
                string json = new JavaScriptSerializer().Serialize(report);
                string fullPath = Path.GetFullPath(path);
                string tempPath = fullPath + "." + Process.GetCurrentProcess().Id + ".tmp";
                try
                {
                    File.WriteAllText(tempPath, json, new UTF8Encoding(false));
                    if (File.Exists(fullPath))
                    {
                        try
                        {
                            File.Replace(tempPath, fullPath, null, true);
                        }
                        catch
                        {
                            File.Copy(tempPath, fullPath, true);
                            File.Delete(tempPath);
                        }
                    }
                    else
                    {
                        File.Move(tempPath, fullPath);
                    }
                }
                finally
                {
                    if (File.Exists(tempPath))
                    {
                        File.Delete(tempPath);
                    }
                }
            }
        }

        private static Options ParseOptions(string[] args)
        {
            if (args == null || args.Length == 0)
            {
                return null;
            }

            var options = new Options();
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];
                string lower = arg.ToLowerInvariant();
                if (lower == "-keyword")
                {
                    options.Keyword = NextValue(args, ref i, "-Keyword");
                }
                else if (lower == "-processid")
                {
                    foreach (string value in NextValue(args, ref i, "-ProcessId").Split(','))
                    {
                        options.ProcessIds.Add(Int32.Parse(value.Trim()));
                    }
                }
                else if (lower == "-processname")
                {
                    options.ProcessNames.AddRange(NextValue(args, ref i, "-ProcessName").Split(',').Where(s => !String.IsNullOrWhiteSpace(s)).Select(s => s.Trim()));
                }
                else if (lower == "-maxbytesperprocess")
                {
                    options.MaxBytesPerProcess = Int64.Parse(NextValue(args, ref i, "-MaxBytesPerProcess"));
                }
                else if (lower == "-maxregionbytes")
                {
                    options.MaxRegionBytes = Int64.Parse(NextValue(args, ref i, "-MaxRegionBytes"));
                }
                else if (lower == "-throttlelimit")
                {
                    options.ThrottleLimit = Int32.Parse(NextValue(args, ref i, "-ThrottleLimit"));
                }
                else if (lower == "-fullscan")
                {
                    options.FullScan = true;
                }
                else if (lower == "-noreversedns")
                {
                    options.NoReverseDns = true;
                }
                else if (lower == "-noprogress")
                {
                    options.NoProgress = true;
                }
                else if (lower == "-jsonpath")
                {
                    options.JsonPath = NextValue(args, ref i, "-JsonPath");
                }
                else if (lower == "-help" || lower == "--help" || lower == "/?")
                {
                    return null;
                }
                else
                {
                    throw new ArgumentException("未知参数：" + arg);
                }
            }

            if (String.IsNullOrWhiteSpace(options.Keyword))
            {
                throw new ArgumentException("必须提供 -Keyword。");
            }
            if (options.MaxBytesPerProcess <= 0 || options.MaxRegionBytes <= 0)
            {
                throw new ArgumentException("内存扫描上限必须大于 0。");
            }
            if (options.ThrottleLimit < 1 || options.ThrottleLimit > 32)
            {
                throw new ArgumentException("-ThrottleLimit 必须在 1 到 32 之间。");
            }
            if (String.IsNullOrWhiteSpace(options.JsonPath))
            {
                string stamp = DateTime.Now.ToString("yyyyMMdd-HHmmss-fff");
                options.JsonPath = Path.Combine(Environment.CurrentDirectory, "ProcessDomainHunter-" + stamp + ".json");
            }
            return options;
        }

        private static string NextValue(string[] args, ref int index, string name)
        {
            if (index + 1 >= args.Length)
            {
                throw new ArgumentException(name + " 缺少值。");
            }
            index++;
            return args[index];
        }

        private static List<ProcessRecord> GetTargetProcesses(Options options)
        {
            int currentPid = Process.GetCurrentProcess().Id;
            var result = new List<ProcessRecord>();
            Process[] processes = Process.GetProcesses();
            foreach (Process process in processes)
            {
                try
                {
                    if (process.Id <= 4 || process.Id == currentPid)
                    {
                        continue;
                    }
                    if (options.ProcessIds.Count > 0 && !options.ProcessIds.Contains(process.Id))
                    {
                        continue;
                    }
                    if (options.ProcessNames.Count > 0 && !options.ProcessNames.Any(n => String.Equals(n, process.ProcessName, StringComparison.OrdinalIgnoreCase)))
                    {
                        continue;
                    }
                    result.Add(new ProcessRecord { Id = process.Id, Name = process.ProcessName, Path = GetProcessPath(process) });
                }
                catch
                {
                }
                finally
                {
                    process.Dispose();
                }
            }
            return result.OrderBy(p => p.Id).ToList();
        }

        private static ProcessRecord GetProcessRecord(int id)
        {
            try
            {
                using (Process process = Process.GetProcessById(id))
                {
                    return new ProcessRecord { Id = id, Name = process.ProcessName, Path = GetProcessPath(process) };
                }
            }
            catch
            {
                return new ProcessRecord { Id = id, Name = "<已退出或不可见>", Path = String.Empty };
            }
        }

        private static string GetProcessPath(Process process)
        {
            try
            {
                return process.MainModule.FileName;
            }
            catch
            {
                return String.Empty;
            }
        }

        private static List<Pattern> BuildPatterns(string keyword)
        {
            string lower = keyword.ToLowerInvariant();
            byte[] utf8 = Encoding.UTF8.GetBytes(lower);
            byte[] unicode = Encoding.Unicode.GetBytes(lower);
            var patterns = new List<Pattern>();
            patterns.Add(new Pattern { Encoding = "UTF-8/ASCII", Bytes = utf8, Shifts = BuildShifts(utf8) });
            patterns.Add(new Pattern { Encoding = "UTF-16LE", Bytes = unicode, Shifts = BuildShifts(unicode) });
            return patterns;
        }

        private static int[] BuildShifts(byte[] pattern)
        {
            var shifts = Enumerable.Repeat(pattern.Length, 256).ToArray();
            for (int i = 0; i < pattern.Length - 1; i++)
            {
                shifts[pattern[i]] = pattern.Length - 1 - i;
            }
            return shifts;
        }

        private static ScanResult ScanProcess(ProcessRecord process, List<Pattern> patterns, long processLimit, long regionLimit, string keyword)
        {
            var result = new ScanResult();
            IntPtr handle = Native.OpenProcess(Native.ProcessAccess.QueryInformation | Native.ProcessAccess.VirtualMemoryRead, false, (uint)process.Id);
            if (handle == IntPtr.Zero)
            {
                result.Error = "无法打开进程，Win32 错误码 " + Marshal.GetLastWin32Error();
                return result;
            }

            try
            {
                IntPtr address = IntPtr.Zero;
                long scanned = 0;
                uint infoSize = (uint)Marshal.SizeOf(typeof(Native.MemoryBasicInformation));
                int overlap = patterns.Max(p => p.Bytes.Length) - 1;

                while (true)
                {
                    Native.MemoryBasicInformation info;
                    if (Native.VirtualQueryEx(handle, address, out info, infoSize) == 0)
                    {
                        break;
                    }
                    long regionSize = (long)info.RegionSize.ToUInt64();
                    if (regionSize <= 0)
                    {
                        break;
                    }
                    long nextAddress = address.ToInt64() + regionSize;
                    if (nextAddress <= address.ToInt64())
                    {
                        break;
                    }

                    if (info.State == MemCommit && IsReadable(info.Protect) && scanned < processLimit)
                    {
                        long bytesInRegion = Math.Min(regionSize, regionLimit);
                        bytesInRegion = Math.Min(bytesInRegion, processLimit - scanned);
                        long regionOffset = 0;
                        byte[] carry = new byte[0];

                        while (regionOffset < bytesInRegion)
                        {
                            int readLength = (int)Math.Min(ChunkSize, bytesInRegion - regionOffset);
                            byte[] buffer = new byte[readLength];
                            UIntPtr bytesRead;
                            bool ok = Native.ReadProcessMemory(handle, new IntPtr(address.ToInt64() + regionOffset), buffer, (UIntPtr)readLength, out bytesRead);
                            int actual = (int)Math.Min(readLength, (long)bytesRead.ToUInt64());
                            if (!ok || actual <= 0)
                            {
                                break;
                            }

                            byte[] combined = new byte[carry.Length + actual];
                            if (carry.Length > 0)
                            {
                                Buffer.BlockCopy(carry, 0, combined, 0, carry.Length);
                            }
                            Buffer.BlockCopy(buffer, 0, combined, carry.Length, actual);
                            byte[] lower = ToAsciiLower(combined);

                            foreach (Pattern pattern in patterns)
                            {
                                int match = FindPattern(lower, pattern);
                                if (match >= 0)
                                {
                                    if (result.Hits.Count < MaxHitsPerProcess)
                                    {
                                        long matchAddress = address.ToInt64() + regionOffset - carry.Length + match;
                                        result.Hits.Add(new MemoryHit
                                        {
                                            Keyword = keyword,
                                            Encoding = pattern.Encoding,
                                            Address = String.Format("0x{0:X}", matchAddress),
                                            Sample = GetSnippet(combined, match, pattern.Bytes.Length, pattern.Encoding == "UTF-16LE")
                                        });
                                    }
                                    else
                                    {
                                        result.HitLimitReached = true;
                                    }
                                }
                            }

                            if (combined.Length > overlap)
                            {
                                carry = new byte[overlap];
                                Buffer.BlockCopy(combined, combined.Length - overlap, carry, 0, overlap);
                            }
                            else
                            {
                                carry = combined;
                            }
                            regionOffset += actual;
                            scanned += actual;
                        }
                    }

                    address = new IntPtr(nextAddress);
                    if (scanned >= processLimit)
                    {
                        break;
                    }
                }
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
            }
            finally
            {
                Native.CloseHandle(handle);
            }
            return result;
        }

        private static bool IsReadable(uint protection)
        {
            if ((protection & PageGuard) != 0 || protection == PageNoAccess)
            {
                return false;
            }
            return protection == 0x02 || protection == 0x04 || protection == 0x08 || protection == 0x20 || protection == 0x40 || protection == 0x80;
        }

        private static byte[] ToAsciiLower(byte[] bytes)
        {
            byte[] result = new byte[bytes.Length];
            Buffer.BlockCopy(bytes, 0, result, 0, bytes.Length);
            for (int i = 0; i < result.Length; i++)
            {
                if (result[i] >= (byte)'A' && result[i] <= (byte)'Z')
                {
                    result[i] = (byte)(result[i] + 32);
                }
            }
            return result;
        }

        private static int FindPattern(byte[] buffer, Pattern pattern)
        {
            int last = pattern.Bytes.Length - 1;
            int offset = 0;
            while (offset <= buffer.Length - pattern.Bytes.Length)
            {
                int i = last;
                while (i >= 0 && buffer[offset + i] == pattern.Bytes[i])
                {
                    i--;
                }
                if (i < 0)
                {
                    return offset;
                }
                offset += pattern.Shifts[buffer[offset + last]];
            }
            return -1;
        }

        private static string GetSnippet(byte[] buffer, int offset, int patternLength, bool unicode)
        {
            int start = Math.Max(0, offset - 48);
            int end = Math.Min(buffer.Length, offset + patternLength + 80);
            int count = end - start;
            if (count <= 0)
            {
                return String.Empty;
            }
            byte[] snippet = new byte[count];
            Buffer.BlockCopy(buffer, start, snippet, 0, count);
            string text = (unicode ? Encoding.Unicode : Encoding.UTF8).GetString(snippet);
            var builder = new StringBuilder(text.Length);
            foreach (char c in text)
            {
                builder.Append(Char.IsControl(c) ? '.' : c);
            }
            string cleaned = builder.ToString().Trim();
            return cleaned.Substring(0, Math.Min(220, cleaned.Length));
        }

        private static string BuildMemoryNote(MemoryHit hit, bool hitLimitReached)
        {
            string sample = hit.Sample ?? String.Empty;
            string suffix = hitLimitReached ? "；该进程至少还有 20 个匹配位置，结果已截取" : String.Empty;
            if (sample.IndexOf("translate", StringComparison.OrdinalIgnoreCase) >= 0 ||
                sample.IndexOf("u=https://", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "内存中命中翻译 URL 或 URL 参数上下文，属于浏览器页面、历史记录或缓存线索；不能证明当前正在访问该域名" + suffix + "。";
            }
            if (sample.IndexOf("partitionKey", StringComparison.OrdinalIgnoreCase) >= 0 ||
                sample.IndexOf("cookie", StringComparison.OrdinalIgnoreCase) >= 0 ||
                sample.IndexOf("cache", StringComparison.OrdinalIgnoreCase) >= 0 ||
                sample.IndexOf("history", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "内存中命中浏览器分区、Cookie、缓存或历史数据上下文，属于历史/页面数据线索；不能证明当前正在访问该域名" + suffix + "。";
            }
            if (sample.IndexOf("http://", StringComparison.OrdinalIgnoreCase) >= 0 ||
                sample.IndexOf("https://", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                return "内存中命中包含 URL 的字符串上下文；这只能证明该 URL 副本存在于进程内存，不能证明当前正在访问该域名" + suffix + "。";
            }
            return "内存中命中该字符串，但当前样本没有足够的 URL 或请求上下文；不能证明当前正在访问该域名" + suffix + "。";
        }

        private static bool IsScannerCommandSample(string sample)
        {
            if (String.IsNullOrEmpty(sample))
            {
                return false;
            }
            bool mentionsScanner = sample.IndexOf("ProcessDomainHunter", StringComparison.OrdinalIgnoreCase) >= 0 ||
                sample.IndexOf("inHunter.exe", StringComparison.OrdinalIgnoreCase) >= 0;
            bool looksLikeCommand = sample.IndexOf("-Keyword", StringComparison.OrdinalIgnoreCase) >= 0 ||
                sample.IndexOf("-FullScan", StringComparison.OrdinalIgnoreCase) >= 0 ||
                sample.IndexOf("-JsonPath", StringComparison.OrdinalIgnoreCase) >= 0;
            return looksLikeCommand && (mentionsScanner ||
                sample.IndexOf("-FullScan", StringComparison.OrdinalIgnoreCase) >= 0 ||
                sample.IndexOf("-JsonPath", StringComparison.OrdinalIgnoreCase) >= 0);
        }

        private static List<TcpConnectionRecord> GetTcpConnections()
        {
            int size = 0;
            uint status = Native.GetExtendedTcpTable(IntPtr.Zero, ref size, true, AfInet, TcpTableOwnerPidAll, 0);
            if (status != ErrorInsufficientBuffer && status != 0)
            {
                throw new InvalidOperationException("GetExtendedTcpTable 返回错误码 " + status);
            }

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                status = Native.GetExtendedTcpTable(buffer, ref size, true, AfInet, TcpTableOwnerPidAll, 0);
                if (status != 0)
                {
                    throw new InvalidOperationException("GetExtendedTcpTable 返回错误码 " + status);
                }
                int count = Marshal.ReadInt32(buffer);
                int rowSize = Marshal.SizeOf(typeof(Native.TcpRowOwnerPid));
                var result = new List<TcpConnectionRecord>();
                IntPtr rowPtr = IntPtr.Add(buffer, 4);
                for (int i = 0; i < count; i++)
                {
                    Native.TcpRowOwnerPid row = (Native.TcpRowOwnerPid)Marshal.PtrToStructure(rowPtr, typeof(Native.TcpRowOwnerPid));
                    int remotePort = NetworkPort(row.RemotePort);
                    IPAddress remote = new IPAddress(row.RemoteAddress);
                    if (remotePort > 0 && !IPAddress.IsLoopback(remote) && !remote.Equals(IPAddress.Any))
                    {
                        result.Add(new TcpConnectionRecord
                        {
                            ProcessId = (int)row.OwningPid,
                            LocalAddress = new IPAddress(row.LocalAddress).ToString(),
                            LocalPort = NetworkPort(row.LocalPort),
                            RemoteAddress = remote.ToString(),
                            RemotePort = remotePort,
                            State = TcpStateName(row.State)
                        });
                    }
                    rowPtr = IntPtr.Add(rowPtr, rowSize);
                }
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        private static int NetworkPort(uint port)
        {
            return (ushort)IPAddress.NetworkToHostOrder((short)(port & 0xffff));
        }

        private static string TcpStateName(uint state)
        {
            string[] names = { "", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RECEIVED", "ESTABLISHED", "FIN_WAIT_1", "FIN_WAIT_2", "CLOSE_WAIT", "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB" };
            return state < names.Length ? names[state] : state.ToString();
        }

        private static string ReverseDns(string address, Dictionary<string, string> cache)
        {
            if (cache.ContainsKey(address))
            {
                return cache[address];
            }
            string host = String.Empty;
            try
            {
                IPAddress ip = IPAddress.Parse(address);
                Task<string> lookup = Task.Factory.StartNew<string>(() => Dns.GetHostEntry(ip).HostName);
                if (lookup.Wait(500))
                {
                    host = lookup.Result;
                }
            }
            catch
            {
            }
            cache[address] = host;
            return host;
        }

        private static void ReportProgress(Options options, string phase, int done, int total, int hits, bool force = false)
        {
            if (options.NoProgress || !IsInteractiveConsole())
            {
                return;
            }
            int percent = total <= 0 ? 100 : Math.Min(100, (int)Math.Round(done * 100.0 / total));
            lock (ConsoleLock)
            {
                long now = Stopwatch.GetTimestamp();
                long minTicks = Stopwatch.Frequency / 10;
                if (!force && LastProgressTicks != 0 && now - LastProgressTicks < minTicks)
                {
                    return;
                }
                LastProgressTicks = now;

                int width = GetConsoleWidth();
                int barWidth = Math.Max(10, Math.Min(24, width - 70));
                int filled = (int)Math.Round(barWidth * percent / 100.0);
                string bar = "[" + new String('#', filled) + new String('-', barWidth - filled) + "]";
                string text = String.Format("{0} {1} {2}/{3} {4,3}% | 命中进程 {5} | 并发 {6}",
                    phase, bar, done, total, percent, hits, options.ThrottleLimit);
                if (text.Length > width)
                {
                    text = text.Substring(0, width);
                }
                text = text.PadRight(width);

                try
                {
                    Console.SetCursorPosition(0, Console.CursorTop);
                    Console.Write(text);
                    ProgressActive = true;
                }
                catch
                {
                    ProgressActive = false;
                }
            }
        }

        private static bool IsInteractiveConsole()
        {
            try
            {
                IntPtr output = Native.GetStdHandle(-11);
                uint mode;
                return output != IntPtr.Zero && output != new IntPtr(-1) && Native.GetConsoleMode(output, out mode);
            }
            catch
            {
                return false;
            }
        }

        private static int GetConsoleWidth()
        {
            try
            {
                return Math.Max(40, Math.Min(120, Console.WindowWidth - 1));
            }
            catch
            {
                return 120;
            }
        }

        private static void FinishProgressLine(Options options)
        {
            if (options.NoProgress || !ProgressActive)
            {
                return;
            }
            lock (ConsoleLock)
            {
                try
                {
                    Console.SetCursorPosition(0, Console.CursorTop);
                    Console.Write(new String(' ', GetConsoleWidth()));
                    Console.SetCursorPosition(0, Console.CursorTop);
                }
                catch
                {
                }
                ProgressActive = false;
            }
        }

        private static void PrintUsage()
        {
            Console.WriteLine("ProcessDomainHunter.exe -Keyword <关键字> [选项]");
            Console.WriteLine("  -ProcessId 123,456       只扫描指定 PID");
            Console.WriteLine("  -ProcessName chrome      只扫描指定进程名");
            Console.WriteLine("  -FullScan                取消每进程和每区域的内存上限");
            Console.WriteLine("  -ThrottleLimit 4         并发扫描槽位，默认 4");
            Console.WriteLine("  -NoReverseDns            只做内存扫描");
            Console.WriteLine("  -NoProgress              关闭总体进度显示");
            Console.WriteLine("  -JsonPath result.json    可选：自定义 JSON 路径；默认当前目录按时间戳生成");
        }
    }
}
