using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace WhiteCellShield
{
    public class ProcessEventArgs : EventArgs
    {
        public required string ProcessName { get; set; }
        public int ProcessId { get; set; }
        public required string OperationType { get; set; }
        public string? Detail { get; set; }
    }

    public sealed class ShieldStatus
    {
        public required string Status { get; init; }
        public required string StartedAt { get; init; }
        public bool IsElevated { get; init; }
        public bool LsassMonitorEnabled { get; init; }
        public bool DocumentsMonitorEnabled { get; init; }
        public int RecentActivityCount { get; init; }
        public int AlertsRaised { get; init; }
        public string? LastAlertType { get; init; }
        public string? LastAlertProcess { get; init; }
        public string DocumentsPath { get; init; } = "";
    }

    public class ShieldAgent
    {
        private readonly object _lockObject = new();
        private readonly Timer _activityTimer;
        private readonly DateTime _startedAt = DateTime.UtcNow;
        private readonly string _documentsPath;
        private readonly bool _isElevated;
        private readonly HashSet<string> _recentActivities = new(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<string> _protectedExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".csv",
            ".zip", ".7z", ".rar", ".jpg", ".jpeg", ".png", ".bmp", ".gif",
            ".sql", ".db", ".bak", ".json", ".xml", ".pst", ".ost"
        };
        private readonly HashSet<string> _suspiciousProcessNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "mimikatz", "procdump", "procdump64", "dumpert", "nanodump", "rundll32",
            "comsvcs", "pypykatz", "winpmem"
        };
        private readonly HashSet<string> _trustedProcessNames = new(StringComparer.OrdinalIgnoreCase)
        {
            "system", "idle", "svchost", "explorer", "searchindexer", "searchhost",
            "msmpeng", "whitecellshield", "code", "devenv", "dotnet"
        };
        private readonly List<FileSystemWatcher> _watchers = new();

        private DateTime _lastActivityTime = DateTime.MinValue;
        private string? _lastAlertType;
        private string? _lastAlertProcess;
        private int _alertsRaised;
        private bool _isMonitoring = true;

        private const int ActivityThreshold = 5;
        private const int TimeWindowMs = 2000;

        public event EventHandler<ProcessEventArgs>? SuspiciousProcessDetected;

        public ShieldAgent()
        {
            _activityTimer = new Timer(ActivityTimerCallback!, null, Timeout.Infinite, Timeout.Infinite);
            _documentsPath = ResolveDocumentsPath();
            _isElevated = IsRunningElevated();
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            SetupLsassMonitor();
            SetupRansomwareDefense();

            EmitStatus("startup");

            while (!cancellationToken.IsCancellationRequested)
            {
                await Task.Delay(200, cancellationToken);
            }

            Stop();
        }

        public ShieldStatus GetStatus()
        {
            lock (_lockObject)
            {
                return new ShieldStatus
                {
                    Status = _isMonitoring ? "running" : "stopped",
                    StartedAt = _startedAt.ToString("O"),
                    IsElevated = _isElevated,
                    LsassMonitorEnabled = true,
                    DocumentsMonitorEnabled = _watchers.Count > 0,
                    RecentActivityCount = _recentActivities.Count,
                    AlertsRaised = _alertsRaised,
                    LastAlertType = _lastAlertType,
                    LastAlertProcess = _lastAlertProcess,
                    DocumentsPath = _documentsPath
                };
            }
        }

        private string ResolveDocumentsPath()
        {
            string documentsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            if (!Directory.Exists(documentsPath))
            {
                documentsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents");
            }

            if (!Directory.Exists(documentsPath))
            {
                Directory.CreateDirectory(documentsPath);
            }

            return documentsPath;
        }

        private static bool IsRunningElevated()
        {
            try
            {
                using WindowsIdentity identity = WindowsIdentity.GetCurrent();
                WindowsPrincipal principal = new(identity);
                return principal.IsInRole(WindowsBuiltInRole.Administrator);
            }
            catch
            {
                return false;
            }
        }

        private void SetupLsassMonitor()
        {
            Task.Run(async () =>
            {
                while (_isMonitoring)
                {
                    try
                    {
                        InspectProcessesForCredentialDumpingSignals();
                        await Task.Delay(3000);
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"Error monitoring LSASS heuristics: {ex.Message}");
                    }
                }
            });
        }

        private void InspectProcessesForCredentialDumpingSignals()
        {
            foreach (Process process in Process.GetProcesses())
            {
                try
                {
                    if (process.Id == Process.GetCurrentProcess().Id)
                    {
                        continue;
                    }

                    string processName = process.ProcessName;
                    if (_trustedProcessNames.Contains(processName))
                    {
                        continue;
                    }

                    if (_suspiciousProcessNames.Contains(processName))
                    {
                        RaiseAndContain(process, "CredentialDumpingTool", $"Suspicious process name detected: {processName}");
                        continue;
                    }

                    List<string> suspiciousModules = GetSuspiciousModules(process);
                    if (suspiciousModules.Count > 0)
                    {
                        RaiseAndContain(process, "CredentialAccessHeuristic", $"Sensitive modules loaded: {string.Join(", ", suspiciousModules)}");
                    }
                }
                catch
                {
                    // Ignore inaccessible or short-lived processes.
                }
            }
        }

        private static List<string> GetSuspiciousModules(Process process)
        {
            List<string> hits = new();
            string[] targets = { "samlib.dll", "vaultcli.dll", "dbghelp.dll", "comsvcs.dll", "ntdsapi.dll" };

            try
            {
                foreach (ProcessModule module in process.Modules)
                {
                    if (targets.Contains(module.ModuleName, StringComparer.OrdinalIgnoreCase))
                    {
                        hits.Add(module.ModuleName);
                    }
                }
            }
            catch
            {
                return new List<string>();
            }

            return hits;
        }

        private void SetupRansomwareDefense()
        {
            FileSystemWatcher watcher = new(_documentsPath)
            {
                IncludeSubdirectories = true,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                InternalBufferSize = 64 * 1024
            };

            watcher.Changed += OnFileChanged!;
            watcher.Renamed += OnFileRenamed!;
            watcher.Created += OnFileChanged!;
            watcher.EnableRaisingEvents = true;
            _watchers.Add(watcher);
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            if (!ShouldTrackFile(e.FullPath))
            {
                return;
            }

            RecordActivity($"changed:{e.FullPath}");
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            if (!ShouldTrackFile(e.FullPath))
            {
                return;
            }

            RecordActivity($"renamed:{e.OldFullPath}->{e.FullPath}");
        }

        private bool ShouldTrackFile(string path)
        {
            string extension = Path.GetExtension(path);
            if (!_protectedExtensions.Contains(extension))
            {
                return false;
            }

            string fileName = Path.GetFileName(path);
            if (string.IsNullOrWhiteSpace(fileName))
            {
                return false;
            }

            if (fileName.StartsWith("~", StringComparison.OrdinalIgnoreCase) ||
                fileName.EndsWith(".tmp", StringComparison.OrdinalIgnoreCase) ||
                fileName.EndsWith(".temp", StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            return true;
        }

        private void RecordActivity(string activity)
        {
            lock (_lockObject)
            {
                _recentActivities.Add(activity);

                if (_lastActivityTime == DateTime.MinValue)
                {
                    _lastActivityTime = DateTime.Now;
                    _activityTimer.Change(TimeWindowMs, Timeout.Infinite);
                }
                else if ((DateTime.Now - _lastActivityTime).TotalMilliseconds > TimeWindowMs)
                {
                    _lastActivityTime = DateTime.Now;
                    _recentActivities.Clear();
                    _recentActivities.Add(activity);
                    _activityTimer.Change(TimeWindowMs, Timeout.Infinite);
                }
                else if (_recentActivities.Count >= ActivityThreshold)
                {
                    TriggerRansomwareDefense();
                    _recentActivities.Clear();
                }
            }
        }

        private void ActivityTimerCallback(object? state)
        {
            lock (_lockObject)
            {
                _lastActivityTime = DateTime.MinValue;
                _recentActivities.Clear();
            }
        }

        private void TriggerRansomwareDefense()
        {
            Process? mostRecentProcess = GetMostRecentlyActiveProcess();
            if (mostRecentProcess != null)
            {
                RaiseAndContain(mostRecentProcess, "RansomwareActivity", "Rapid protected-file changes detected");
            }
        }

        private Process? GetMostRecentlyActiveProcess()
        {
            try
            {
                Process? culprit = null;

                foreach (Process proc in Process.GetProcesses()
                    .Where(p => !_trustedProcessNames.Contains(p.ProcessName) && p.Id != Process.GetCurrentProcess().Id))
                {
                    try
                    {
                        TimeSpan cpuTime = proc.TotalProcessorTime;
                        if (culprit == null || cpuTime > culprit.TotalProcessorTime)
                        {
                            culprit = proc;
                        }
                    }
                    catch
                    {
                        continue;
                    }
                }

                return culprit;
            }
            catch
            {
                return Process.GetProcesses()
                    .Where(p => !_trustedProcessNames.Contains(p.ProcessName))
                    .OrderByDescending(p => p.Id)
                    .FirstOrDefault();
            }
        }

        private void RaiseAndContain(Process process, string operationType, string detail)
        {
            if (_trustedProcessNames.Contains(process.ProcessName))
            {
                return;
            }

            lock (_lockObject)
            {
                _alertsRaised += 1;
                _lastAlertType = operationType;
                _lastAlertProcess = process.ProcessName;
            }

            OnSuspiciousProcessDetected(new ProcessEventArgs
            {
                ProcessName = process.ProcessName,
                ProcessId = process.Id,
                OperationType = operationType,
                Detail = detail
            });

            if (_isElevated)
            {
                SuspendProcess(process, operationType, detail);
            }
            else
            {
                Console.WriteLine(JsonSerializer.Serialize(new
                {
                    alert = operationType,
                    processName = process.ProcessName,
                    processId = process.Id,
                    detail,
                    action = "observe_only",
                    reason = "shield_not_elevated",
                    timestamp = DateTime.UtcNow.ToString("O")
                }));
            }
        }

        private void SuspendProcess(Process process, string operationType, string detail)
        {
            try
            {
                foreach (ProcessThread thread in process.Threads)
                {
                    IntPtr threadHandle = NativeMethods.OpenThread(NativeMethods.ThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);
                    if (threadHandle == IntPtr.Zero)
                    {
                        continue;
                    }

                    try
                    {
                        NativeMethods.SuspendThread(threadHandle);
                    }
                    finally
                    {
                        NativeMethods.CloseHandle(threadHandle);
                    }
                }

                Console.WriteLine(JsonSerializer.Serialize(new
                {
                    alert = operationType,
                    processName = process.ProcessName,
                    processId = process.Id,
                    detail,
                    action = "suspend",
                    timestamp = DateTime.UtcNow.ToString("O")
                }));
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Failed to suspend process {process.ProcessName} ({process.Id}): {ex.Message}");
            }
        }

        private void EmitStatus(string reason)
        {
            ShieldStatus status = GetStatus();
            Console.WriteLine(JsonSerializer.Serialize(new
            {
                status = status.Status,
                reason,
                startedAt = status.StartedAt,
                isElevated = status.IsElevated,
                lsassMonitorEnabled = status.LsassMonitorEnabled,
                documentsMonitorEnabled = status.DocumentsMonitorEnabled,
                documentsPath = status.DocumentsPath
            }));
        }

        protected virtual void OnSuspiciousProcessDetected(ProcessEventArgs e)
        {
            SuspiciousProcessDetected?.Invoke(this, e);
        }

        public void Stop()
        {
            _isMonitoring = false;
            foreach (FileSystemWatcher watcher in _watchers)
            {
                watcher.Dispose();
            }

            _watchers.Clear();
            _activityTimer.Dispose();
        }
    }

    public static class NativeMethods
    {
        [Flags]
        public enum ThreadAccess : int
        {
            SUSPEND_RESUME = 0x0002
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll")]
        public static extern uint SuspendThread(IntPtr hThread);
    }

    internal static class Program
    {
        private static ShieldAgent? _agent;
        private static CancellationTokenSource? _cancellationTokenSource;

        private static async Task Main(string[] args)
        {
            _cancellationTokenSource = new CancellationTokenSource();
            _agent = new ShieldAgent();

            Console.CancelKeyPress += (_, e) =>
            {
                e.Cancel = true;
                Shutdown();
            };

            Task inputTask = ListenForCommands(_cancellationTokenSource.Token);
            Task agentTask = _agent.StartAsync(_cancellationTokenSource.Token);

            await Task.WhenAny(inputTask, agentTask);
        }

        private static async Task ListenForCommands(CancellationToken cancellationToken)
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    string? inputLine = Console.ReadLine();
                    if (inputLine == null)
                    {
                        await Task.Delay(200, cancellationToken);
                        continue;
                    }

                    using JsonDocument doc = JsonDocument.Parse(inputLine);
                    JsonElement root = doc.RootElement;
                    if (!root.TryGetProperty("cmd", out JsonElement cmdProperty))
                    {
                        Console.WriteLine(JsonSerializer.Serialize(new { error = "Invalid command format: missing 'cmd' property" }));
                        continue;
                    }

                    string? command = cmdProperty.GetString();
                    switch (command)
                    {
                        case "heartbeat":
                            Console.WriteLine(JsonSerializer.Serialize(new { status = "active" }));
                            break;
                        case "status":
                            if (_agent == null)
                            {
                                Console.WriteLine(JsonSerializer.Serialize(new { error = "Shield not initialized" }));
                                break;
                            }
                            Console.WriteLine(JsonSerializer.Serialize(_agent.GetStatus()));
                            break;
                        case "stop":
                            Shutdown();
                            break;
                        default:
                            Console.WriteLine(JsonSerializer.Serialize(new { error = $"Unknown command: {command}" }));
                            break;
                    }
                }
                catch (JsonException)
                {
                    Console.WriteLine(JsonSerializer.Serialize(new { error = "Invalid JSON received" }));
                }
                catch (Exception ex)
                {
                    Console.WriteLine(JsonSerializer.Serialize(new { error = $"Error processing command: {ex.Message}" }));
                }
            }
        }

        private static void Shutdown()
        {
            Console.WriteLine(JsonSerializer.Serialize(new { status = "shutdown" }));
            _cancellationTokenSource?.Cancel();
            _agent?.Stop();
            Environment.Exit(0);
        }
    }
}
