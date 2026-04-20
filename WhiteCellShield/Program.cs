using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
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
    }

    public class ShieldAgent
    {
        private FileSystemWatcher? _watcher;
        private readonly object _lockObject = new object();
        private DateTime _lastActivityTime = DateTime.MinValue;
        private List<string> _recentActivities = new List<string>();
        private readonly Timer _activityTimer;
        private const int ACTIVITY_THRESHOLD = 5; // Number of activities to trigger alert
        private const int TIME_WINDOW_MS = 2000; // Time window in milliseconds
        private bool _isMonitoring = true;

        public event EventHandler<ProcessEventArgs>? SuspiciousProcessDetected;

        public ShieldAgent()
        {
            _activityTimer = new Timer(ActivityTimerCallback!, null, Timeout.Infinite, Timeout.Infinite);
        }

        public async Task StartAsync(CancellationToken cancellationToken)
        {
            SetupLsassMonitor();
            SetupRansomwareDefense();

            while (!cancellationToken.IsCancellationRequested)
            {
                await Task.Delay(100, cancellationToken); // Small delay to prevent busy loop
            }

            Stop();
        }

        private void SetupLsassMonitor()
        {
            // Monitor for access attempts to lsass process
            Task.Run(() =>
            {
                while (_isMonitoring)
                {
                    try
                    {
                        var lsass = Process.GetProcessesByName("lsass").FirstOrDefault();
                        if (lsass != null)
                        {
                            CheckForSuspiciousAccess(lsass);
                        }
                        Thread.Sleep(1000); // Check every second
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine($"Error monitoring lsass: {ex.Message}");
                    }
                }
            });
        }

        private void CheckForSuspiciousAccess(Process lsass)
        {
            try
            {
                foreach (var process in Process.GetProcesses())
                {
                    if (process.Id == lsass.Id || process.ProcessName.Equals("System", StringComparison.OrdinalIgnoreCase))
                        continue;

                    IntPtr handle = IntPtr.Zero;
                    try
                    {
                        // Try to open the LSASS process to see if another process has access
                        handle = NativeMethods.OpenProcess(NativeMethods.PROCESS_ACCESS_FLAGS.PROCESS_VM_READ | NativeMethods.PROCESS_ACCESS_FLAGS.PROCESS_QUERY_INFORMATION, false, lsass.Id);

                        if (handle != IntPtr.Zero)
                        {
                            // Check if the process has elevated privileges or is doing something suspicious
                            ProcessModuleCollection modules;
                            try
                            {
                                modules = process.Modules;
                            }
                            catch
                            {
                                // Can't access modules, skip this process
                                continue;
                            }
                            
                            // Look for known credential dumping tools/modules
                            var suspiciousModules = new[] { "samlib.dll", "ntdsapi.dll", "vaultcli.dll", "crypt32.dll" };
                            var hasSuspiciousModules = false;
                            foreach (ProcessModule module in modules)
                            {
                                if (suspiciousModules.Contains(module.ModuleName.ToLower()))
                                {
                                    hasSuspiciousModules = true;
                                    break;
                                }
                            }

                            if (hasSuspiciousModules)
                            {
                                OnSuspiciousProcessDetected(new ProcessEventArgs
                                {
                                    ProcessName = process.ProcessName,
                                    ProcessId = process.Id,
                                    OperationType = "CredentialDumpingAttempt"
                                });
                                
                                // In a real scenario, you might want to terminate or suspend the suspicious process
                                SuspendProcess(process);
                            }
                        }
                    }
                    finally
                    {
                        if (handle != IntPtr.Zero)
                        {
                            NativeMethods.CloseHandle(handle);
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Error checking for lsass access: {ex.Message}");
            }
        }

        private void SetupRansomwareDefense()
        {
            string documentsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
            
            if (!Directory.Exists(documentsPath))
            {
                // Fallback to default path if Documents folder doesn't exist
                documentsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents");
            }

            if (!Directory.Exists(documentsPath))
            {
                Console.Error.WriteLine("Documents folder not found, creating fallback");
                Directory.CreateDirectory(documentsPath);
            }

            _watcher = new FileSystemWatcher(documentsPath);
            _watcher.IncludeSubdirectories = true;
            _watcher.NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size;
            _watcher.Changed += OnFileChanged!;
            _watcher.Renamed += OnFileRenamed!;
            _watcher.EnableRaisingEvents = true;
        }

        private void OnFileChanged(object sender, FileSystemEventArgs e)
        {
            RecordActivity($"File changed: {e.Name} ({e.FullPath})");
        }

        private void OnFileRenamed(object sender, RenamedEventArgs e)
        {
            RecordActivity($"File renamed: {e.OldName} -> {e.Name} ({e.FullPath})");
        }

        private void RecordActivity(string activity)
        {
            lock (_lockObject)
            {
                _recentActivities.Add(activity);
                
                if (_lastActivityTime == DateTime.MinValue)
                {
                    _lastActivityTime = DateTime.Now;
                    _activityTimer.Change(TIME_WINDOW_MS, Timeout.Infinite);
                }
                else if ((DateTime.Now - _lastActivityTime).TotalMilliseconds > TIME_WINDOW_MS)
                {
                    // Reset the timer and activities since the last batch was too long ago
                    _lastActivityTime = DateTime.Now;
                    _recentActivities.Clear();
                    _recentActivities.Add(activity);
                    _activityTimer.Change(TIME_WINDOW_MS, Timeout.Infinite);
                }
                else if (_recentActivities.Count >= ACTIVITY_THRESHOLD)
                {
                    // Trigger ransomware defense
                    TriggerRansomwareDefense();
                    _recentActivities.Clear(); // Reset after triggering
                }
            }
        }

        private void ActivityTimerCallback(object? state)
        {
            lock (_lockObject)
            {
                _lastActivityTime = DateTime.MinValue; // Reset timer state
            }
        }

        private void TriggerRansomwareDefense()
        {
            // Find the process responsible for the file changes
            var mostRecentProcess = GetMostRecentlyActiveProcess();
            if (mostRecentProcess != null)
            {
                OnSuspiciousProcessDetected(new ProcessEventArgs
                {
                    ProcessName = mostRecentProcess.ProcessName,
                    ProcessId = mostRecentProcess.Id,
                    OperationType = "RansomwareActivity"
                });

                SuspendProcess(mostRecentProcess);
            }
        }

        private Process? GetMostRecentlyActiveProcess()
        {
            try
            {
                // Get the process with the most file handles in the Documents directory
                var processes = Process.GetProcesses();
                Process? culprit = null;

                string documentsPath = Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments);
                if (!Directory.Exists(documentsPath))
                {
                    documentsPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Documents");
                }

                foreach (var proc in processes.Where(p => !p.ProcessName.Equals("System", StringComparison.OrdinalIgnoreCase) && 
                                                         !p.ProcessName.Equals("Idle", StringComparison.OrdinalIgnoreCase)))
                {
                    try
                    {
                        // We can't easily enumerate handles in .NET without P/Invoke to NtQuerySystemInformation
                        // As a proxy, we'll use CPU time as an indicator of recent activity
                        var cpuTime = proc.TotalProcessorTime;
                        if (proc.Id != Process.GetCurrentProcess().Id) // Exclude our own process
                        {
                            if (culprit == null || cpuTime > culprit.TotalProcessorTime)
                            {
                                culprit = proc;
                            }
                        }
                    }
                    catch
                    {
                        // Process might have exited or we don't have permissions
                        continue;
                    }
                }

                return culprit;
            }
            catch
            {
                // Fallback: return the current user process with highest ID (most recently created)
                return Process.GetProcesses()
                    .Where(p => !p.ProcessName.Equals("System", StringComparison.OrdinalIgnoreCase) &&
                               !p.ProcessName.Equals("Idle", StringComparison.OrdinalIgnoreCase))
                    .OrderByDescending(p => p.Id)
                    .FirstOrDefault();
            }
        }

        private void SuspendProcess(Process process)
        {
            try
            {
                // Suspend the process using Windows API
                foreach (ProcessThread thread in process.Threads)
                {
                    IntPtr tHandle = NativeMethods.OpenThread(NativeMethods.ThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);
                    if (tHandle != IntPtr.Zero)
                    {
                        try
                        {
                            NativeMethods.SuspendThread(tHandle);
                        }
                        finally
                        {
                            NativeMethods.CloseHandle(tHandle);
                        }
                    }
                }
                
                Console.WriteLine(JsonSerializer.Serialize(new { 
                    alert = "Process suspended", 
                    processName = process.ProcessName, 
                    processId = process.Id,
                    timestamp = DateTime.UtcNow.ToString("O") 
                }));
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Failed to suspend process {process.ProcessName} ({process.Id}): {ex.Message}");
            }
        }

        protected virtual void OnSuspiciousProcessDetected(ProcessEventArgs e)
        {
            SuspiciousProcessDetected?.Invoke(this, e);
        }

        public void Stop()
        {
            _isMonitoring = false;
            _watcher?.Dispose();
            _activityTimer?.Dispose();
        }
    }

    // Static class to hold native Windows API methods
    public static class NativeMethods
    {
        [Flags]
        public enum ThreadAccess : int
        {
            TERMINATE = (0x0001),
            SUSPEND_RESUME = (0x0002),
            GET_CONTEXT = (0x0008),
            SET_CONTEXT = (0x0010),
            SET_INFORMATION = (0x0020),
            QUERY_INFORMATION = (0x0040),
            SET_THREAD_TOKEN = (0x0080),
            IMPERSONATE = (0x0100),
            DIRECT_IMPERSONATION = (0x0200)
        }

        [Flags]
        public enum PROCESS_ACCESS_FLAGS : uint
        {
            PROCESS_VM_READ = 0x0010,
            PROCESS_QUERY_INFORMATION = 0x0400
        }

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenProcess(PROCESS_ACCESS_FLAGS processAccess, bool bInheritHandle, int processId);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll")]
        public static extern IntPtr OpenThread(ThreadAccess dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("kernel32.dll")]
        public static extern uint SuspendThread(IntPtr hThread);
    }

    class Program
    {
        private static ShieldAgent? _agent;
        private static CancellationTokenSource? _cancellationTokenSource;

        static async Task Main(string[] args)
        {
            _cancellationTokenSource = new CancellationTokenSource();
            _agent = new ShieldAgent();
            
            // Handle Ctrl+C gracefully
            Console.CancelKeyPress += (sender, e) =>
            {
                e.Cancel = true;
                Shutdown();
            };

            // Start listening for commands from Python
            var inputTask = ListenForCommands(_cancellationTokenSource.Token);
            var agentTask = _agent.StartAsync(_cancellationTokenSource.Token);

            await Task.WhenAny(inputTask, agentTask);
        }

        static async Task ListenForCommands(CancellationToken cancellationToken)
        {
            string? inputLine;
            while (!cancellationToken.IsCancellationRequested)
            {
                try
                {
                    inputLine = Console.ReadLine();
                    if (inputLine == null) continue; // EOF reached

                    using var doc = JsonDocument.Parse(inputLine);
                    var root = doc.RootElement;

                    if (root.TryGetProperty("cmd", out var cmdProperty))
                    {
                        var command = cmdProperty.GetString();

                        switch (command)
                        {
                            case "heartbeat":
                                Console.WriteLine(JsonSerializer.Serialize(new { status = "active" }));
                                break;
                            case "stop":
                                Shutdown();
                                break;
                            case "status":
                                Console.WriteLine(JsonSerializer.Serialize(new { 
                                    status = "running", 
                                    uptime = DateTime.UtcNow.ToString("O") 
                                }));
                                break;
                            default:
                                Console.WriteLine(JsonSerializer.Serialize(new { 
                                    error = $"Unknown command: {command}" 
                                }));
                                break;
                        }
                    }
                    else
                    {
                        Console.WriteLine(JsonSerializer.Serialize(new { 
                            error = "Invalid command format: missing 'cmd' property" 
                        }));
                    }
                }
                catch (JsonException)
                {
                    Console.WriteLine(JsonSerializer.Serialize(new { 
                        error = "Invalid JSON received" 
                    }));
                }
                catch (Exception ex)
                {
                    Console.WriteLine(JsonSerializer.Serialize(new { 
                        error = $"Error processing command: {ex.Message}" 
                    }));
                }
            }
        }

        static void Shutdown()
        {
            Console.WriteLine(JsonSerializer.Serialize(new { status = "shutdown" }));
            _cancellationTokenSource?.Cancel();
            _agent?.Stop();
            Environment.Exit(0);
        }
    }
}