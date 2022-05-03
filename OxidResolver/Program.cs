using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Net;
using System.Net.NetworkInformation;

using NtApiDotNet.Win32.Rpc.Transport;
using NetTools;

// TODO:
// * Add threading

namespace OxidResolver
{
    public class Program
    {
        public class Options
        {
            public string IP { get; set; }
            public string Port { get; set; } = "135";
            // Sleep between each IP address
            public int Sleep { get; set; }
            public bool Verbose { get; set; }
            public bool Ping { get; set; }

            public void Parse(string[] args)
            {
                var options = new Dictionary<string, string>();
                foreach (var arg in args)
                {
                    var splitted = arg.Split(new char[] { ':' }, 2);
                    if (splitted.Length == 2)
                    {
                        options[splitted[0].Substring(1)] = splitted[1];
                    }
                    else
                    {
                        options[splitted[0].Substring(1)] = "";
                    }
                }

                foreach (var key in options.Keys)
                {
                    var value = options[key];
                    switch (key)
                    {
                        case "ip":
                            IP = value;
                            break;
                        case "port":
                            Port = value;
                            break;
                        case "sleep":
                            int sleep;
                            int.TryParse(value, out sleep);
                            Sleep = sleep;
                            break;
                        case "verbose":
                            Verbose = true;
                            break;
                        case "ping":
                            Ping = true;
                            break;
                        default:
                            break;
                    }
                }
            }
        }

        static void Main(string[] args)
        {
            var opts = new Options();
            opts.Parse(args);

            IObjectExporter iObjectExporter = new IObjectExporter();
            RpcTransportSecurity sec = new RpcTransportSecurity();
            sec.AuthenticationLevel = RpcAuthenticationLevel.None;
            sec.AuthenticationType = RpcAuthenticationType.None;

            IPAddressRange ips;
            var isParsed = IPAddressRange.TryParse(opts.IP, out ips);
            if (!isParsed)
            {
                try
                {
                    var hostEntry = Dns.GetHostEntry(opts.IP);
                    ips = new IPAddressRange(hostEntry.AddressList[0]);
                }
                catch (Exception ex)
                {
                    if (opts.Verbose)
                    {
                        Console.WriteLine("{{\"{0}\": {{\"error\": \"[DNS] {1}\"}}}}", "", ex.Message);
                    }
                    return;
                }
            }

            foreach (var ip in ips)
            {
                if (opts.Ping)
                {
                    using (var ping = new Ping())
                    {
                        try
                        {
                            PingReply reply = ping.Send(ip);
                            if (!(reply.Status == IPStatus.Success))
                            {
                                if (opts.Verbose)
                                {
                                    Console.WriteLine("{{\"{0}\": {{\"error\": \"Host did not respond\"}}}}", ip);
                                }
                                continue;
                            }
                        }
                        catch (Exception ex)
                        {
                            if (opts.Verbose)
                            {
                                // no dns, but we use ips
                                Console.WriteLine("{{\"{0}\": {{\"error\": \"Host did not respond\"}}}}", ip);
                            }
                            continue;
                        }
                    }
                }

                var interfaces = GetInterfaces(iObjectExporter, sec, ip.ToString(), opts.Port, opts.Verbose);
                if (interfaces != null)
                {
                    for (int i = 0; i < interfaces.Length; i++)
                    {
                        interfaces[i] = string.Format("\"{0}\"", interfaces[i]);
                    }
                    Console.WriteLine("{{\"{0}\":[{1}]}}", ip, string.Join(",", interfaces));
                }
                Thread.Sleep(opts.Sleep);
            }
        }

        public static string[] GetInterfaces(IObjectExporter exp, RpcTransportSecurity sec, string host, string port="135", bool verbose=false)
        {
            try
            {
                exp.Connect("ncacn_ip_tcp", port, host, sec);
                List<string> interfaces = new List<string>();
                if (exp.Connected)
                {
                    Struct_2 s2 = new Struct_2();
                    Struct_0? s0 = new Struct_0?();
                    int p2;
                    uint res = exp.ServerAlive2(out s2, out s0, out p2);
                    if (res != 0)
                    {
                        if (verbose)
                        {
                            Console.WriteLine("{{\"{0}\": {{\"error\": \"[ServerAlive2] {1}\"}}}}", host, res);
                        }
                        return null;
                    }

                    if (!s0.HasValue)
                    {
                        return null;
                    }

                    var strArray = s0?.Member4.Take((int)s0?.Member2);
                    int[] indices = strArray.Select((b, i) => b == 0 ? i : -1).Where(i => i != -1).ToArray();
                    int prevIndex = 0;
                    // ugly as hell
                    foreach (var i in indices)
                    {
                        if (i == prevIndex) break;
                        var valArr = strArray.Skip(prevIndex).Take(i - prevIndex).ToArray();
                        var bytes = valArr.Skip(1).SelectMany(x => BitConverter.GetBytes(x)).ToArray();
                        interfaces.Add(Encoding.Unicode.GetString(bytes));
                        prevIndex = i + 1;
                    }

                    return interfaces.ToArray();
                }
                else
                {
                    Console.WriteLine("{{\"{0}\": {{\"error\": \"[Connect] Could not connect\"}}}}", host);
                    return null;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("{{\"{0}\": {{\"error\": \"[Connect] {1}\"}}}}", host, ex.Message);
            }
            finally
            {
                if (exp.Connected)
                {
                    exp.Disconnect();
                }
            }
            return null;
        }
    }
}
