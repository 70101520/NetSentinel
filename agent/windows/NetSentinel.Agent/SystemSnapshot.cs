using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace NetSentinel.Agent;

public interface ISystemSnapshot { HeartbeatRequest Capture(Guid deviceId); EnrollRequest Enrollment(string token, Guid installationId); }

public sealed class WindowsSystemSnapshot : ISystemSnapshot
{
    private readonly object metricsLock = new();
    private ulong? previousIdle;
    private ulong? previousKernel;
    private ulong? previousUser;
    private long? previousReceived;
    private long? previousSent;
    private DateTimeOffset? previousNetworkSample;

    public EnrollRequest Enrollment(string token, Guid installationId) => new(token, installationId.ToString(), Environment.MachineName, "Windows", OsVersion(), RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant(), AgentVersion.Current);
    public HeartbeatRequest Capture(Guid deviceId)
    {
        var interfaces = NetworkInterface.GetAllNetworkInterfaces().Where(value => value.OperationalStatus == OperationalStatus.Up).ToArray();
        var properties = interfaces.Select(value => value.GetIPProperties()).ToArray();
        var ips = properties.SelectMany(value => value.UnicastAddresses).Select(value => value.Address.ToString()).Take(32).ToArray();
        var macs = interfaces.Select(value => string.Join(":", value.GetPhysicalAddress().GetAddressBytes().Select(part => part.ToString("x2")))).Where(value => value.Length == 17).Take(32).ToArray();
        var gateway = properties.SelectMany(value => value.GatewayAddresses).Select(value => value.Address.ToString()).FirstOrDefault();
        var dns = properties.SelectMany(value => value.DnsAddresses).Select(value => value.ToString()).Distinct().Take(16).ToArray();
        var uptime = Environment.TickCount64 / 1000;
        return new(deviceId, DateTimeOffset.UtcNow, Environment.MachineName, InteractiveUser(), AgentVersion.Current, "Windows", OsVersion(), ips, macs, gateway, dns, DateTimeOffset.UtcNow.AddSeconds(-uptime), uptime, SystemMetrics: CaptureMetrics(interfaces));
    }

    private SystemMetrics CaptureMetrics(NetworkInterface[] interfaces)
    {
        lock (metricsLock)
        {
            var sampledAt=DateTimeOffset.UtcNow;
            double? cpu=null;
            if(GetSystemTimes(out var idleTime,out var kernelTime,out var userTime))
            {
                var idle=ToUInt64(idleTime);var kernel=ToUInt64(kernelTime);var user=ToUInt64(userTime);
                if(previousIdle is not null&&previousKernel is not null&&previousUser is not null)
                {
                    var total=(kernel-previousKernel.Value)+(user-previousUser.Value);var idleDelta=idle-previousIdle.Value;
                    if(total>0)cpu=ClampPercent(100d*(total-idleDelta)/total);
                }
                previousIdle=idle;previousKernel=kernel;previousUser=user;
            }
            double? memory=null;var memoryState=new MemoryStatus{Length=(uint)Marshal.SizeOf<MemoryStatus>()};
            if(GlobalMemoryStatusEx(ref memoryState))memory=ClampPercent(memoryState.MemoryLoad);
            double? disk=null;
            try{var drives=DriveInfo.GetDrives().Where(value=>value.IsReady&&value.DriveType==DriveType.Fixed).ToArray();var total=drives.Sum(value=>(double)value.TotalSize);var free=drives.Sum(value=>(double)value.AvailableFreeSpace);if(total>0)disk=ClampPercent(100d*(total-free)/total);}catch(IOException){}
            long received=0,sent=0,speed=0;
            foreach(var item in interfaces.Where(value=>value.NetworkInterfaceType is not NetworkInterfaceType.Loopback and not NetworkInterfaceType.Tunnel))
            {
                try{var stats=item.GetIPStatistics();received+=stats.BytesReceived;sent+=stats.BytesSent;if(item.Speed>0)speed+=item.Speed;}catch(NetworkInformationException){}
            }
            double? receiveBps=null,sendBps=null,networkPercent=null;
            if(previousReceived is not null&&previousSent is not null&&previousNetworkSample is not null)
            {
                var seconds=(sampledAt-previousNetworkSample.Value).TotalSeconds;
                if(seconds>0){receiveBps=Math.Max(0,(received-previousReceived.Value)/seconds);sendBps=Math.Max(0,(sent-previousSent.Value)/seconds);if(speed>0)networkPercent=ClampPercent((receiveBps.Value+sendBps.Value)*8d*100d/speed);}
            }
            previousReceived=received;previousSent=sent;previousNetworkSample=sampledAt;
            return new(cpu,memory,disk,receiveBps,sendBps,networkPercent,sampledAt);
        }
    }

    private static double ClampPercent(double value)=>Math.Round(Math.Clamp(value,0,100),2);
    private static ulong ToUInt64(FileTime value)=>((ulong)value.High<<32)|value.Low;

    private static string OsVersion() => Registry.GetValue(@"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion", null)?.ToString() ?? Environment.OSVersion.VersionString;
    private static string? InteractiveUser()
    {
        var session = WTSGetActiveConsoleSessionId();
        if (session == uint.MaxValue || !WTSQuerySessionInformation(IntPtr.Zero, session, 5, out var pointer, out _)) return null;
        try { return Marshal.PtrToStringUni(pointer); } finally { WTSFreeMemory(pointer); }
    }
    [DllImport("kernel32.dll")] private static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("Wtsapi32.dll", CharSet = CharSet.Unicode)] private static extern bool WTSQuerySessionInformation(IntPtr server, uint sessionId, int infoClass, out IntPtr buffer, out uint bytes);
    [DllImport("Wtsapi32.dll")] private static extern void WTSFreeMemory(IntPtr pointer);
    [StructLayout(LayoutKind.Sequential)] private struct FileTime{public uint Low;public uint High;}
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Auto)] private struct MemoryStatus{public uint Length;public uint MemoryLoad;public ulong TotalPhysical;public ulong AvailablePhysical;public ulong TotalPageFile;public ulong AvailablePageFile;public ulong TotalVirtual;public ulong AvailableVirtual;public ulong AvailableExtendedVirtual;}
    [DllImport("kernel32.dll",SetLastError=true)] private static extern bool GetSystemTimes(out FileTime idleTime,out FileTime kernelTime,out FileTime userTime);
    [DllImport("kernel32.dll",CharSet=CharSet.Auto,SetLastError=true)] private static extern bool GlobalMemoryStatusEx(ref MemoryStatus buffer);
}
