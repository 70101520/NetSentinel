using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Microsoft.Win32;

namespace NetSentinel.Agent;

public interface ISystemSnapshot { HeartbeatRequest Capture(Guid deviceId); EnrollRequest Enrollment(string token, Guid installationId); }

public sealed class WindowsSystemSnapshot : ISystemSnapshot
{
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
        return new(deviceId, DateTimeOffset.UtcNow, Environment.MachineName, InteractiveUser(), AgentVersion.Current, "Windows", OsVersion(), ips, macs, gateway, dns, DateTimeOffset.UtcNow.AddSeconds(-uptime), uptime);
    }

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
}
