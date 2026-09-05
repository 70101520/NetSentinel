using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;

namespace NetSentinel.Agent;

public sealed record ProxySnapshot(bool Enabled, string? Proxy, string? Bypass);

public interface IWindowsProxyStore
{
    ProxySnapshot Read();
    void Write(ProxySnapshot value);
}

public sealed class WinHttpProxyStore : IWindowsProxyStore
{
    private const uint NoProxy = 1, NamedProxy = 3;
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Info { public uint AccessType; public IntPtr Proxy; public IntPtr Bypass; }
    [DllImport("winhttp.dll", SetLastError = true)] private static extern bool WinHttpGetDefaultProxyConfiguration(out Info info);
    [DllImport("winhttp.dll", SetLastError = true)] private static extern bool WinHttpSetDefaultProxyConfiguration(ref Info info);
    [DllImport("kernel32.dll")] private static extern IntPtr GlobalFree(IntPtr value);

    public ProxySnapshot Read()
    {
        if (!OperatingSystem.IsWindows()) return new(false, null, null);
        if (!WinHttpGetDefaultProxyConfiguration(out var info))
        {
            var error = Marshal.GetLastWin32Error();
            if (error == 12180) return new(false, null, null);
            throw new Win32Exception(error, "Unable to read WinHTTP proxy configuration");
        }
        try { return new(info.AccessType == NamedProxy, Marshal.PtrToStringUni(info.Proxy), Marshal.PtrToStringUni(info.Bypass)); }
        finally { if (info.Proxy != IntPtr.Zero) GlobalFree(info.Proxy); if (info.Bypass != IntPtr.Zero) GlobalFree(info.Bypass); }
    }

    public void Write(ProxySnapshot value)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("WinHTTP proxy configuration requires Windows");
        var info = new Info { AccessType = value.Enabled ? NamedProxy : NoProxy, Proxy = value.Enabled ? Marshal.StringToHGlobalUni(value.Proxy) : IntPtr.Zero, Bypass = value.Enabled && !string.IsNullOrEmpty(value.Bypass) ? Marshal.StringToHGlobalUni(value.Bypass) : IntPtr.Zero };
        try { if (!WinHttpSetDefaultProxyConfiguration(ref info)) throw new Win32Exception(Marshal.GetLastWin32Error(), "Unable to write WinHTTP proxy configuration"); }
        finally { if (info.Proxy != IntPtr.Zero) Marshal.FreeHGlobal(info.Proxy); if (info.Bypass != IntPtr.Zero) Marshal.FreeHGlobal(info.Bypass); }
    }
}

public sealed class ProxyConfigurationManager(IWindowsProxyStore store, AgentPaths paths, ILogger<ProxyConfigurationManager> logger)
{
    private static readonly Regex Host = new(@"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$", RegexOptions.CultureInvariant);
    private static readonly Regex Bypass = new(@"^(?:<local>|[A-Za-z0-9*._:\[\]-]+)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static void Validate(ProxyConfiguration config)
    {
        if (config.Version < 1) throw new InvalidDataException("Proxy configuration version is invalid");
        if (config.Mode is not ("disabled" or "configured")) throw new InvalidDataException("Proxy configuration mode is unsupported");
        if (!config.Enabled && config.Mode != "disabled") throw new InvalidDataException("Disabled proxy configuration has an inconsistent mode");
        if (config.Enabled && (config.Mode != "configured" || string.IsNullOrWhiteSpace(config.Host) || !Host.IsMatch(config.Host) || config.Port is null or < 1 or > 65535)) throw new InvalidDataException("Enabled proxy configuration is invalid");
        if (config.Bypass.Length > 64 || config.Bypass.Any(x => x.Length > 253 || !Bypass.IsMatch(x))) throw new InvalidDataException("Proxy bypass configuration is invalid");
    }

    public async Task<ProxyRuntimeStatus> ReconcileAsync(ProxyConfiguration desired, ProxyRuntimeStatus? previous, CancellationToken ct)
    {
        var sync = DateTimeOffset.UtcNow;
        try
        {
            Validate(desired);
            var baseline = await LoadOrCaptureBaselineAsync(ct);
            var expected = desired.Enabled ? new ProxySnapshot(true, $"{desired.Host}:{desired.Port}", string.Join(';', desired.Bypass)) : baseline;
            var actual = store.Read();
            var drift = !Equivalent(actual, expected);
            var versionChanged = previous?.AppliedVersion != desired.Version;
            if (drift || versionChanged)
            {
                store.Write(expected);
                actual = store.Read();
                if (!Equivalent(actual, expected)) throw new IOException("WinHTTP proxy state did not match after apply");
                logger.LogInformation(desired.Enabled ? "Proxy configuration version {Version} applied" : "Proxy baseline restored for configuration version {Version}", desired.Version);
            }
            else logger.LogDebug("Proxy configuration version {Version} unchanged", desired.Version);
            return new(desired.Version, desired.Version, desired.Enabled ? "configured" : "disabled", drift, drift || versionChanged ? "applied" : "no-change", null, desired.Enabled ? desired.Host : null, desired.Enabled ? desired.Port : null, $"{desired.Bypass.Length} entries", sync);
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or Win32Exception or PlatformNotSupportedException)
        {
            logger.LogError("Proxy configuration version {Version} failed: {ErrorType}", desired.Version, ex.GetType().Name);
            return new(desired.Version, previous?.AppliedVersion, "error", previous?.DriftDetected ?? false, "failed", ex.Message, previous?.EffectiveHost, previous?.EffectivePort, previous?.BypassSummary, sync);
        }
    }

    private async Task<ProxySnapshot> LoadOrCaptureBaselineAsync(CancellationToken ct)
    {
        if (File.Exists(paths.ProxyBaselinePath)) return JsonSerializer.Deserialize<ProxySnapshot>(await File.ReadAllTextAsync(paths.ProxyBaselinePath, ct), Json) ?? throw new InvalidDataException("Proxy baseline is invalid");
        var baseline = store.Read();
        var temporary = paths.ProxyBaselinePath + ".tmp";
        await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(baseline, Json), ct);
        try { File.Move(temporary, paths.ProxyBaselinePath, false); }
        catch (IOException) { File.Delete(temporary); }
        logger.LogInformation("Original WinHTTP proxy baseline captured");
        return baseline;
    }

    private static bool Equivalent(ProxySnapshot left, ProxySnapshot right) => left.Enabled == right.Enabled && string.Equals(left.Proxy ?? "", right.Proxy ?? "", StringComparison.OrdinalIgnoreCase) && string.Equals(left.Bypass ?? "", right.Bypass ?? "", StringComparison.OrdinalIgnoreCase);

    public static async Task RestoreBaselineAsync(IWindowsProxyStore store, AgentPaths paths, CancellationToken ct)
    {
        if (!File.Exists(paths.ProxyBaselinePath)) return;
        var baseline=JsonSerializer.Deserialize<ProxySnapshot>(await File.ReadAllTextAsync(paths.ProxyBaselinePath,ct),Json) ?? throw new InvalidDataException("Proxy baseline is invalid");
        store.Write(baseline);
    }
}
