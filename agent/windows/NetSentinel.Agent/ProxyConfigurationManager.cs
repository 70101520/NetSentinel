using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;

namespace NetSentinel.Agent;

public sealed record ProxySnapshot(
    bool Enabled,
    string? Proxy,
    string? Bypass,
    int? BrowserProxyEnable = null,
    string? BrowserProxy = null,
    string? BrowserBypass = null,
    int? ProxySettingsPerUser = null,
    bool? EdgePolicyPresent = null,
    string? EdgeProxySettings = null,
    bool? ChromePolicyPresent = null,
    string? ChromeProxySettings = null,
    bool? FirefoxPolicyPresent = null,
    string? FirefoxMode = null,
    int? FirefoxLocked = null,
    string? FirefoxHttpProxy = null,
    int? FirefoxUseHttpProxyForAllProtocols = null,
    string? FirefoxSslProxy = null,
    string? FirefoxPassthrough = null);

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
    [DllImport("wininet.dll", SetLastError = true)] private static extern bool InternetSetOption(IntPtr internet, int option, IntPtr buffer, int length);
    private const string InternetSettings = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const string InternetPolicy = @"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings";
    private const string EdgePolicy = @"SOFTWARE\Policies\Microsoft\Edge";
    private const string ChromePolicy = @"SOFTWARE\Policies\Google\Chrome";
    private const string FirefoxProxyPolicy = @"SOFTWARE\Policies\Mozilla\Firefox\Proxy";

    public ProxySnapshot Read()
    {
        if (!OperatingSystem.IsWindows()) return new(false, null, null);
        if (!WinHttpGetDefaultProxyConfiguration(out var info))
        {
            var error = Marshal.GetLastWin32Error();
            if (error == 12180) return new(false, null, null);
            throw new Win32Exception(error, "Unable to read WinHTTP proxy configuration");
        }
        try
        {
            using var settings = Registry.LocalMachine.OpenSubKey(InternetSettings);
            using var policy = Registry.LocalMachine.OpenSubKey(InternetPolicy);
            using var edge = Registry.LocalMachine.OpenSubKey(EdgePolicy);
            using var chrome = Registry.LocalMachine.OpenSubKey(ChromePolicy);
            using var firefox = Registry.LocalMachine.OpenSubKey(FirefoxProxyPolicy);
            var edgeProxy=edge?.GetValue("ProxySettings") as string;
            var chromeProxy=chrome?.GetValue("ProxySettings") as string;
            var firefoxMode = firefox?.GetValue("Mode") as string;
            var firefoxLocked = firefox?.GetValue("Locked") as int?;
            var firefoxHttpProxy = firefox?.GetValue("HTTPProxy") as string;
            var firefoxUseAllProtocols = firefox?.GetValue("UseHTTPProxyForAllProtocols") as int?;
            var firefoxSslProxy = firefox?.GetValue("SSLProxy") as string;
            var firefoxPassthrough = firefox?.GetValue("Passthrough") as string;
            var firefoxPolicyPresent = firefoxMode is not null || firefoxLocked.HasValue ||
                firefoxHttpProxy is not null || firefoxUseAllProtocols.HasValue ||
                firefoxSslProxy is not null || firefoxPassthrough is not null;
            return new(
                info.AccessType == NamedProxy,
                Marshal.PtrToStringUni(info.Proxy),
                Marshal.PtrToStringUni(info.Bypass),
                settings?.GetValue("ProxyEnable") as int?,
                settings?.GetValue("ProxyServer") as string,
                settings?.GetValue("ProxyOverride") as string,
                policy?.GetValue("ProxySettingsPerUser") as int?,
                edgeProxy is not null,
                edgeProxy,
                chromeProxy is not null,
                chromeProxy,
                firefoxPolicyPresent,
                firefoxMode,
                firefoxLocked,
                firefoxHttpProxy,
                firefoxUseAllProtocols,
                firefoxSslProxy,
                firefoxPassthrough);
        }
        finally { if (info.Proxy != IntPtr.Zero) GlobalFree(info.Proxy); if (info.Bypass != IntPtr.Zero) GlobalFree(info.Bypass); }
    }

    public void Write(ProxySnapshot value)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("WinHTTP proxy configuration requires Windows");
        var info = new Info { AccessType = value.Enabled ? NamedProxy : NoProxy, Proxy = value.Enabled ? Marshal.StringToHGlobalUni(value.Proxy) : IntPtr.Zero, Bypass = value.Enabled && !string.IsNullOrEmpty(value.Bypass) ? Marshal.StringToHGlobalUni(value.Bypass) : IntPtr.Zero };
        var succeeded=false;var error=0;
        try { succeeded=WinHttpSetDefaultProxyConfiguration(ref info);if(!succeeded)error=Marshal.GetLastWin32Error(); }
        finally { if (info.Proxy != IntPtr.Zero) Marshal.FreeHGlobal(info.Proxy); if (info.Bypass != IntPtr.Zero) Marshal.FreeHGlobal(info.Bypass); }
        if (value.BrowserProxyEnable.HasValue)
        {
            using var policy = Registry.LocalMachine.CreateSubKey(InternetPolicy, true) ?? throw new IOException("Unable to open machine proxy policy");
            using var settings = Registry.LocalMachine.CreateSubKey(InternetSettings, true) ?? throw new IOException("Unable to open machine Internet settings");
            if (value.ProxySettingsPerUser.HasValue) policy.SetValue("ProxySettingsPerUser", value.ProxySettingsPerUser.Value, RegistryValueKind.DWord); else policy.DeleteValue("ProxySettingsPerUser", false);
            settings.SetValue("ProxyEnable", value.BrowserProxyEnable.Value, RegistryValueKind.DWord);
            if (value.BrowserProxy is not null) settings.SetValue("ProxyServer", value.BrowserProxy, RegistryValueKind.String); else settings.DeleteValue("ProxyServer", false);
            if (value.BrowserBypass is not null) settings.SetValue("ProxyOverride", value.BrowserBypass, RegistryValueKind.String); else settings.DeleteValue("ProxyOverride", false);
            InternetSetOption(IntPtr.Zero, 39, IntPtr.Zero, 0);
            InternetSetOption(IntPtr.Zero, 37, IntPtr.Zero, 0);
        }
        WriteBrowserPolicy(EdgePolicy,value.EdgePolicyPresent,value.EdgeProxySettings);
        WriteBrowserPolicy(ChromePolicy,value.ChromePolicyPresent,value.ChromeProxySettings);
        WriteFirefoxPolicy(value);
        if (!succeeded)
        {
            var actual=Read();
            var matches=actual.Enabled==value.Enabled&&string.Equals(actual.Proxy??"",value.Proxy??"",StringComparison.OrdinalIgnoreCase)&&string.Equals(actual.Bypass??"",value.Bypass??"",StringComparison.OrdinalIgnoreCase);
            if (!matches)throw new Win32Exception(error,"Unable to write WinHTTP proxy configuration");
        }
    }

    private static void WriteBrowserPolicy(string path,bool? present,string? settings)
    {
        if (!present.HasValue)return;
        using var key=Registry.LocalMachine.CreateSubKey(path,true) ?? throw new IOException($"Unable to open browser proxy policy: {path}");
        if (present.Value && settings is not null)key.SetValue("ProxySettings",settings,RegistryValueKind.String);
        else key.DeleteValue("ProxySettings",false);
    }

    private static void WriteFirefoxPolicy(ProxySnapshot value)
    {
        if (!value.FirefoxPolicyPresent.HasValue) return;
        using var key = Registry.LocalMachine.CreateSubKey(FirefoxProxyPolicy, true) ?? throw new IOException("Unable to open Firefox proxy policy");
        WriteValue(key, "Mode", value.FirefoxPolicyPresent.Value ? value.FirefoxMode : null, RegistryValueKind.String);
        WriteValue(key, "Locked", value.FirefoxPolicyPresent.Value ? value.FirefoxLocked : null, RegistryValueKind.DWord);
        WriteValue(key, "HTTPProxy", value.FirefoxPolicyPresent.Value ? value.FirefoxHttpProxy : null, RegistryValueKind.String);
        WriteValue(key, "UseHTTPProxyForAllProtocols", value.FirefoxPolicyPresent.Value ? value.FirefoxUseHttpProxyForAllProtocols : null, RegistryValueKind.DWord);
        WriteValue(key, "SSLProxy", value.FirefoxPolicyPresent.Value ? value.FirefoxSslProxy : null, RegistryValueKind.String);
        WriteValue(key, "Passthrough", value.FirefoxPolicyPresent.Value ? value.FirefoxPassthrough : null, RegistryValueKind.String);
    }

    private static void WriteValue(RegistryKey key, string name, object? value, RegistryValueKind kind)
    {
        if (value is null) key.DeleteValue(name, false);
        else key.SetValue(name, value, kind);
    }
}

public sealed class ProxyConfigurationManager(IWindowsProxyStore store, AgentPaths paths, ILogger<ProxyConfigurationManager> logger)
{
    private static readonly Regex Host = new(@"^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$", RegexOptions.CultureInvariant);
    private static readonly Regex Bypass = new(@"^(?:<local>|[A-Za-z0-9*._:\[\]/-]+)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };

    public static void Validate(ProxyConfiguration config)
    {
        if (config.Version < 1) throw new InvalidDataException("Proxy configuration version is invalid");
        if (config.Mode is not ("disabled" or "configured")) throw new InvalidDataException("Proxy configuration mode is unsupported");
        if (!config.Enabled && config.Mode != "disabled") throw new InvalidDataException("Disabled proxy configuration has an inconsistent mode");
        if (config.Enabled && (config.Mode != "configured" || string.IsNullOrWhiteSpace(config.Host) || !Host.IsMatch(config.Host) || config.Port is null or < 1 or > 65535)) throw new InvalidDataException("Enabled proxy configuration is invalid");
        if (config.Bypass.Length > 256 || config.Bypass.Any(x => x.Length > 253 || !Bypass.IsMatch(x))) throw new InvalidDataException("Proxy bypass configuration is invalid");
    }

    public async Task<ProxyRuntimeStatus> ReconcileAsync(ProxyConfiguration desired, ProxyRuntimeStatus? previous, CancellationToken ct)
    {
        var sync = DateTimeOffset.UtcNow;
        try
        {
            Validate(desired);
            var baseline = await LoadOrCaptureBaselineAsync(ct);
            var proxy=$"{desired.Host}:{desired.Port}";
            var browserPolicy=JsonSerializer.Serialize(new Dictionary<string,string>{{"ProxyMode","fixed_servers"},{"ProxyServer",proxy},{"ProxyBypassList",string.Join(',',desired.Bypass)}});
            var semicolonBypass = string.Join(';', desired.Bypass);
            var expected = desired.Enabled
                ? new ProxySnapshot(
                    true,
                    proxy,
                    semicolonBypass,
                    1,
                    proxy,
                    semicolonBypass,
                    0,
                    true,
                    browserPolicy,
                    true,
                    browserPolicy,
                    true,
                    "manual",
                    1,
                    proxy,
                    1,
                    proxy,
                    string.Join(',', desired.Bypass))
                : baseline;
            var actual = store.Read();
            var drift = !Equivalent(actual, expected);
            var versionChanged = previous?.AppliedVersion != desired.Version;
            var requiresWrite = drift || (versionChanged && desired.Enabled);
            if (requiresWrite)
            {
                store.Write(expected);
                actual = store.Read();
                if (!Equivalent(actual, expected)) throw new IOException("Managed proxy state did not match after apply");
                logger.LogInformation(desired.Enabled ? "Proxy configuration version {Version} applied" : "Proxy baseline restored for configuration version {Version}", desired.Version);
            }
            else logger.LogDebug("Proxy configuration version {Version} unchanged", desired.Version);
            return new(desired.Version, desired.Version, desired.Enabled ? "configured" : "disabled", drift, requiresWrite ? "applied" : "no-change", null, desired.Enabled ? desired.Host : null, desired.Enabled ? desired.Port : null, $"{desired.Bypass.Length} entries", sync);
        }
        catch (Exception ex) when (ex is InvalidDataException or IOException or Win32Exception or PlatformNotSupportedException)
        {
            logger.LogError("Proxy configuration version {Version} failed: {ErrorType}", desired.Version, ex.GetType().Name);
            return new(desired.Version, previous?.AppliedVersion, "error", previous?.DriftDetected ?? false, "failed", ex.Message, previous?.EffectiveHost, previous?.EffectivePort, previous?.BypassSummary, sync);
        }
    }

    private async Task<ProxySnapshot> LoadOrCaptureBaselineAsync(CancellationToken ct)
    {
        if (File.Exists(paths.ProxyBaselinePath))
        {
            var savedBaseline=JsonSerializer.Deserialize<ProxySnapshot>(await File.ReadAllTextAsync(paths.ProxyBaselinePath,ct),Json) ?? throw new InvalidDataException("Proxy baseline is invalid");
            if (!savedBaseline.EdgePolicyPresent.HasValue || !savedBaseline.ChromePolicyPresent.HasValue || !savedBaseline.FirefoxPolicyPresent.HasValue)
            {
                var current=store.Read();
                savedBaseline=savedBaseline with
                {
                    EdgePolicyPresent=current.EdgePolicyPresent,
                    EdgeProxySettings=current.EdgeProxySettings,
                    ChromePolicyPresent=current.ChromePolicyPresent,
                    ChromeProxySettings=current.ChromeProxySettings,
                    FirefoxPolicyPresent=current.FirefoxPolicyPresent,
                    FirefoxMode=current.FirefoxMode,
                    FirefoxLocked=current.FirefoxLocked,
                    FirefoxHttpProxy=current.FirefoxHttpProxy,
                    FirefoxUseHttpProxyForAllProtocols=current.FirefoxUseHttpProxyForAllProtocols,
                    FirefoxSslProxy=current.FirefoxSslProxy,
                    FirefoxPassthrough=current.FirefoxPassthrough
                };
                await File.WriteAllTextAsync(paths.ProxyBaselinePath,JsonSerializer.Serialize(savedBaseline,Json),ct);
            }
            return savedBaseline;
        }
        var baseline = store.Read();
        var temporary = paths.ProxyBaselinePath + ".tmp";
        await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(baseline, Json), ct);
        try { File.Move(temporary, paths.ProxyBaselinePath, false); }
        catch (IOException) { File.Delete(temporary); }
        logger.LogInformation("Original WinHTTP proxy baseline captured");
        return baseline;
    }

    private static bool Equivalent(ProxySnapshot left, ProxySnapshot right) =>
        left.Enabled == right.Enabled &&
        string.Equals(left.Proxy ?? "", right.Proxy ?? "", StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.Bypass ?? "", right.Bypass ?? "", StringComparison.OrdinalIgnoreCase) &&
        left.BrowserProxyEnable == right.BrowserProxyEnable &&
        string.Equals(left.BrowserProxy ?? "", right.BrowserProxy ?? "", StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.BrowserBypass ?? "", right.BrowserBypass ?? "", StringComparison.OrdinalIgnoreCase) &&
        left.ProxySettingsPerUser == right.ProxySettingsPerUser &&
        left.EdgePolicyPresent == right.EdgePolicyPresent &&
        string.Equals(left.EdgeProxySettings ?? "",right.EdgeProxySettings ?? "",StringComparison.Ordinal) &&
        left.ChromePolicyPresent == right.ChromePolicyPresent &&
        string.Equals(left.ChromeProxySettings ?? "",right.ChromeProxySettings ?? "",StringComparison.Ordinal) &&
        left.FirefoxPolicyPresent == right.FirefoxPolicyPresent &&
        string.Equals(left.FirefoxMode ?? "", right.FirefoxMode ?? "", StringComparison.OrdinalIgnoreCase) &&
        left.FirefoxLocked == right.FirefoxLocked &&
        string.Equals(left.FirefoxHttpProxy ?? "", right.FirefoxHttpProxy ?? "", StringComparison.OrdinalIgnoreCase) &&
        left.FirefoxUseHttpProxyForAllProtocols == right.FirefoxUseHttpProxyForAllProtocols &&
        string.Equals(left.FirefoxSslProxy ?? "", right.FirefoxSslProxy ?? "", StringComparison.OrdinalIgnoreCase) &&
        string.Equals(left.FirefoxPassthrough ?? "", right.FirefoxPassthrough ?? "", StringComparison.OrdinalIgnoreCase);

    public static async Task RestoreBaselineAsync(IWindowsProxyStore store, AgentPaths paths, CancellationToken ct)
    {
        if (!File.Exists(paths.ProxyBaselinePath)) return;
        var baseline=JsonSerializer.Deserialize<ProxySnapshot>(await File.ReadAllTextAsync(paths.ProxyBaselinePath,ct),Json) ?? throw new InvalidDataException("Proxy baseline is invalid");
        store.Write(baseline);
    }
}
