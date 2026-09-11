using System.Text.Json;
using System.Security.Principal;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Serilog;

namespace NetSentinel.Agent;

public static class Program
{
    [STAThread]
    public static async Task<int> Main(string[] args)
    {
        if (args.FirstOrDefault()?.Equals("maintenance-service", StringComparison.OrdinalIgnoreCase) == true)
            return await RunMaintenanceServiceAsync();
        if (args.FirstOrDefault()?.Equals("authorize-uninstall", StringComparison.OrdinalIgnoreCase) == true)
            return await AuthorizeUninstallAsync();
        if (args.FirstOrDefault()?.Equals("consume-uninstall-authorization", StringComparison.OrdinalIgnoreCase) == true)
            return await UninstallAuthorization.ConsumeAsync(new AgentPaths(),CancellationToken.None)?0:4;
        if (args.FirstOrDefault()?.Equals("gui", StringComparison.OrdinalIgnoreCase) == true)
            return RunControlPanel();
        var statusCommand = args.FirstOrDefault()?.Equals("status", StringComparison.OrdinalIgnoreCase) == true;
        var paths = new AgentPaths(ensureDirectories: !statusCommand);
        if (statusCommand)
        {
            try
            {
                await using (var probe = new FileStream(paths.StatePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete)) { }
                var state = await new StateStore(paths).LoadAsync(CancellationToken.None);
                Console.WriteLine(JsonSerializer.Serialize(new { service = "Query SCM with Get-Service NetSentinelAgent", state.Enrollment, state.DeviceId, state.PairingCode, state.Server, state.LastHeartbeat, state.LastSuccess, state.ConsecutiveFailures, state.AgentVersion, ProxyManagementEnabled = state.Proxy?.CurrentState == "configured", Proxy = state.Proxy }, new JsonSerializerOptions { WriteIndented = true }));
                return 0;
            }
            catch (UnauthorizedAccessException)
            {
                Console.Error.WriteLine("Detailed Agent status is protected. Run this command as an administrator.");
                return 3;
            }
            catch (FileNotFoundException)
            {
                Console.Error.WriteLine("Agent state is not initialized. Install or configure the Agent first.");
                return 2;
            }
        }
        if (args.FirstOrDefault()?.Equals("restore-proxy", StringComparison.OrdinalIgnoreCase) == true)
        {
            await ProxyConfigurationManager.RestoreBaselineAsync(new WinHttpProxyStore(), paths, CancellationToken.None);
            Console.WriteLine("Original WinHTTP proxy baseline restored.");
            return 0;
        }
        if (args.FirstOrDefault()?.Equals("configure", StringComparison.OrdinalIgnoreCase) == true)
            return await ConfigureAsync(args.Skip(1).ToArray(), paths);

        Log.Logger = new LoggerConfiguration().MinimumLevel.Information().WriteTo.File(Path.Combine(paths.LogDirectory, "agent-.log"), rollingInterval: RollingInterval.Day, retainedFileCountLimit: 14, fileSizeLimitBytes: 10 * 1024 * 1024, rollOnFileSizeLimit: true).CreateLogger();
        try
        {
            var builder = Host.CreateApplicationBuilder(args);
            builder.Configuration.AddJsonFile(paths.ConfigurationPath, optional: true, reloadOnChange: false);
            builder.Services.AddWindowsService(value => value.ServiceName = "NetSentinel Agent");
            builder.Services.Configure<AgentOptions>(builder.Configuration.GetSection(AgentOptions.Section));
            builder.Services.AddSingleton(paths);
            builder.Services.AddSingleton<StateStore>();
            builder.Services.AddSingleton<ISecretStore, DpapiSecretStore>();
            builder.Services.AddSingleton<ISystemSnapshot, WindowsSystemSnapshot>();
            builder.Services.AddHttpClient<ManagementClient>((services, http) =>
            {
                var settings = services.GetRequiredService<IOptions<AgentOptions>>().Value;
                if (!Uri.TryCreate(settings.ServerUrl.TrimEnd('/') + "/", UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http") || (uri.Scheme == "http" && !settings.AllowHttp)) throw new InvalidOperationException("Agent:ServerUrl must use HTTPS unless AllowHttp is explicitly enabled for controlled testing");
                http.BaseAddress = uri;
                http.Timeout = TimeSpan.FromSeconds(settings.RequestTimeoutSeconds);
            }).ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler { UseProxy = false });
            builder.Services.AddSingleton<IWindowsProxyStore, WinHttpProxyStore>();
            builder.Services.AddSingleton<ProxyConfigurationManager>();
            builder.Services.AddSingleton<MaintenanceSettingsStore>();
            builder.Services.AddHostedService<AgentWorker>();
            builder.Services.AddSerilog();
            await builder.Build().RunAsync();
            return 0;
        }
        catch (Exception ex) { Log.Fatal(ex, "Agent terminated unexpectedly"); return 1; }
        finally { await Log.CloseAndFlushAsync(); }
    }

    internal static async Task<int> ConfigureAsync(string[] args, AgentPaths paths)
    {
        var serverIndex = Array.IndexOf(args, "--server");
        var server = serverIndex >= 0 && serverIndex + 1 < args.Length ? args[serverIndex + 1].Trim() : null;
        var allowHttp = args.Contains("--allow-http");
        var token = args.Contains("--enrollment-token-stdin") ? await Console.In.ReadLineAsync() : null;
        var portalApproval = args.Contains("--portal-approval");
        var modeIndex = Array.IndexOf(args, "--control-mode");
        var requestedControlMode = modeIndex >= 0 && modeIndex + 1 < args.Length ? args[modeIndex + 1].Trim().ToUpperInvariant() : "MONITOR_ONLY";
        if (!Uri.TryCreate(server, UriKind.Absolute, out var uri) || !IsValidManagementServer(uri, allowHttp) || (!portalApproval && string.IsNullOrWhiteSpace(token)) || requestedControlMode is not ("MONITOR_ONLY" or "WEB_CONTROLLED")) { Console.Error.WriteLine("configure requires --server HTTPS_URL and either --portal-approval or --enrollment-token-stdin; use --allow-http only for controlled LAN tests"); return 2; }
        var previousServer = ReadConfiguredServer(paths.ConfigurationPath);
        if (previousServer is not null && !SameManagementAuthority(previousServer, uri))
            await ResetForManagementServerChangeAsync(paths);
        var configuration = JsonSerializer.Serialize(new { Agent = new { ServerUrl = uri.ToString().TrimEnd('/'), AllowHttp = allowHttp, RequestedControlMode = requestedControlMode } }, new JsonSerializerOptions { WriteIndented = true });
        var temporaryConfiguration = paths.ConfigurationPath + ".tmp";
        await File.WriteAllTextAsync(temporaryConfiguration, configuration);
        File.Move(temporaryConfiguration, paths.ConfigurationPath, true);
        var secretStore = new DpapiSecretStore(paths);
        if (!string.IsNullOrWhiteSpace(token)) await secretStore.SaveBootstrapTokenAsync(token, CancellationToken.None);
        if (portalApproval)
        {
            var stateStore = new StateStore(paths);
            var state = await stateStore.LoadAsync(CancellationToken.None);
            if (state.DeviceId is null && state.Enrollment == "PairingRejected")
            {
                await secretStore.DeletePairingSecretAsync(CancellationToken.None);
                await stateStore.SaveAsync(state with { PairingRequestId = null, PairingCode = null, Enrollment = "NotEnrolled" }, CancellationToken.None);
            }
        }
        Console.WriteLine(portalApproval ? "Configuration saved; portal approval pairing will start with the service." : "Configuration saved; enrollment token is DPAPI-protected.");
        return 0;
    }

    internal static Uri? ReadConfiguredServer(string configurationPath)
    {
        if (!File.Exists(configurationPath)) return null;
        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(configurationPath));
            var value = document.RootElement.GetProperty("Agent").GetProperty("ServerUrl").GetString();
            return Uri.TryCreate(value, UriKind.Absolute, out var uri) ? uri : null;
        }
        catch (Exception ex) when (ex is IOException or JsonException or KeyNotFoundException)
        {
            return null;
        }
    }

    internal static bool IsValidManagementServer(Uri uri, bool allowHttp) =>
        uri.Scheme is "https" or "http" &&
        (uri.Scheme != "http" || allowHttp) &&
        string.IsNullOrEmpty(uri.UserInfo) &&
        string.IsNullOrEmpty(uri.Query) &&
        string.IsNullOrEmpty(uri.Fragment);

    internal static bool SameManagementAuthority(Uri left, Uri right) =>
        left.Scheme.Equals(right.Scheme, StringComparison.OrdinalIgnoreCase) &&
        left.IdnHost.Equals(right.IdnHost, StringComparison.OrdinalIgnoreCase) &&
        left.Port == right.Port &&
        left.AbsolutePath.TrimEnd('/').Equals(right.AbsolutePath.TrimEnd('/'), StringComparison.Ordinal);

    private static async Task ResetForManagementServerChangeAsync(AgentPaths paths)
    {
        await ProxyConfigurationManager.RestoreBaselineAsync(new WinHttpProxyStore(), paths, CancellationToken.None);
        if (File.Exists(paths.StatePath)) File.Copy(paths.StatePath, paths.PreviousStatePath, true);
        await new DpapiSecretStore(paths).DeleteAllAsync(CancellationToken.None);
        if (File.Exists(paths.StatePath)) File.Delete(paths.StatePath);
        if (File.Exists(paths.ProxyBaselinePath)) File.Delete(paths.ProxyBaselinePath);
        await new StateStore(paths).SaveAsync(new LocalState(Guid.NewGuid(), Enrollment: "NotEnrolled", AgentVersion: AgentVersion.Current), CancellationToken.None);
        Console.WriteLine("Management server changed; old enrollment was archived and a fresh portal pairing will start.");
    }

    private static int RunControlPanel()
    {
        if (!OperatingSystem.IsWindows()) return 2;
        var identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
        {
            try
            {
                var executable = Environment.ProcessPath ?? throw new InvalidOperationException("Agent executable path is unavailable");
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(executable, "gui") { UseShellExecute = true, Verb = "runas" });
                return 0;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Administrator approval is required: {ex.Message}");
                return 3;
            }
        }
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new AgentControlForm(new AgentPaths()));
        return 0;
    }

    private static async Task<int> RunMaintenanceServiceAsync()
    {
        Log.Logger=new LoggerConfiguration().MinimumLevel.Information().WriteTo.File(Path.Combine(new AgentPaths().LogDirectory,"maintenance-.log"),rollingInterval:RollingInterval.Day,retainedFileCountLimit:14).CreateLogger();
        try
        {
            // SCM owns this process mode; the selector is not an application
            // configuration argument and must not reach the generic host parser.
            var builder=Host.CreateApplicationBuilder(Array.Empty<string>());builder.Services.AddWindowsService(value=>value.ServiceName="NetSentinel Maintenance");
            builder.Services.AddSingleton<AgentPaths>();builder.Services.AddSingleton<StateStore>();builder.Services.AddSingleton<ISecretStore,DpapiSecretStore>();builder.Services.AddHostedService<MaintenanceWorker>();builder.Services.AddSerilog();
            await builder.Build().RunAsync();return 0;
        }
        catch(Exception ex){Log.Fatal(ex,"Maintenance broker terminated unexpectedly");return 1;}
        finally{await Log.CloseAndFlushAsync();}
    }

    private static async Task<int> AuthorizeUninstallAsync()
    {
        if(!OperatingSystem.IsWindows())return 2;
        var identity=WindowsIdentity.GetCurrent();if(!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))return 3;
        Application.EnableVisualStyles();Application.SetCompatibleTextRenderingDefault(false);
        using var dialog=new UninstallAuthorizationForm();
        if(dialog.ShowDialog()!=DialogResult.OK)return 4;
        if(await UninstallAuthorization.CreateAsync(dialog.SuppliedSecret,new AgentPaths(),CancellationToken.None))return 0;
        MessageBox.Show("Password or recovery code is invalid, or maintenance policy has not synchronized yet.","Uninstall denied",MessageBoxButtons.OK,MessageBoxIcon.Error);return 4;
    }
}
