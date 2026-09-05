using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Serilog;

namespace NetSentinel.Agent;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        var paths = new AgentPaths();
        if (args.FirstOrDefault()?.Equals("status", StringComparison.OrdinalIgnoreCase) == true)
        {
            var state = await new StateStore(paths).LoadAsync(CancellationToken.None);
            Console.WriteLine(JsonSerializer.Serialize(new { service = "Query SCM with Get-Service NetSentinelAgent", state.Enrollment, state.DeviceId, state.Server, state.LastHeartbeat, state.LastSuccess, state.ConsecutiveFailures, state.AgentVersion, ProxyManagementEnabled = state.Proxy?.CurrentState == "configured", Proxy = state.Proxy }, new JsonSerializerOptions { WriteIndented = true }));
            return 0;
        }
        if (args.FirstOrDefault()?.Equals("restore-proxy", StringComparison.OrdinalIgnoreCase) == true)
        {
            await ProxyConfigurationManager.RestoreBaselineAsync(new WinHttpProxyStore(), paths, CancellationToken.None);
            Console.WriteLine("Original WinHTTP proxy baseline restored.");
            return 0;
        }
        if (args.FirstOrDefault()?.Equals("configure", StringComparison.OrdinalIgnoreCase) == true)
            return await Configure(args.Skip(1).ToArray(), paths);

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
            builder.Services.AddHostedService<AgentWorker>();
            builder.Services.AddSerilog();
            await builder.Build().RunAsync();
            return 0;
        }
        catch (Exception ex) { Log.Fatal(ex, "Agent terminated unexpectedly"); return 1; }
        finally { await Log.CloseAndFlushAsync(); }
    }

    private static async Task<int> Configure(string[] args, AgentPaths paths)
    {
        var serverIndex = Array.IndexOf(args, "--server");
        var server = serverIndex >= 0 && serverIndex + 1 < args.Length ? args[serverIndex + 1] : null;
        var allowHttp = args.Contains("--allow-http");
        var token = args.Contains("--enrollment-token-stdin") ? await Console.In.ReadLineAsync() : null;
        if (!Uri.TryCreate(server, UriKind.Absolute, out var uri) || uri.Scheme is not ("https" or "http") || (uri.Scheme == "http" && !allowHttp) || string.IsNullOrWhiteSpace(token)) { Console.Error.WriteLine("configure requires --server HTTPS_URL --enrollment-token-stdin; use --allow-http only for controlled LAN tests"); return 2; }
        await File.WriteAllTextAsync(paths.ConfigurationPath, JsonSerializer.Serialize(new { Agent = new { ServerUrl = server, AllowHttp = allowHttp } }, new JsonSerializerOptions { WriteIndented = true }));
        await new DpapiSecretStore(paths).SaveBootstrapTokenAsync(token, CancellationToken.None);
        Console.WriteLine("Configuration saved; enrollment token is DPAPI-protected.");
        return 0;
    }
}
