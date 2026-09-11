using System.Text.Json;

namespace NetSentinel.Agent;

public sealed class AgentPaths
{
    public AgentPaths(string? root = null, bool ensureDirectories = true)
    {
        Root = root ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "NetSentinel", "Agent");
        if (ensureDirectories)
        {
            Directory.CreateDirectory(Root);
            Directory.CreateDirectory(LogDirectory);
        }
    }
    public string Root { get; }
    public string LogDirectory => Path.Combine(Root, "Logs");
    public string ConfigurationPath => Path.Combine(Root, "agent.json");
    public string StatePath => Path.Combine(Root, "state.json");
    public string CredentialPath => Path.Combine(Root, "credential.dpapi");
    public string BootstrapTokenPath => Path.Combine(Root, "bootstrap.dpapi");
    public string PairingSecretPath => Path.Combine(Root, "pairing.dpapi");
    public string ProxyBaselinePath => Path.Combine(Root, "proxy-baseline.json");
    public string PreviousStatePath => Path.Combine(Root, "state.previous-server.json");
    public string MaintenanceConfigurationPath => Path.Combine(Root, "maintenance.json");
    public string MaintenanceRequestPath => Path.Combine(Root, "maintenance-request.json");
    public string MaintenanceScriptPath => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "NetSentinel", "Agent", "maintenance-uninstall.ps1");
    public string UninstallAuthorizationPath => Path.Combine(Root, "uninstall-authorization.json");
}

public sealed class StateStore(AgentPaths paths)
{
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    public async Task<LocalState> LoadAsync(CancellationToken ct)
    {
        if (!File.Exists(paths.StatePath)) return new LocalState(Guid.NewGuid());
        try { return JsonSerializer.Deserialize<LocalState>(await File.ReadAllTextAsync(paths.StatePath, ct), Json) ?? throw new JsonException(); }
        catch (JsonException ex) { throw new InvalidDataException("Local agent state is corrupt", ex); }
    }
    public async Task SaveAsync(LocalState state, CancellationToken ct)
    {
        var temporary = paths.StatePath + ".tmp";
        await File.WriteAllTextAsync(temporary, JsonSerializer.Serialize(state, Json), ct);
        File.Move(temporary, paths.StatePath, true);
    }
}
