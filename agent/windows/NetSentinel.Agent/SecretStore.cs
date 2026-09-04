using System.Security.Cryptography;
using System.Text;

namespace NetSentinel.Agent;

public interface ISecretStore
{
    Task SaveCredentialAsync(string value, CancellationToken cancellationToken);
    Task<string?> LoadCredentialAsync(CancellationToken cancellationToken);
    Task SaveBootstrapTokenAsync(string value, CancellationToken cancellationToken);
    Task<string?> LoadBootstrapTokenAsync(CancellationToken cancellationToken);
    Task DeleteBootstrapTokenAsync(CancellationToken cancellationToken);
    Task DeleteAllAsync(CancellationToken cancellationToken);
}

public sealed class DpapiSecretStore(AgentPaths paths) : ISecretStore
{
    private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("NetSentinel.Agent.v1");

    public Task SaveCredentialAsync(string value, CancellationToken ct) => SaveAsync(paths.CredentialPath, value, ct);
    public Task<string?> LoadCredentialAsync(CancellationToken ct) => LoadAsync(paths.CredentialPath, ct);
    public Task SaveBootstrapTokenAsync(string value, CancellationToken ct) => SaveAsync(paths.BootstrapTokenPath, value, ct);

    public Task<string?> LoadBootstrapTokenAsync(CancellationToken ct) => LoadAsync(paths.BootstrapTokenPath, ct);
    public Task DeleteBootstrapTokenAsync(CancellationToken ct) { if (File.Exists(paths.BootstrapTokenPath)) File.Delete(paths.BootstrapTokenPath); return Task.CompletedTask; }

    public Task DeleteAllAsync(CancellationToken ct)
    {
        foreach (var path in new[] { paths.CredentialPath, paths.BootstrapTokenPath })
            if (File.Exists(path)) File.Delete(path);
        return Task.CompletedTask;
    }

    private static async Task SaveAsync(string path, string value, CancellationToken ct)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("DPAPI requires Windows");
        var protectedBytes = ProtectedData.Protect(Encoding.UTF8.GetBytes(value), Entropy, DataProtectionScope.LocalMachine);
        var temporary = path + ".tmp";
        await File.WriteAllBytesAsync(temporary, protectedBytes, ct);
        File.Move(temporary, path, true);
    }

    private static async Task<string?> LoadAsync(string path, CancellationToken ct)
    {
        if (!File.Exists(path)) return null;
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("DPAPI requires Windows");
        var protectedBytes = await File.ReadAllBytesAsync(path, ct);
        try { return Encoding.UTF8.GetString(ProtectedData.Unprotect(protectedBytes, Entropy, DataProtectionScope.LocalMachine)); }
        catch (CryptographicException) { return null; }
    }
}
