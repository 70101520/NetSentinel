using System.Net;
using System.Text;
using NetSentinel.Agent;
using Xunit;

namespace NetSentinel.Agent.Tests;

public sealed class AgentTests : IDisposable
{
    private readonly string root = Path.Combine(Path.GetTempPath(), "netsentinel-agent-tests-" + Guid.NewGuid());
    public void Dispose() { if (Directory.Exists(root)) Directory.Delete(root, true); }

    [Fact]
    public async Task Installation_identity_survives_state_reload()
    {
        var store = new StateStore(new AgentPaths(root));
        var first = await store.LoadAsync(default);
        await store.SaveAsync(first, default);
        var second = await store.LoadAsync(default);
        Assert.Equal(first.InstallationId, second.InstallationId);
    }

    [Fact]
    public async Task Stored_device_identity_survives_restart()
    {
        var store = new StateStore(new AgentPaths(root));
        var expected = new LocalState(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), Enrollment: "Enrolled");
        await store.SaveAsync(expected, default);
        Assert.Equal(expected, await store.LoadAsync(default));
    }

    [Fact]
    public async Task Corrupt_configuration_state_fails_closed()
    {
        var paths = new AgentPaths(root);
        await File.WriteAllTextAsync(paths.StatePath, "{not-json");
        await Assert.ThrowsAsync<InvalidDataException>(() => new StateStore(paths).LoadAsync(default));
    }

    [Fact]
    public async Task Dpapi_machine_store_never_writes_plaintext_secret()
    {
        var paths = new AgentPaths(root);
        var store = new DpapiSecretStore(paths);
        const string secret = "credential-value-that-must-not-be-plaintext";
        await store.SaveCredentialAsync(secret, default);
        Assert.Equal(secret, await store.LoadCredentialAsync(default));
        Assert.DoesNotContain(secret, Encoding.UTF8.GetString(await File.ReadAllBytesAsync(paths.CredentialPath)));
    }

    [Fact]
    public async Task Bootstrap_token_is_deleted_only_after_explicit_success_cleanup()
    {
        var paths = new AgentPaths(root);
        var store = new DpapiSecretStore(paths);
        await store.SaveBootstrapTokenAsync("one-time-token", default);
        Assert.Equal("one-time-token", await store.LoadBootstrapTokenAsync(default));
        Assert.True(File.Exists(paths.BootstrapTokenPath));
        await store.DeleteBootstrapTokenAsync(default);
        Assert.False(File.Exists(paths.BootstrapTokenPath));
    }

    [Theory]
    [InlineData(200, HeartbeatResult.Success)]
    [InlineData(401, HeartbeatResult.CredentialRejected)]
    [InlineData(403, HeartbeatResult.CredentialRejected)]
    [InlineData(503, HeartbeatResult.TransientFailure)]
    public async Task Heartbeat_classifies_server_response(int status, HeartbeatResult expected)
    {
        var client = new ManagementClient(new HttpClient(new StubHandler((HttpStatusCode)status)) { BaseAddress = new Uri("https://server/") });
        var body = new HeartbeatRequest(Guid.NewGuid(), DateTimeOffset.UtcNow, "PC", null, "0.1.0", "Windows", "11", [], [], null, [], DateTimeOffset.UtcNow, 1);
        Assert.Equal(expected, await client.HeartbeatAsync(body, "secret", default));
    }

    [Fact]
    public async Task Dns_or_network_failure_is_transient()
    {
        var client = new ManagementClient(new HttpClient(new StubHandler()) { BaseAddress = new Uri("https://unavailable/") });
        var body = new HeartbeatRequest(Guid.NewGuid(), DateTimeOffset.UtcNow, "PC", null, "0.1.0", "Windows", "11", [], [], null, [], DateTimeOffset.UtcNow, 1);
        Assert.Equal(HeartbeatResult.TransientFailure, await client.HeartbeatAsync(body, "secret", default));
    }

    private sealed class StubHandler(HttpStatusCode? status = null) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => status is null ? Task.FromException<HttpResponseMessage>(new HttpRequestException("offline")) : Task.FromResult(new HttpResponseMessage(status.Value) { Content = new StringContent("{}", Encoding.UTF8, "application/json") });
    }
}
