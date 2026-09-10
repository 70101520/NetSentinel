using System.Net;
using System.Text;
using NetSentinel.Agent;
using Microsoft.Extensions.Logging.Abstractions;
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

    [Fact]
    public async Task Pairing_secret_is_dpapi_protected_and_removed_after_claim()
    {
        var paths = new AgentPaths(root);
        var store = new DpapiSecretStore(paths);
        const string secret = "pairing-secret-that-must-never-be-plaintext";
        await store.SavePairingSecretAsync(secret, default);
        Assert.Equal(secret, await store.LoadPairingSecretAsync(default));
        Assert.DoesNotContain(secret, Encoding.UTF8.GetString(await File.ReadAllBytesAsync(paths.PairingSecretPath)));
        await store.DeletePairingSecretAsync(default);
        Assert.False(File.Exists(paths.PairingSecretPath));
    }

    [Fact]
    public async Task Portal_pairing_registration_and_claim_are_parsed()
    {
        var requestId = Guid.NewGuid();
        var deviceId = Guid.NewGuid();
        var registrationJson = $"{{\"id\":\"{requestId}\",\"pairing_code\":\"ABCD-1234\",\"status\":\"pending\",\"expires_at\":\"2030-01-01T00:00:00Z\"}}";
        var registrationClient = new ManagementClient(new HttpClient(new JsonHandler(registrationJson)) { BaseAddress = new Uri("https://server/") });
        var registration = await registrationClient.RequestPairingAsync(new PairingRequest("secret-value-long-enough", Guid.NewGuid().ToString(), "PC", "Windows", "11", "x64", AgentVersion.Current, "MONITOR_ONLY", "10.0.0.2"), default);
        Assert.NotNull(registration);
        Assert.Equal("ABCD-1234", registration.PairingCode);

        var claimJson = $"{{\"status\":\"approved\",\"device_id\":\"{deviceId}\",\"agent_identity\":\"{requestId}\",\"credential\":\"credential\",\"server\":{{\"heartbeat_interval_seconds\":30}}}}";
        var claimClient = new ManagementClient(new HttpClient(new JsonHandler(claimJson)) { BaseAddress = new Uri("https://server/") });
        var claim = await claimClient.ClaimPairingAsync(requestId, "secret-value-long-enough", default);
        Assert.NotNull(claim);
        Assert.Equal(deviceId, claim.DeviceId);
        Assert.Equal("credential", claim.Credential);
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

    [Fact]
    public async Task Graceful_stop_reports_offline_with_agent_credential()
    {
        var client = new ManagementClient(new HttpClient(new StubHandler(HttpStatusCode.OK)) { BaseAddress = new Uri("https://server/") });
        Assert.True(await client.ReportOfflineAsync("device.secret", default));
        var offline = new ManagementClient(new HttpClient(new StubHandler()) { BaseAddress = new Uri("https://server/") });
        Assert.False(await offline.ReportOfflineAsync("device.secret", default));
    }

    [Fact]
    public async Task System_snapshot_reports_bounded_resource_metrics()
    {
        var collector=new WindowsSystemSnapshot();
        _=collector.Capture(Guid.NewGuid());
        await Task.Delay(100);
        var snapshot=collector.Capture(Guid.NewGuid());
        Assert.NotNull(snapshot.SystemMetrics);
        Assert.InRange(snapshot.SystemMetrics.MemoryPercent!.Value,0,100);
        Assert.InRange(snapshot.SystemMetrics.DiskPercent!.Value,0,100);
        Assert.NotNull(snapshot.SystemMetrics.NetworkAdapter);
        Assert.InRange(snapshot.SystemMetrics.SampleWindowSeconds!.Value,0.05,1);
        Assert.True(snapshot.SystemMetrics.NetworkReceiveBps!.Value>=0);
        Assert.True(snapshot.SystemMetrics.NetworkSendBps!.Value>=0);
    }

    [Fact]
    public async Task Proxy_config_parses_and_server_unavailable_preserves_local_state()
    {
        var json="{\"proxy\":{\"enabled\":true,\"host\":\"proxy.test\",\"port\":3128,\"bypass\":[\"localhost\"],\"mode\":\"configured\",\"version\":2}}";
        var client=new ManagementClient(new HttpClient(new JsonHandler(json)){BaseAddress=new Uri("https://server/")});
        var config=await client.GetConfigurationAsync("credential",default);
        Assert.NotNull(config);Assert.Equal(2,config.Version);Assert.Equal("proxy.test",config.Host);
        var offline=new ManagementClient(new HttpClient(new StubHandler()){BaseAddress=new Uri("https://server/")});
        Assert.Null(await offline.GetConfigurationAsync("credential",default));
    }

    [Fact]
    public async Task Full_control_defaults_to_management_host_gateway()
    {
        var json="{\"control_mode\":\"WEB_CONTROLLED\",\"proxy\":{\"enabled\":false,\"host\":null,\"port\":null,\"bypass\":[],\"mode\":\"disabled\",\"version\":3}}";
        var client=new ManagementClient(new HttpClient(new JsonHandler(json)){BaseAddress=new Uri("https://192.168.32.10:8080/")});
        var config=await client.GetConfigurationAsync("credential",default);
        Assert.NotNull(config);Assert.True(config.Enabled);Assert.Equal("192.168.32.10",config.Host);Assert.Equal(3128,config.Port);
    }
    [Fact]
    public async Task Proxy_baseline_is_captured_once_apply_is_versioned_and_disable_restores()
    {
        var paths=new AgentPaths(root);var baseline=new ProxySnapshot(false,null,null);var store=new FakeProxyStore(baseline);
        var manager=new ProxyConfigurationManager(store,paths,NullLogger<ProxyConfigurationManager>.Instance);
        var desired=new ProxyConfiguration(true,"proxy.test",3128,["localhost","*.internal"],"configured",1);
        var applied=await manager.ReconcileAsync(desired,null,default);
        Assert.Equal(1,store.Writes);Assert.Equal(1,applied.AppliedVersion);Assert.True(File.Exists(paths.ProxyBaselinePath));
        var unchanged=await manager.ReconcileAsync(desired,applied,default);
        Assert.Equal(1,store.Writes);Assert.Equal("no-change",unchanged.LastApplyResult);
        var disabled=await manager.ReconcileAsync(new(false,null,null,[],"disabled",2),unchanged,default);
        Assert.Equal(2,store.Writes);Assert.False(store.Value.Enabled);Assert.Equal(2,disabled.AppliedVersion);
        store.Value=new(true,"manual:9999",null);
        var drift=await manager.ReconcileAsync(new(true,"proxy.test",8080,["<local>"],"configured",3),disabled,default);
        Assert.True(drift.DriftDetected);Assert.Equal("proxy.test:8080",store.Value.Proxy);
        Assert.Equal(baseline, System.Text.Json.JsonSerializer.Deserialize<ProxySnapshot>(await File.ReadAllTextAsync(paths.ProxyBaselinePath),new System.Text.Json.JsonSerializerOptions(System.Text.Json.JsonSerializerDefaults.Web)));
    }

    [Fact]
    public async Task Initially_disabled_matching_baseline_does_not_require_a_privileged_write()
    {
        var paths=new AgentPaths(root);var store=new FakeProxyStore(new(false,null,null));
        var manager=new ProxyConfigurationManager(store,paths,NullLogger<ProxyConfigurationManager>.Instance);
        var result=await manager.ReconcileAsync(new(false,null,null,[],"disabled",1),null,default);
        Assert.Equal(0,store.Writes);Assert.Equal(1,result.AppliedVersion);Assert.Equal("no-change",result.LastApplyResult);
    }

    [Theory]
    [InlineData("",3128,"configured")]
    [InlineData("bad host;command",3128,"configured")]
    [InlineData("proxy.test",0,"configured")]
    [InlineData("proxy.test",3128,"enforced")]
    public void Invalid_proxy_configuration_is_rejected(string host,int port,string mode)
    {
        Assert.Throws<InvalidDataException>(()=>ProxyConfigurationManager.Validate(new(true,host,port,[],mode,1)));
    }

    [Fact]
    public void Bypass_serialization_is_safe_and_malformed_input_is_rejected()
    {
        ProxyConfigurationManager.Validate(new(true,"proxy.test",3128,["localhost","127.0.0.1","*.internal","<local>"],"configured",1));
        Assert.Throws<InvalidDataException>(()=>ProxyConfigurationManager.Validate(new(true,"proxy.test",3128,["localhost;netsh"],"configured",1)));
    }

    [Fact]
    public async Task Apply_failure_is_reported_without_losing_previous_version()
    {
        var paths=new AgentPaths(root);var manager=new ProxyConfigurationManager(new FailingProxyStore(),paths,NullLogger<ProxyConfigurationManager>.Instance);
        var result=await manager.ReconcileAsync(new(true,"proxy.test",3128,[],"configured",2),new(AppliedVersion:1),default);
        Assert.Equal("failed",result.LastApplyResult);Assert.Equal(1,result.AppliedVersion);Assert.DoesNotContain("credential",result.LastError??"",StringComparison.OrdinalIgnoreCase);
    }


    [Fact]
    public void Pairing_request_serializes_installer_requested_mode()
    {
        var request=new PairingRequest("secret-value-long-enough",Guid.NewGuid().ToString(),"PC","Windows","11","x64",AgentVersion.Current,"WEB_CONTROLLED","10.0.0.2");
        var json=System.Text.Json.JsonSerializer.Serialize(request);
        Assert.Contains("\"requested_control_mode\":\"WEB_CONTROLLED\"",json);
    }
    private sealed class StubHandler(HttpStatusCode? status = null) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken ct) => status is null ? Task.FromException<HttpResponseMessage>(new HttpRequestException("offline")) : Task.FromResult(new HttpResponseMessage(status.Value) { Content = new StringContent("{}", Encoding.UTF8, "application/json") });
    }
    private sealed class JsonHandler(string json) : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken ct)=>Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(json,Encoding.UTF8,"application/json")});
    }
    private sealed class FakeProxyStore(ProxySnapshot initial) : IWindowsProxyStore
    {
        public ProxySnapshot Value { get; set; }=initial;public int Writes{get;private set;}
        public ProxySnapshot Read()=>Value;
        public void Write(ProxySnapshot value){Value=value;Writes++;}
    }
    private sealed class FailingProxyStore : IWindowsProxyStore
    {
        public ProxySnapshot Read()=>new(false,null,null);
        public void Write(ProxySnapshot value)=>throw new IOException("simulated apply failure");
    }
}
