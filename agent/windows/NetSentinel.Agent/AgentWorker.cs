using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System.Security.Cryptography;

namespace NetSentinel.Agent;

public sealed class AgentWorker(
    ManagementClient client,
    StateStore states,
    ISecretStore secrets,
    ISystemSnapshot system,
    ProxyConfigurationManager proxyManager,
    IOptions<AgentOptions> options,
    ILogger<AgentWorker> logger) : BackgroundService
{
    private static readonly int[] RetrySeconds = [5, 15, 30, 60];

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("Agent service starting; version {Version}", AgentVersion.Current);
        LocalState state;
        try { state = await states.LoadAsync(stoppingToken); }
        catch (InvalidDataException ex) { logger.LogCritical("Local state is invalid: {Reason}", ex.Message); return; }
        if (state.AgentVersion != AgentVersion.Current)
        {
            state = state with { AgentVersion = AgentVersion.Current };
            await states.SaveAsync(state, stoppingToken);
            logger.LogInformation("Local agent state upgraded to version {Version}", AgentVersion.Current);
        }

        var credential = await secrets.LoadCredentialAsync(stoppingToken);
        if (state.DeviceId is null || credential is null)
        {
            var enrollmentToken = await secrets.LoadBootstrapTokenAsync(stoppingToken);
            if (string.IsNullOrWhiteSpace(enrollmentToken))
            {
                (state, credential) = await AwaitPortalApprovalAsync(state, stoppingToken);
                if (credential is null) return;
            }
            else try
            {
                var enrolled = await client.EnrollAsync(system.Enrollment(enrollmentToken, state.InstallationId), stoppingToken);
                credential = enrolled.Credential;
                await secrets.SaveCredentialAsync(credential, stoppingToken);
                await secrets.DeleteBootstrapTokenAsync(stoppingToken);
                state = state with { DeviceId = enrolled.DeviceId, AgentIdentity = enrolled.AgentIdentity, HeartbeatIntervalSeconds = Math.Max(options.Value.MinimumHeartbeatSeconds, enrolled.Server.HeartbeatIntervalSeconds), Enrollment = "Enrolled" };
                await states.SaveAsync(state, stoppingToken);
                logger.LogInformation("Enrollment succeeded for device {DeviceId}", state.DeviceId);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException) { logger.LogWarning("Enrollment server is unavailable; service will retry after restart or configuration recovery"); return; }
        }

        var failure = 0;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                var desired = await client.GetConfigurationAsync(credential!, stoppingToken);
                if (desired is not null)
                {
                    logger.LogDebug("Proxy configuration version {Version} received", desired.Version);
                    state = state with { Proxy = await proxyManager.ReconcileAsync(desired, state.Proxy, stoppingToken) };
                    await states.SaveAsync(state, stoppingToken);
                }
            }
            catch (UnauthorizedAccessException)
            {
                state = state with { Enrollment = "CredentialInvalid", Server = "Reachable", LastHeartbeat = DateTimeOffset.UtcNow, ConsecutiveFailures = failure + 1 };
                await states.SaveAsync(state, stoppingToken);
                logger.LogError("Agent credential was rejected during configuration sync; administrative recovery is required");
                return;
            }
            var result = await client.HeartbeatAsync(system.Capture(state.DeviceId!.Value) with { ProxyStatus = state.Proxy }, credential!, stoppingToken);
            var now = DateTimeOffset.UtcNow;
            if (result == HeartbeatResult.CredentialRejected)
            {
                state = state with { Enrollment = "CredentialInvalid", Server = "Reachable", LastHeartbeat = now, ConsecutiveFailures = failure + 1 };
                await states.SaveAsync(state, stoppingToken);
                logger.LogError("Agent credential was rejected; administrative recovery is required");
                return;
            }
            if (result == HeartbeatResult.Success)
            {
                if (failure > 0) logger.LogInformation("Management server connectivity restored");
                failure = 0;
                state = state with { Server = "Reachable", LastHeartbeat = now, LastSuccess = now, ConsecutiveFailures = 0 };
                await states.SaveAsync(state, stoppingToken);
                await DelayWithJitter(state.HeartbeatIntervalSeconds, stoppingToken);
            }
            else
            {
                failure++;
                state = state with { Server = "Unreachable", LastHeartbeat = now, ConsecutiveFailures = failure };
                await states.SaveAsync(state, stoppingToken);
                var delay = RetrySeconds[Math.Min(failure - 1, RetrySeconds.Length - 1)];
                logger.LogWarning("Heartbeat failed ({FailureCount}); retrying with backoff", failure);
                await DelayWithJitter(delay, stoppingToken);
            }
        }
        logger.LogInformation("Agent service stopped cleanly");
    }

    private async Task<(LocalState State, string? Credential)> AwaitPortalApprovalAsync(LocalState state, CancellationToken ct)
    {
        var secret = await secrets.LoadPairingSecretAsync(ct);
        if (string.IsNullOrWhiteSpace(secret))
        {
            secret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            await secrets.SavePairingSecretAsync(secret, ct);
        }
        while (!ct.IsCancellationRequested)
        {
            if (state.PairingRequestId is null)
            {
                var identity = system.Enrollment(string.Empty, state.InstallationId);
                var snapshot = system.Capture(Guid.Empty);
                var initialIp = snapshot.ActiveIps.FirstOrDefault(value => System.Net.IPAddress.TryParse(value, out var parsed) && parsed.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && !System.Net.IPAddress.IsLoopback(parsed));
                var registered = await client.RequestPairingAsync(new(secret, state.InstallationId.ToString(), identity.Hostname, identity.OsName, identity.OsVersion, identity.Architecture, identity.AgentVersion, initialIp), ct);
                if (registered is null)
                {
                    state = state with { Enrollment = "PairingUnavailable", Server = "Unreachable" };
                    await states.SaveAsync(state, ct);
                    await DelayWithJitter(30, ct);
                    continue;
                }
                state = state with { PairingRequestId = registered.Id, PairingCode = registered.PairingCode, Enrollment = "PendingApproval", Server = "Reachable" };
                await states.SaveAsync(state, ct);
                logger.LogInformation("Agent is awaiting portal approval; pairing code {PairingCode}", registered.PairingCode);
            }
            try
            {
                var claim = await client.ClaimPairingAsync(state.PairingRequestId.Value, secret, ct);
                if (claim?.Status == "approved" && claim.DeviceId is not null && claim.AgentIdentity is not null && claim.Credential is not null && claim.Server is not null)
                {
                    await secrets.SaveCredentialAsync(claim.Credential, ct);
                    await secrets.DeletePairingSecretAsync(ct);
                    state = state with { DeviceId = claim.DeviceId, AgentIdentity = claim.AgentIdentity, HeartbeatIntervalSeconds = Math.Max(options.Value.MinimumHeartbeatSeconds, claim.Server.HeartbeatIntervalSeconds), Enrollment = "Enrolled", Server = "Reachable", PairingRequestId = null, PairingCode = null };
                    await states.SaveAsync(state, ct);
                    logger.LogInformation("Portal-approved enrollment succeeded for device {DeviceId}", state.DeviceId);
                    return (state, claim.Credential);
                }
                state = state with { Enrollment = "PendingApproval", Server = claim is null ? "Unreachable" : "Reachable" };
                await states.SaveAsync(state, ct);
            }
            catch (UnauthorizedAccessException)
            {
                state = state with { Enrollment = "PairingRejected", Server = "Reachable" };
                await states.SaveAsync(state, ct);
                logger.LogError("Agent pairing was rejected or expired; reconfiguration is required");
                return (state, null);
            }
            await DelayWithJitter(15, ct);
        }
        return (state, null);
    }

    private static Task DelayWithJitter(int seconds, CancellationToken ct)
    {
        var factor = 0.85 + Random.Shared.NextDouble() * 0.30;
        return Task.Delay(TimeSpan.FromSeconds(Math.Max(1, seconds * factor)), ct);
    }
}
