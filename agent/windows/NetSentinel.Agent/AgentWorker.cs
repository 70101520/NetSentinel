using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace NetSentinel.Agent;

public sealed class AgentWorker(
    ManagementClient client,
    StateStore states,
    ISecretStore secrets,
    ISystemSnapshot system,
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

        var credential = await secrets.LoadCredentialAsync(stoppingToken);
        if (state.DeviceId is null || credential is null)
        {
            var enrollmentToken = await secrets.LoadBootstrapTokenAsync(stoppingToken);
            if (string.IsNullOrWhiteSpace(enrollmentToken)) { logger.LogWarning("Enrollment required; no protected bootstrap token is available"); return; }
            try
            {
                var enrolled = await client.EnrollAsync(system.Enrollment(enrollmentToken, state.InstallationId), stoppingToken);
                credential = enrolled.Credential;
                await secrets.SaveCredentialAsync(credential, stoppingToken);
                await secrets.DeleteBootstrapTokenAsync(stoppingToken);
                state = state with { DeviceId = enrolled.DeviceId, AgentIdentity = enrolled.AgentIdentity, HeartbeatIntervalSeconds = Math.Max(options.Value.MinimumHeartbeatSeconds, enrolled.Server.HeartbeatIntervalSeconds), Enrollment = "Enrolled" };
                await states.SaveAsync(state, stoppingToken);
                logger.LogInformation("Enrollment succeeded for device {DeviceId}", state.DeviceId);
            }
            catch (Exception ex) when (ex is HttpRequestException or TaskCanceledException)
            {
                logger.LogWarning("Enrollment server is unavailable; service will retry after restart or configuration recovery");
                return;
            }
        }

        var failure = 0;
        while (!stoppingToken.IsCancellationRequested)
        {
            var result = await client.HeartbeatAsync(system.Capture(state.DeviceId!.Value), credential!, stoppingToken);
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

    private static Task DelayWithJitter(int seconds, CancellationToken ct)
    {
        var factor = 0.85 + Random.Shared.NextDouble() * 0.30;
        return Task.Delay(TimeSpan.FromSeconds(Math.Max(1, seconds * factor)), ct);
    }
}
