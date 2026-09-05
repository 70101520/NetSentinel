using System.Text.Json.Serialization;

namespace NetSentinel.Agent;

public sealed class AgentOptions
{
    public const string Section = "Agent";
    public string ServerUrl { get; set; } = "";
    public int RequestTimeoutSeconds { get; set; } = 15;
    public int MinimumHeartbeatSeconds { get; set; } = 15;
    public string LogLevel { get; set; } = "Information";
    public bool AllowHttp { get; set; } = false;
}

public sealed record LocalState(
    Guid InstallationId,
    Guid? DeviceId = null,
    Guid? AgentIdentity = null,
    int HeartbeatIntervalSeconds = 60,
    string Enrollment = "NotEnrolled",
    string Server = "Unknown",
    DateTimeOffset? LastHeartbeat = null,
    DateTimeOffset? LastSuccess = null,
    int ConsecutiveFailures = 0,
    string AgentVersion = AgentVersion.Current,
    ProxyRuntimeStatus? Proxy = null);

public sealed record ProxyConfiguration(bool Enabled, string? Host, int? Port, string[] Bypass, string Mode, long Version);
public sealed record ProxyConfigurationEnvelope([property: JsonPropertyName("proxy")] ProxyConfiguration Proxy);
public sealed record ProxyRuntimeStatus(
    [property: JsonPropertyName("desired_version")] long DesiredVersion = 1,
    [property: JsonPropertyName("applied_version")] long? AppliedVersion = null,
    [property: JsonPropertyName("current_state")] string CurrentState = "unknown",
    [property: JsonPropertyName("drift_detected")] bool DriftDetected = false,
    [property: JsonPropertyName("last_apply_result")] string? LastApplyResult = null,
    [property: JsonPropertyName("last_error")] string? LastError = null,
    [property: JsonPropertyName("effective_host")] string? EffectiveHost = null,
    [property: JsonPropertyName("effective_port")] int? EffectivePort = null,
    [property: JsonPropertyName("bypass_summary")] string? BypassSummary = null,
    DateTimeOffset? LastConfigurationSync = null);

public sealed record EnrollRequest(
    [property: JsonPropertyName("enrollment_token")] string EnrollmentToken,
    [property: JsonPropertyName("installation_id")] string InstallationId,
    [property: JsonPropertyName("hostname")] string Hostname,
    [property: JsonPropertyName("os_name")] string OsName,
    [property: JsonPropertyName("os_version")] string OsVersion,
    [property: JsonPropertyName("architecture")] string Architecture,
    [property: JsonPropertyName("agent_version")] string AgentVersion);

public sealed record EnrollResponse(
    [property: JsonPropertyName("device_id")] Guid DeviceId,
    [property: JsonPropertyName("agent_identity")] Guid AgentIdentity,
    [property: JsonPropertyName("credential")] string Credential,
    [property: JsonPropertyName("server")] ServerPolicy Server);

public sealed record ServerPolicy([property: JsonPropertyName("heartbeat_interval_seconds")] int HeartbeatIntervalSeconds);

public sealed record HeartbeatRequest(
    [property: JsonPropertyName("device_id")] Guid DeviceId,
    [property: JsonPropertyName("timestamp")] DateTimeOffset Timestamp,
    [property: JsonPropertyName("hostname")] string Hostname,
    [property: JsonPropertyName("username")] string? Username,
    [property: JsonPropertyName("agent_version")] string AgentVersion,
    [property: JsonPropertyName("os_name")] string OsName,
    [property: JsonPropertyName("os_version")] string OsVersion,
    [property: JsonPropertyName("active_ips")] string[] ActiveIps,
    [property: JsonPropertyName("mac_addresses")] string[] MacAddresses,
    [property: JsonPropertyName("gateway")] string? Gateway,
    [property: JsonPropertyName("dns")] string[] Dns,
    [property: JsonPropertyName("boot_time")] DateTimeOffset BootTime,
    [property: JsonPropertyName("uptime_seconds")] long UptimeSeconds,
    [property: JsonPropertyName("proxy_status")] ProxyRuntimeStatus? ProxyStatus = null);

public static class AgentVersion { public const string Current = "0.1.0"; }
