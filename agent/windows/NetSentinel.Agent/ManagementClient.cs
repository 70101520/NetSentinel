using System.Net;
using System.Net.Http.Json;

namespace NetSentinel.Agent;

public enum HeartbeatResult { Success, TransientFailure, CredentialRejected }

public sealed class ManagementClient(HttpClient http)
{
    public async Task<PairingRegistration?> RequestPairingAsync(PairingRequest request,CancellationToken ct)
    {
        try{using var response=await http.PostAsJsonAsync("api/v1/agents/pairing-requests",request,ct);if(!response.IsSuccessStatusCode)return null;return await response.Content.ReadFromJsonAsync<PairingRegistration>(cancellationToken:ct);}
        catch(HttpRequestException){return null;}catch(TaskCanceledException) when(!ct.IsCancellationRequested){return null;}
    }

    public async Task<PairingClaim?> ClaimPairingAsync(Guid requestId,string secret,CancellationToken ct)
    {
        using var message=new HttpRequestMessage(HttpMethod.Post,$"api/v1/agents/pairing-requests/{requestId}/claim"){Content=JsonContent.Create(new{pairing_secret=secret})};
        try{using var response=await http.SendAsync(message,ct);if(response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden or HttpStatusCode.Gone)throw new UnauthorizedAccessException("Agent pairing was rejected, expired, or invalid");if(!response.IsSuccessStatusCode)return null;return await response.Content.ReadFromJsonAsync<PairingClaim>(cancellationToken:ct);}
        catch(HttpRequestException){return null;}catch(TaskCanceledException) when(!ct.IsCancellationRequested){return null;}
    }
    public async Task<bool> SyncControlModeAsync(string credential,string requestedControlMode,CancellationToken ct)
    {
        using var message=new HttpRequestMessage(HttpMethod.Put,"api/v1/agents/control-mode"){Content=JsonContent.Create(new{control_mode=requestedControlMode})};
        message.Headers.Add("X-Agent-Credential",credential);
        try
        {
            using var response=await http.SendAsync(message,ct);
            if(response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)throw new UnauthorizedAccessException("Agent credential rejected during control-mode sync");
            return response.IsSuccessStatusCode;
        }
        catch(HttpRequestException){return false;}
        catch(TaskCanceledException) when(!ct.IsCancellationRequested){return false;}
    }

    public async Task<ProxyConfiguration?> GetConfigurationAsync(string credential, CancellationToken ct)
        => (await GetAgentConfigurationAsync(credential,ct))?.Proxy;

    public async Task<AgentConfiguration?> GetAgentConfigurationAsync(string credential, CancellationToken ct)
    {
        using var message = new HttpRequestMessage(HttpMethod.Get, "api/v1/agents/config");
        message.Headers.Add("X-Agent-Credential", credential);
        try
        {
            using var response = await http.SendAsync(message, ct);
            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden) throw new UnauthorizedAccessException("Agent credential rejected during configuration sync");
            if (!response.IsSuccessStatusCode) return null;
            var envelope = await response.Content.ReadFromJsonAsync<ProxyConfigurationEnvelope>(cancellationToken: ct) ?? throw new InvalidDataException("Proxy configuration response was empty");
            if (envelope.ControlMode == "WEB_CONTROLLED" && !envelope.Proxy.Enabled)
            {
                var host = http.BaseAddress?.Host ?? throw new InvalidDataException("Management server host is unavailable");
                var bypass=new[]{"localhost","127.0.0.1",host}.Concat(envelope.Proxy.Bypass).Distinct(StringComparer.OrdinalIgnoreCase).ToArray();
                return new AgentConfiguration(new ProxyConfiguration(true, host, 3128, bypass, "configured", envelope.Proxy.Version),envelope.Maintenance);
            }
            return new AgentConfiguration(envelope.Proxy,envelope.Maintenance);
        }
        catch (HttpRequestException) { return null; }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested) { return null; }
    }

    public async Task<SignedCommandEnvelope?> GetPendingCommandAsync(string credential,CancellationToken ct)
    {
        using var message=new HttpRequestMessage(HttpMethod.Get,"api/v1/agents/commands/pending");message.Headers.Add("X-Agent-Credential",credential);
        try
        {
            using var response=await http.SendAsync(message,ct);
            if(response.StatusCode==HttpStatusCode.NoContent)return null;
            if(response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden)throw new UnauthorizedAccessException("Agent credential rejected during command sync");
            if(!response.IsSuccessStatusCode)return null;
            return await response.Content.ReadFromJsonAsync<SignedCommandEnvelope>(cancellationToken:ct);
        }
        catch(HttpRequestException){return null;}
        catch(TaskCanceledException) when(!ct.IsCancellationRequested){return null;}
    }

    public async Task<bool> AcknowledgeCommandAsync(Guid commandId,string status,string? detail,string credential,CancellationToken ct)
    {
        using var message=new HttpRequestMessage(HttpMethod.Post,$"api/v1/agents/commands/{commandId}/ack"){Content=JsonContent.Create(new{status,message=detail})};message.Headers.Add("X-Agent-Credential",credential);
        try{using var response=await http.SendAsync(message,ct);return response.IsSuccessStatusCode;}
        catch(HttpRequestException){return false;}catch(TaskCanceledException) when(!ct.IsCancellationRequested){return false;}
    }

    public async Task<EnrollResponse> EnrollAsync(EnrollRequest request, CancellationToken ct)
    {
        using var response = await http.PostAsJsonAsync("api/v1/agents/enroll", request, ct);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadFromJsonAsync<EnrollResponse>(cancellationToken: ct) ?? throw new InvalidDataException("Enrollment response was empty");
    }

    public async Task<HeartbeatResult> HeartbeatAsync(HeartbeatRequest request, string credential, CancellationToken ct)
    {
        using var message = new HttpRequestMessage(HttpMethod.Post, "api/v1/agents/heartbeat") { Content = JsonContent.Create(request) };
        message.Headers.Add("X-Agent-Credential", credential);
        try
        {
            using var response = await http.SendAsync(message, ct);
            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden) return HeartbeatResult.CredentialRejected;
            return response.IsSuccessStatusCode ? HeartbeatResult.Success : HeartbeatResult.TransientFailure;
        }
        catch (HttpRequestException) { return HeartbeatResult.TransientFailure; }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested) { return HeartbeatResult.TransientFailure; }
    }

    public async Task<bool> ReportOfflineAsync(string credential, CancellationToken ct)
    {
        using var message = new HttpRequestMessage(HttpMethod.Post, "api/v1/agents/offline");
        message.Headers.Add("X-Agent-Credential", credential);
        try { using var response = await http.SendAsync(message, ct); return response.IsSuccessStatusCode; }
        catch (HttpRequestException) { return false; }
        catch (TaskCanceledException) { return false; }
    }
}
