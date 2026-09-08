using System.Net;
using System.Net.Http.Json;

namespace NetSentinel.Agent;

public enum HeartbeatResult { Success, TransientFailure, CredentialRejected }

public sealed class ManagementClient(HttpClient http)
{
    public async Task<ProxyConfiguration?> GetConfigurationAsync(string credential, CancellationToken ct)
    {
        using var message = new HttpRequestMessage(HttpMethod.Get, "api/v1/agents/config");
        message.Headers.Add("X-Agent-Credential", credential);
        try
        {
            using var response = await http.SendAsync(message, ct);
            if (response.StatusCode is HttpStatusCode.Unauthorized or HttpStatusCode.Forbidden) throw new UnauthorizedAccessException("Agent credential rejected during configuration sync");
            if (!response.IsSuccessStatusCode) return null;
            return (await response.Content.ReadFromJsonAsync<ProxyConfigurationEnvelope>(cancellationToken: ct))?.Proxy ?? throw new InvalidDataException("Proxy configuration response was empty");
        }
        catch (HttpRequestException) { return null; }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested) { return null; }
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
}
