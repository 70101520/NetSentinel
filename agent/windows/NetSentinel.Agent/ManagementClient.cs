using System.Net;
using System.Net.Http.Json;

namespace NetSentinel.Agent;

public enum HeartbeatResult { Success, TransientFailure, CredentialRejected }

public sealed class ManagementClient(HttpClient http)
{
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
