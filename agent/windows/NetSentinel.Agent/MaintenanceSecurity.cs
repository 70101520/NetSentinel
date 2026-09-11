using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace NetSentinel.Agent;

public static class AgentCommandVerifier
{
    private static readonly byte[] Context = Encoding.UTF8.GetBytes("NetSentinel.Agent.Command.v1\0");
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static AgentCommandPayload Verify(SignedCommandEnvelope envelope, string credential, Guid deviceId, DateTimeOffset now)
    {
        if (envelope.Algorithm != "HMAC-SHA256" || envelope.KeyContext != "agent-credential-v1") throw new InvalidDataException("Agent command signature metadata is unsupported");
        var separator=credential.IndexOf('.');
        if(separator<1||separator==credential.Length-1)throw new InvalidDataException("Agent credential is invalid");
        var payload=Decode(envelope.Payload);var supplied=Decode(envelope.Signature);
        var key=Encoding.UTF8.GetBytes(credential[(separator+1)..]);
        var signed=new byte[Context.Length+payload.Length];Context.CopyTo(signed,0);payload.CopyTo(signed,Context.Length);
        var expected=HMACSHA256.HashData(key,signed);
        if(!CryptographicOperations.FixedTimeEquals(expected,supplied))throw new InvalidDataException("Agent command signature is invalid");
        var command=JsonSerializer.Deserialize<AgentCommandPayload>(payload,Json)??throw new InvalidDataException("Agent command payload is invalid");
        if(command.DeviceId!=deviceId||command.CommandType!="UNINSTALL"||command.Nonce.Length<32)throw new InvalidDataException("Agent command scope is invalid");
        if(command.ExpiresAt<=now||command.IssuedAt>now.AddMinutes(2)||command.ExpiresAt-command.IssuedAt>TimeSpan.FromMinutes(15))throw new InvalidDataException("Agent command is expired or outside its validity window");
        return command;
    }

    private static byte[] Decode(string value)
    {
        var padded=value.Replace('-','+').Replace('_','/');padded+=new string('=',(4-padded.Length%4)%4);
        try{return Convert.FromBase64String(padded);}catch(FormatException ex){throw new InvalidDataException("Agent command encoding is invalid",ex);}
    }
}

public sealed class MaintenanceSettingsStore(AgentPaths paths)
{
    private static readonly JsonSerializerOptions Json=new(JsonSerializerDefaults.Web){WriteIndented=true};
    public async Task SaveAsync(MaintenanceConfiguration settings,CancellationToken ct)
    {
        var temporary=paths.MaintenanceConfigurationPath+".tmp";await File.WriteAllTextAsync(temporary,JsonSerializer.Serialize(settings,Json),ct);File.Move(temporary,paths.MaintenanceConfigurationPath,true);
    }
    public async Task StageCommandAsync(SignedCommandEnvelope envelope,CancellationToken ct)
    {
        var temporary=paths.MaintenanceRequestPath+".tmp";await File.WriteAllTextAsync(temporary,JsonSerializer.Serialize(envelope,Json),ct);File.Move(temporary,paths.MaintenanceRequestPath,true);
    }
}

public static class PasswordVerifier
{
    public static bool Verify(string value,string? record)
    {
        if(string.IsNullOrWhiteSpace(record))return false;
        var parts=record.Split('$');
        if(parts.Length!=4||parts[0]!="pbkdf2-sha256"||!int.TryParse(parts[1],out var iterations)||iterations<100_000)return false;
        try
        {
            var salt=Decode(parts[2]);var expected=Decode(parts[3]);var actual=Rfc2898DeriveBytes.Pbkdf2(value,salt,iterations,HashAlgorithmName.SHA256,expected.Length);
            return CryptographicOperations.FixedTimeEquals(actual,expected);
        }
        catch(FormatException){return false;}
    }
    private static byte[] Decode(string value){var padded=value.Replace('-','+').Replace('_','/');padded+=new string('=',(4-padded.Length%4)%4);return Convert.FromBase64String(padded);}
}
