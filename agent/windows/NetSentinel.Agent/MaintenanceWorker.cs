using System.Diagnostics;
using System.Text.Json;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace NetSentinel.Agent;

public sealed class MaintenanceWorker(AgentPaths paths,StateStore states,ISecretStore secrets,IHostApplicationLifetime lifetime,ILogger<MaintenanceWorker> logger):BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        logger.LogInformation("NetSentinel privileged maintenance broker started");
        while(!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if(File.Exists(paths.MaintenanceRequestPath) && await ProcessRequestAsync(stoppingToken))return;
            }
            catch(Exception ex) when(ex is IOException or UnauthorizedAccessException or InvalidDataException or System.Security.Cryptography.CryptographicException)
            {
                logger.LogError("Maintenance request rejected: {Reason}",ex.Message);
                try{File.Move(paths.MaintenanceRequestPath,paths.MaintenanceRequestPath+".rejected",true);}catch(IOException){}
            }
            await Task.Delay(TimeSpan.FromSeconds(3),stoppingToken);
        }
    }

    private async Task<bool> ProcessRequestAsync(CancellationToken ct)
    {
        var envelope=JsonSerializer.Deserialize<SignedCommandEnvelope>(await File.ReadAllTextAsync(paths.MaintenanceRequestPath,ct),new JsonSerializerOptions(JsonSerializerDefaults.Web))??throw new InvalidDataException("Maintenance request is empty");
        var state=await states.LoadAsync(ct);var credential=await secrets.LoadCredentialAsync(ct)??throw new InvalidDataException("Agent credential is unavailable");
        if(state.DeviceId is null)throw new InvalidDataException("Agent device identity is unavailable");
        var command=AgentCommandVerifier.Verify(envelope,credential,state.DeviceId.Value,DateTimeOffset.UtcNow);
        if(!File.Exists(paths.MaintenanceScriptPath))throw new IOException("Signed maintenance script is unavailable");
        await ProxyConfigurationManager.RestoreBaselineAsync(new WinHttpProxyStore(),paths,ct);
        var temporary=Path.Combine(Path.GetTempPath(),$"NetSentinel-maintenance-{command.CommandId:N}.ps1");File.Copy(paths.MaintenanceScriptPath,temporary,true);
        File.Move(paths.MaintenanceRequestPath,paths.MaintenanceRequestPath+".accepted",true);
        var start=new ProcessStartInfo(Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),"WindowsPowerShell","v1.0","powershell.exe")){UseShellExecute=false,CreateNoWindow=true};
        start.ArgumentList.Add("-NoProfile");start.ArgumentList.Add("-NonInteractive");start.ArgumentList.Add("-ExecutionPolicy");start.ArgumentList.Add("Bypass");start.ArgumentList.Add("-File");start.ArgumentList.Add(temporary);start.ArgumentList.Add("-CommandId");start.ArgumentList.Add(command.CommandId.ToString());
        if(command.RemoveIdentity)start.ArgumentList.Add("-RemoveIdentity");
        _=Process.Start(start)??throw new IOException("Unable to start signed maintenance operation");
        logger.LogWarning("Verified uninstall command {CommandId} handed to the maintenance helper",command.CommandId);lifetime.StopApplication();return true;
    }
}
