using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace NetSentinel.Agent;

internal sealed record UninstallAuthorizationRecord(DateTimeOffset ExpiresAt,string Nonce,string Signature);

internal static class UninstallAuthorization
{
    private static readonly byte[] Context=Encoding.UTF8.GetBytes("NetSentinel.LocalUninstall.v1\0");
    private static readonly JsonSerializerOptions Json=new(JsonSerializerDefaults.Web){WriteIndented=true};
    public static async Task<bool> CreateAsync(string supplied,AgentPaths paths,CancellationToken ct)
    {
        if(!File.Exists(paths.MaintenanceConfigurationPath))return false;
        var settings=JsonSerializer.Deserialize<MaintenanceConfiguration>(await File.ReadAllTextAsync(paths.MaintenanceConfigurationPath,ct),Json);
        if(settings is null||(!PasswordVerifier.Verify(supplied,settings.UninstallPasswordVerifier)&&!PasswordVerifier.Verify(supplied,settings.RecoveryCodeVerifier)))return false;
        var credential=await new DpapiSecretStore(paths).LoadCredentialAsync(ct);if(string.IsNullOrWhiteSpace(credential))return false;
        var expires=DateTimeOffset.UtcNow.AddMinutes(2);var nonce=Convert.ToHexString(RandomNumberGenerator.GetBytes(24));var signature=Sign(expires,nonce,credential);
        var temporary=paths.UninstallAuthorizationPath+".tmp";await File.WriteAllTextAsync(temporary,JsonSerializer.Serialize(new UninstallAuthorizationRecord(expires,nonce,signature),Json),ct);File.Move(temporary,paths.UninstallAuthorizationPath,true);return true;
    }
    public static async Task<bool> ConsumeAsync(AgentPaths paths,CancellationToken ct)
    {
        try
        {
            var record=JsonSerializer.Deserialize<UninstallAuthorizationRecord>(await File.ReadAllTextAsync(paths.UninstallAuthorizationPath,ct),Json);var credential=await new DpapiSecretStore(paths).LoadCredentialAsync(ct);
            if(record is null||credential is null||record.ExpiresAt<DateTimeOffset.UtcNow)return false;
            return CryptographicOperations.FixedTimeEquals(Convert.FromHexString(record.Signature),Convert.FromHexString(Sign(record.ExpiresAt,record.Nonce,credential)));
        }
        catch(Exception ex) when(ex is IOException or JsonException or FormatException){return false;}
        finally{if(File.Exists(paths.UninstallAuthorizationPath))File.Delete(paths.UninstallAuthorizationPath);}
    }
    private static string Sign(DateTimeOffset expires,string nonce,string credential)=>Convert.ToHexString(HMACSHA256.HashData(Encoding.UTF8.GetBytes(credential),Context.Concat(Encoding.UTF8.GetBytes(expires.ToUnixTimeSeconds()+"|"+nonce)).ToArray()));
}

internal sealed class UninstallAuthorizationForm:Form
{
    private readonly TextBox secret=new(){UseSystemPasswordChar=true,Dock=DockStyle.Fill};
    public string SuppliedSecret=>secret.Text;
    public UninstallAuthorizationForm()
    {
        Text="Authorize NetSentinel uninstall";Width=480;Height=230;StartPosition=FormStartPosition.CenterScreen;Font=new Font("Segoe UI",10);FormBorderStyle=FormBorderStyle.FixedDialog;MaximizeBox=false;MinimizeBox=false;
        var layout=new TableLayoutPanel{Dock=DockStyle.Fill,Padding=new Padding(22),ColumnCount=1,RowCount=5};
        layout.Controls.Add(new Label{Text="Uninstall authorization",Font=new Font(Font,FontStyle.Bold),AutoSize=true});
        layout.Controls.Add(new Label{Text="Enter the device uninstall password or the current emergency recovery code.",AutoSize=true,MaximumSize=new Size(410,0)});layout.Controls.Add(secret);
        var buttons=new FlowLayoutPanel{FlowDirection=FlowDirection.RightToLeft,Dock=DockStyle.Fill};var approve=new Button{Text="Authorize",DialogResult=DialogResult.OK,AutoSize=true};var cancel=new Button{Text="Cancel",DialogResult=DialogResult.Cancel,AutoSize=true};buttons.Controls.Add(approve);buttons.Controls.Add(cancel);layout.Controls.Add(buttons);Controls.Add(layout);AcceptButton=approve;CancelButton=cancel;
    }
}
