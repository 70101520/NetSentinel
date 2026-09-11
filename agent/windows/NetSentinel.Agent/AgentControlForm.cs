using System.Diagnostics;
using System.Text.Json;

namespace NetSentinel.Agent;

internal sealed class AgentControlForm : Form
{
    private readonly AgentPaths paths;
    private readonly TextBox server = new() { Dock = DockStyle.Fill };
    private readonly CheckBox monitoring = new() { Text = "Monitoring", Checked = true, Enabled = false, AutoSize = true };
    private readonly CheckBox fullControl = new() { Text = "Full control and web blocking", AutoSize = true };
    private readonly CheckBox allowHttp = new() { Text = "Allow HTTP (controlled lab only)", AutoSize = true };
    private readonly Label status = new() { AutoSize = true };
    private readonly Label pairing = new() { AutoSize = true };
    private readonly Button save = new() { Text = "Apply and restart Agent", AutoSize = true };

    public AgentControlForm(AgentPaths paths)
    {
        this.paths = paths;
        Text = "NetSentinel Agent Settings";
        Width = 620;
        Height = 390;
        MinimumSize = new Size(520, 350);
        StartPosition = FormStartPosition.CenterScreen;
        Font = new Font("Segoe UI", 10);

        var title = new Label { Text = "NetSentinel Agent", Font = new Font(Font, FontStyle.Bold), AutoSize = true };
        var help = new Label
        {
            Text = "Monitoring is always enabled. Full control sends supported browser traffic through the NetSentinel web policy gateway.",
            AutoSize = true,
            MaximumSize = new Size(540, 0),
            ForeColor = Color.DimGray
        };
        var layout = new TableLayoutPanel { Dock = DockStyle.Fill, Padding = new Padding(24), ColumnCount = 1, RowCount = 10, AutoScroll = true };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        layout.Controls.Add(title);
        layout.Controls.Add(help);
        layout.Controls.Add(new Label { Text = "Management server", AutoSize = true, Margin = new Padding(0, 18, 0, 4) });
        layout.Controls.Add(server);
        layout.Controls.Add(monitoring);
        layout.Controls.Add(fullControl);
        layout.Controls.Add(allowHttp);
        layout.Controls.Add(status);
        layout.Controls.Add(pairing);
        layout.Controls.Add(save);
        Controls.Add(layout);
        AcceptButton = save;
        save.Click += async (_, _) => await ApplyAsync();
        Shown += async (_, _) => await RefreshStateAsync();
    }

    private async Task RefreshStateAsync()
    {
        var configured = Program.ReadConfiguredServer(paths.ConfigurationPath);
        server.Text = configured?.ToString().TrimEnd('/') ?? string.Empty;
        allowHttp.Checked = configured?.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase) == true;
        try
        {
            if (File.Exists(paths.ConfigurationPath))
            {
                using var document = JsonDocument.Parse(await File.ReadAllTextAsync(paths.ConfigurationPath));
                var mode = document.RootElement.GetProperty("Agent").TryGetProperty("RequestedControlMode", out var value) ? value.GetString() : null;
                fullControl.Checked = mode == "WEB_CONTROLLED";
            }
            var state = await new StateStore(paths).LoadAsync(CancellationToken.None);
            status.Text = $"Status: {state.Enrollment} · Server: {state.Server} · Agent {state.AgentVersion}";
            pairing.Text = state.PairingCode is null ? "Pairing code: not pending" : $"Pairing code: {state.PairingCode}";
        }
        catch (Exception ex)
        {
            status.Text = $"Status unavailable: {ex.Message}";
            pairing.Text = string.Empty;
        }
    }

    private async Task ApplyAsync()
    {
        var value = server.Text.Trim().TrimEnd('/');
        if (!Uri.TryCreate(value, UriKind.Absolute, out var target) || !Program.IsValidManagementServer(target, allowHttp.Checked))
        {
            MessageBox.Show(this, "Enter an HTTPS server URL. Enable HTTP only in a controlled lab.", "Invalid server", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        var previous = Program.ReadConfiguredServer(paths.ConfigurationPath);
        if (previous is not null && !Program.SameManagementAuthority(previous, target))
        {
            var answer = MessageBox.Show(this, "Changing the management server archives the old local enrollment and starts fresh portal approval. Continue?", "Change management server", MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (answer != DialogResult.Yes) return;
        }
        save.Enabled = false;
        UseWaitCursor = true;
        try
        {
            await RunServiceCommandAsync("stop", tolerateFailure: true);
            var arguments = new List<string> { "--server", value, "--portal-approval", "--control-mode", fullControl.Checked ? "WEB_CONTROLLED" : "MONITOR_ONLY" };
            if (allowHttp.Checked) arguments.Add("--allow-http");
            var result = await Program.ConfigureAsync(arguments.ToArray(), paths);
            if (result != 0) throw new InvalidOperationException("Agent rejected the configuration");
            await RunServiceCommandAsync("start", tolerateFailure: false);
            await Task.Delay(1500);
            await RefreshStateAsync();
            MessageBox.Show(this, "Agent configuration saved. Approve the new pairing request in the portal if the server changed.", "NetSentinel Agent", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Configuration failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            UseWaitCursor = false;
            save.Enabled = true;
        }
    }

    private static async Task RunServiceCommandAsync(string command, bool tolerateFailure)
    {
        using var process = Process.Start(new ProcessStartInfo("net.exe")
        {
            Arguments = $"{command} NetSentinelAgent",
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardError = true,
            RedirectStandardOutput = true
        }) ?? throw new InvalidOperationException("Unable to control the NetSentinel Agent service");
        await process.WaitForExitAsync();
        if (process.ExitCode != 0 && !tolerateFailure)
            throw new InvalidOperationException($"Windows could not {command} the NetSentinel Agent service");
    }
}
