#define MyAppName "NetSentinel Agent"
#define MyAppVersion "0.9.2"
#define MyAppPublisher "NetSentinel"
#define MyAppExeName "NetSentinel.Agent.exe"

[Setup]
AppId={{35ED1F1C-94CE-40D8-A7C0-95C714847F33}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\NetSentinel\Agent
DisableDirPage=yes
DisableProgramGroupPage=yes
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=installer-output
OutputBaseFilename=NetSentinel-Agent-Setup-{#MyAppVersion}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#MyAppExeName}

[Files]
Source: "NetSentinel.Agent\bin\Release\net8.0-windows\win-x64\publish\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "install-paired-agent.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "uninstall-agent.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "maintenance-uninstall.ps1"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\NetSentinel Agent Settings"; Filename: "{app}\{#MyAppExeName}"; Parameters: "gui"; WorkingDir: "{app}"
Name: "{commondesktop}\NetSentinel Agent Settings"; Filename: "{app}\{#MyAppExeName}"; Parameters: "gui"; WorkingDir: "{app}"

[UninstallRun]
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File ""{app}\uninstall-agent.ps1"""; Flags: runhidden waituntilterminated; RunOnceId: "RemoveService"

[Code]
var
  ServerPage: TInputQueryWizardPage;
  LabHttpPage: TInputOptionWizardPage;
  ModePage: TInputOptionWizardPage;

function InitializeUninstall(): Boolean;
var
  ResultCode: Integer;
begin
  Result := Exec(ExpandConstant('{app}\{#MyAppExeName}'), 'authorize-uninstall', '', SW_SHOW,
    ewWaitUntilTerminated, ResultCode) and (ResultCode = 0);
  if not Result then
    MsgBox('NetSentinel uninstall was not authorized. Use the device password or recovery code from the portal.', mbError, MB_OK);
end;

procedure InitializeWizard;
begin
  ServerPage := CreateInputQueryPage(wpSelectDir,
    'Connect to NetSentinel',
    'Enter the NetSentinel server address',
    'Enter the server IP with port, or the HTTPS URL supplied by your administrator.');
  ServerPage.Add('Server IP or URL:', False);
  ServerPage.Values[0] := '';

  LabHttpPage := CreateInputOptionPage(ServerPage.ID,
    'Transport security',
    'Use HTTPS unless this is a controlled test environment',
    'HTTP sends management traffic without TLS and must never be enabled in production.',
    False, False);
  LabHttpPage.Add('Allow HTTP for a controlled lab only');

  ModePage := CreateInputOptionPage(LabHttpPage.ID,
    'Agent features',
    'Choose what this computer will allow',
    'Monitoring is always installed. Full control routes supported web traffic through NetSentinel for domain logging and blocking.',
    False, False);
  ModePage.Add('Monitoring (required)');
  ModePage.Add('Full control and blocking');
  ModePage.Values[0] := True;
  ModePage.Values[1] := False;
  ModePage.CheckListBox.ItemEnabled[0] := False;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Value: String;
begin
  Result := True;
  if CurPageID = LabHttpPage.ID then
  begin
    Value := Trim(ServerPage.Values[0]);
    if Pos('://', Value) = 0 then
    begin
      if LabHttpPage.Values[0] then Value := 'http://' + Value
      else Value := 'https://' + Value;
    end;
    ServerPage.Values[0] := Value;
    if (Pos('"', Value) > 0) or (Pos(' ', Value) > 0) then
    begin
      MsgBox('The server address cannot contain quotes or spaces.', mbError, MB_OK);
      Result := False;
      Exit;
    end;
    if (Pos('https://', Lowercase(Value)) = 1) and (Length(Value) > 8) then Exit;
    if (Pos('http://', Lowercase(Value)) = 1) and (Length(Value) > 7) and LabHttpPage.Values[0] then Exit;
    MsgBox('Enter an HTTPS URL. HTTP requires the controlled-lab option.', mbError, MB_OK);
    Result := False;
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  Exec(ExpandConstant('{sys}\net.exe'), 'stop NetSentinelAgent', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(ExpandConstant('{sys}\net.exe'), 'stop NetSentinelMaintenance', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function ReadPairingCode(): String;
var
  Contents, Tail: AnsiString;
  MarkerPosition, QuotePosition: Integer;
begin
  Result := '';
  if not LoadStringFromFile(ExpandConstant('{commonappdata}\NetSentinel\Agent\state.json'), Contents) then Exit;
  MarkerPosition := Pos('"pairingCode"', Contents);
  if MarkerPosition = 0 then Exit;
  Tail := Copy(Contents, MarkerPosition + Length('"pairingCode"'), Length(Contents));
  QuotePosition := Pos('"', Tail);
  if QuotePosition = 0 then Exit;
  Tail := Copy(Tail, QuotePosition + 1, Length(Tail));
  QuotePosition := Pos('"', Tail);
  if QuotePosition > 0 then Result := Copy(Tail, 1, QuotePosition - 1);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  Params: String;
  PairingCode: String;
  ResultCode: Integer;
  Attempt: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    Params := '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
      ExpandConstant('{app}\install-paired-agent.ps1') + '" -ServerUrl "' +
      ServerPage.Values[0] + '"';
    if LabHttpPage.Values[0] then Params := Params + ' -AllowHttp';
    if ModePage.Values[1] then Params := Params + ' -RequestedControlMode WEB_CONTROLLED'
    else Params := Params + ' -RequestedControlMode MONITOR_ONLY';
    if (not Exec(ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe'), Params,
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode)) or (ResultCode <> 0) then
      RaiseException('NetSentinel Agent service configuration failed. See C:\ProgramData\NetSentinel\Agent\install.log for the exact stage and error.');
    PairingCode := '';
    for Attempt := 1 to 15 do
    begin
      PairingCode := ReadPairingCode();
      if PairingCode <> '' then Break;
      Sleep(1000);
    end;
    if PairingCode <> '' then
      MsgBox('Installation completed. Ask a NetSentinel administrator to approve this computer on the Agents page and verify pairing code ' + PairingCode + '. No enrollment token is required.', mbInformation, MB_OK)
    else
      MsgBox('Installation completed. Ask a NetSentinel administrator to approve this computer on the Agents page. The pairing request can take a few seconds to appear.', mbInformation, MB_OK);
  end;
end;
