[Setup]
AppName=NetSnoop System Monitor
AppVersion=1.0
DefaultDirName={pf}\NetSnoop
DefaultGroupName=NetSnoop
OutputDir=.
OutputBaseFilename=NetSnoopSetup
Compression=lzma
SolidCompression=yes

[Files]
Source: "netsnoop_gui.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\NetSnoop System Monitor"; Filename: "{app}\netsnoop_gui.exe"
Name: "{commondesktop}\NetSnoop System Monitor"; Filename: "{app}\netsnoop_gui.exe"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a Desktop shortcut"; GroupDescription: "Additional Icons:"

[Run]
Filename: "{app}\netsnoop_gui.exe"; Description: "Launch NetSnoop after installation"; Flags: nowait postinstall skipifsilent
