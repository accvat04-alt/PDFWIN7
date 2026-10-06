; Inno Setup script cho KySoPDF (tuong thich Windows 7)
[Setup]
AppName=KySoPDF
AppVersion=1.0
DefaultDirName={autopf}\KySoPDF
DefaultGroupName=KySoPDF
OutputDir=Output
OutputBaseFilename=KySoPDF-Setup
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\KySoPDF.exe

[Files]
Source: "dist\KySoPDF\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autodesktop}\Ky so PDF"; Filename: "{app}\KySoPDF.exe"; WorkingDir: "{app}"
Name: "{group}\Ky so PDF"; Filename: "{app}\KySoPDF.exe"; WorkingDir: "{app}"
Name: "{group}\Go cai dat KySoPDF"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\KySoPDF.exe"; Description: "Chay Ky so PDF ngay"; Flags: nowait postinstall skipifsilent
