; OpenGuardian Inno Setup 安装包脚本
; 使用：安装 Inno Setup 后，用编译器打开此文件 → Build → Compile
; 前提：先运行 build.bat 选项 1 生成 dist\OpenGuardian 文件夹

#define MyAppName "OpenGuardian"
#define MyAppVersion "0.7.0"
#define MyAppPublisher "OpenGuardian Team"
#define MyAppURL "https://github.com/OpenGuardian"
#define MyAppExeName "OpenGuardian.exe"

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
AllowNoIcons=yes
OutputDir=.
OutputBaseFilename=OpenGuardian-{#MyAppVersion}-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
SetupIconFile=OpenGuardian.ico
UninstallDisplayIcon={app}\OpenGuardian.ico
PrivilegesRequired=admin

[Languages]
Name: "chinese"; MessagesFile: "C:\Users\14845\AppData\Local\InnoSetup\Languages\ChineseSimplified.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加图标:"; Flags: checkedonce

[Files]
Source: "dist\OpenGuardian\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\OpenGuardian.exe"
Name: "{commondesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; IconFilename: "{app}\OpenGuardian.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "启动 OpenGuardian"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
Type: filesandordirs; Name: "{localappdata}\OpenGuardian"
Type: files; Name: "{app}\config.json"
Type: files; Name: "{app}\.env"
Type: filesandordirs; Name: "{app}\kb_data"
Type: filesandordirs; Name: "{app}\_internal"
Type: files; Name: "{app}\*.log"
Type: files; Name: "{app}\*.db"
Type: dirifempty; Name: "{app}"
