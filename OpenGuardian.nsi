; OpenGuardian NSIS 安装包脚本
; 使用: makensis OpenGuardian.nsi (需要安装 NSIS)
; 前提: 先用 build.bat 选项 1 生成 dist\OpenGuardian 文件夹

!define PRODUCT_NAME "OpenGuardian"
!define PRODUCT_VERSION "0.5.8"
!define PRODUCT_PUBLISHER "OpenGuardian Team"
!define PRODUCT_WEB_SITE "https://github.com/yourname/OpenGuardian"
!define PRODUCT_DIR_REGKEY "Software\Microsoft\Windows\CurrentVersion\App Paths\OpenGuardian.exe"

SetCompressor lzma
Name "${PRODUCT_NAME} ${PRODUCT_VERSION}"
OutFile "OpenGuardian-${PRODUCT_VERSION}-Setup.exe"
InstallDir "$PROGRAMFILES64\OpenGuardian"
InstallDirRegKey HKLM "${PRODUCT_DIR_REGKEY}" ""
RequestExecutionLevel admin
BrandingText "OpenGuardian"
Icon "OpenGuardian.ico"

Section "install"
  SetOutPath "$INSTDIR"
  File /r "dist\OpenGuardian\*.*"

  ; 创建快捷方式
  CreateDirectory "$SMPROGRAMS\OpenGuardian"
  CreateShortCut "$SMPROGRAMS\OpenGuardian\OpenGuardian.lnk" "$INSTDIR\OpenGuardian.exe" "" "$INSTDIR\OpenGuardian.ico"
  CreateShortCut "$DESKTOP\OpenGuardian.lnk" "$INSTDIR\OpenGuardian.exe" "" "$INSTDIR\OpenGuardian.ico"

  ; 注册表
  WriteRegStr HKLM "${PRODUCT_DIR_REGKEY}" "" "$INSTDIR\OpenGuardian.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "DisplayName" "OpenGuardian"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "UninstallString" "$INSTDIR\uninstall.exe"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "DisplayIcon" "$INSTDIR\OpenGuardian.ico"
  WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}" "DisplayVersion" "${PRODUCT_VERSION}"

  ; 卸载程序
  WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Section "Uninstall"
  RMDir /r "$INSTDIR"
  RMDir /r "$SMPROGRAMS\OpenGuardian"
  Delete "$DESKTOP\OpenGuardian.lnk"
  DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${PRODUCT_NAME}"
  DeleteRegKey HKLM "${PRODUCT_DIR_REGKEY}"
SectionEnd
