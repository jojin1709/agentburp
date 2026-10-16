; ==============================================================================
; agentburp — NSIS Modern Installer Script
; Developed by JOJIN JOHN
; Single-User Installation (No Admin Rights Required, Works Anywhere)
; ==============================================================================

!include "MUI2.nsh"
!include "WinMessages.nsh"

Name "agentburp"
OutFile "dist\agentburp-setup.exe"
InstallDir "$LOCALAPPDATA\Programs\agentburp"
InstallDirRegKey HKCU "Software\agentburp" "Install_Dir"
RequestExecutionLevel user

; Branding & Icons
!define MUI_ICON "assets\icon.ico"
!define MUI_UNICON "assets\icon.ico"
!define MUI_ABORTWARNING
BrandingText "agentburp — Developed by JOJIN JOHN"

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_NOAUTOCLOSE
!define MUI_FINISHPAGE_RUN
!define MUI_FINISHPAGE_RUN_TEXT "Start agentburp proxy listener now"
!define MUI_FINISHPAGE_RUN_FUNCTION "LaunchProxy"
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section "agentburp Core (Required)" SecCore
  SectionIn RO

  SetOutPath "$INSTDIR"
  File "dist\agentburp.exe"
  File "scope.yml"
  File "LICENSE"
  File "README.md"
  File "assets\icon.ico"

  ; Write Uninstaller
  WriteUninstaller "$INSTDIR\uninstall.exe"

  ; Store installation folder in Registry
  WriteRegStr HKCU "Software\agentburp" "Install_Dir" "$INSTDIR"

  ; Add $INSTDIR to user PATH in registry
  ReadRegStr $0 HKCU "Environment" "Path"
  StrCmp $0 "" AddEmptyPath
  WriteRegExpandStr HKCU "Environment" "Path" "$0;$INSTDIR"
  Goto BroadcastPath
AddEmptyPath:
  WriteRegExpandStr HKCU "Environment" "Path" "$INSTDIR"
BroadcastPath:
  SendMessage ${HWND_BROADCAST} ${WM_SETTINGCHANGE} 0 "STR:Environment" /TIMEOUT=5000

  ; Add uninstaller to Add/Remove Programs
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\agentburp" "DisplayName" "agentburp"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\agentburp" "DisplayIcon" "$INSTDIR\icon.ico"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\agentburp" "Publisher" "JOJIN JOHN"
  WriteRegStr HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\agentburp" "UninstallString" '"$INSTDIR\uninstall.exe"'
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\agentburp" "NoModify" 1
  WriteRegDWORD HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\agentburp" "NoRepair" 1

  ; Create Start Menu Shortcuts
  CreateDirectory "$SMPROGRAMS\agentburp"
  CreateShortcut "$SMPROGRAMS\agentburp\agentburp Proxy.lnk" "$SYSDIR\cmd.exe" '/k "agentburp proxy start --addr 127.0.0.1:8888"' "$INSTDIR\icon.ico" 0
  CreateShortcut "$SMPROGRAMS\agentburp\agentburp Terminal.lnk" "$SYSDIR\cmd.exe" '/k "agentburp --help"' "$INSTDIR\icon.ico" 0
  CreateShortcut "$SMPROGRAMS\agentburp\Uninstall agentburp.lnk" "$INSTDIR\uninstall.exe" "" "$INSTDIR\uninstall.exe" 0
SectionEnd

Function LaunchProxy
  ExecShell "open" "$SYSDIR\cmd.exe" '/k "$INSTDIR\agentburp.exe proxy start --addr 127.0.0.1:8888"'
FunctionEnd

Section "Uninstall"
  Delete "$INSTDIR\agentburp.exe"
  Delete "$INSTDIR\scope.yml"
  Delete "$INSTDIR\LICENSE"
  Delete "$INSTDIR\README.md"
  Delete "$INSTDIR\icon.ico"
  Delete "$INSTDIR\uninstall.exe"

  RMDir "$INSTDIR"

  ; Remove Start Menu Shortcuts
  Delete "$SMPROGRAMS\agentburp\agentburp Proxy.lnk"
  Delete "$SMPROGRAMS\agentburp\agentburp Terminal.lnk"
  Delete "$SMPROGRAMS\agentburp\Uninstall agentburp.lnk"
  RMDir "$SMPROGRAMS\agentburp"

  DeleteRegKey HKCU "Software\Microsoft\Windows\CurrentVersion\Uninstall\agentburp"
  DeleteRegKey HKCU "Software\agentburp"
SectionEnd
