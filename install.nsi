; install.nsi
; (C) 2014, all rights reserved,
; 
; This program is free software: you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation, either version 3 of the License, or
; (at your option) any later version.
; 
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
; 
; You should have received a copy of the GNU General Public License
; along with this program.  If not, see <http://www.gnu.org/licenses/>.

!include "MUI2.nsh"

SetCompressor /SOLID /FINAL lzma

Name "Tallow"
OutFile "TallowBundle-install.exe"

InstallDir "$PROGRAMFILES\Tallow\"

RequestExecutionLevel admin

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section ""
    SetOutPath $INSTDIR
    File "tallow.exe"
    File "tor.exe"
    File "WinDivert32.sys"
    File "WinDivert64.sys"
    File "WinDivert.dll"
    File "hosts.deny"
    File "traffic.deny"
    File "torrc"
    File "LICENSE"
    WriteUninstaller "TallowBundle-uninstall.exe"
    WriteRegStr HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\Tallow" \
        "DisplayName" "TallowBundle"
    WriteRegStr HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\Tallow" \
        "UninstallString" "$\"$INSTDIR\TallowBundle-uninstall.exe$\""
    CreateShortCut "$DESKTOP\Tallow.lnk" "$INSTDIR\tallow.exe" ""
SectionEnd

Section "Uninstall"
    Delete "$INSTDIR\tallow.exe"
    Delete "$INSTDIR\tor.exe"
    Delete "$INSTDIR\WinDivert32.sys"
    Delete "$INSTDIR\WinDivert64.sys"
    Delete "$INSTDIR\WinDivert.dll"
    Delete "$INSTDIR\hosts.deny"
    Delete "$INSTDIR\traffic.deny"
    Delete "$INSTDIR\torrc"
    Delete "$INSTDIR\LICENSE"
    Delete "$INSTDIR\TallowBundle-uninstall.exe"
    RMDir "$INSTDIR\"
    DeleteRegKey HKCU "Software\Tallow"
    DeleteRegKey HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\Tallow"
    Delete "$DESKTOP\Tallow.lnk"
SectionEnd

