; install.nsi
; (C) 2013, all rights reserved,
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

Name "TorWall"
OutFile "TorWall-install.exe"

InstallDir "$PROGRAMFILES\TorWall\"

RequestExecutionLevel admin

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_INSTFILES

!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Section ""
    SetOutPath $INSTDIR
    File "tor_wall.exe"
    File "tor_wall.exe.manifest"
    File "privoxy.exe"
    File "mgwz.dll"
    File "tor.exe"
    File "libeay32.dll"
    File "ssleay32.dll"
    File "WinDivert.sys"
    File "WinDivert.inf"
    File "WinDivert.dll"
    File "WdfCoInstaller01009.dll"
    File "config.txt"
    File "default.action"
    File "default.filter"
    File "match-all.action"
    File "trust.txt"
    File "user.action"
    File "user.filter"
    WriteUninstaller "TorWall-uninstall.exe"
    CreateShortCut "$DESKTOP\TorWall.lnk" "$INSTDIR\tor_wall.exe" ""
SectionEnd

Section "Uninstall"
    Delete "$INSTDIR\tor_wall.exe"
    Delete "$INSTDIR\tor_wall.exe.manifest"
    Delete "$INSTDIR\privoxy.exe"
    Delete "$INSTDIR\mgwz.dll"
    Delete "$INSTDIR\tor.exe"
    Delete "$INSTDIR\libeay32.dll"
    Delete "$INSTDIR\ssleay32.dll"
    Delete "$INSTDIR\WinDivert.sys"
    Delete "$INSTDIR\WinDivert.inf"
    Delete "$INSTDIR\WinDivert.dll"
    Delete "$INSTDIR\WdfCoInstaller01009.dll"
    Delete "$INSTDIR\config.txt"
    Delete "$INSTDIR\default.action"
    Delete "$INSTDIR\default.filter"
    Delete "$INSTDIR\match-all.action"
    Delete "$INSTDIR\trust.txt"
    Delete "$INSTDIR\user.action"
    Delete "$INSTDIR\user.filter"
    Delete "$INSTDIR\privoxy.log"
    Delete "$INSTDIR\TorWall-uninstall.exe"
    RMDir "$INSTDIR\"
    Delete "$DESKTOP\TorWall.lnk"
SectionEnd

