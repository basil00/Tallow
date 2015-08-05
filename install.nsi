; install.nsi
; (C) 2015, all rights reserved,
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

    ; Tallow files:
    File "tallow.exe"
    File "hosts.deny"
    File "traffic.deny"
    File "LICENSE"
    
    ; WinDivert files:
    File "WinDivert32.sys"
    File "WinDivert64.sys"
    File "WinDivert.dll"

    ; Tor files:
    File "libeay32.dll"
    File "libevent-2-0-5.dll"
    File "libevent_core-2-0-5.dll"
    File "libevent_extra-2-0-5.dll"
    File "libgcc_s_sjlj-1.dll"
    File "libssp-0.dll"
    File "ssleay32.dll"
    File "zlib1.dll"
    File "tor.exe"
    File "geoip"
    File "geoip6"
    File "torrc"

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
    RMDir /R /REBOOTOK "$INSTDIR\"
    DeleteRegKey HKCU "Software\Tallow"
    DeleteRegKey HKLM \
        "Software\Microsoft\Windows\CurrentVersion\Uninstall\Tallow"
    Delete "$DESKTOP\Tallow.lnk"
SectionEnd

