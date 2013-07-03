#!/bin/bash
#
# (C) 2013, all rights reserved,
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# Script for building WinDivert binary packages.  This script assumes the
# binaries are already built and are in the install/ subdirectory.

set -e

WINDIVERT=WinDivert-1.0.5-MINGW
PRIVOXY=privoxy
TOR=tor
MGWZ=mgwz
LIBEAY32=libeay32
SSLEAY32=ssleay32

echo "Checking for dependencies..."
cd contrib
if [ ! -e "$WINDIVERT.zip" ]
then
    echo "ERROR: missing \"$WINDIVERT.zip\"; download from" \
        "(http://reqrypt.org/windivert.html)" 2>&1
    exit 1
fi
for FILE in "$PRIVOXY.exe" "$MGWZ.dll"
do
    if [ ! -e "$FILE" ]
    then
        echo "ERROR: missing \"$FILE\"; download and extract from the" \
            "Privoxy Windows installation package (http://www.privoxy.org/)" 2&1
        exit 1
    fi
done
for FILE in "$TOR.exe" "$LIBEAY32.dll" "$SSLEAY32.dll"
do
    if [ ! -e "$FILE" ]
    then
        echo "ERROR: missing \"$FILE\"; download and extract from the Tor" \
            "Browser Bundle for Windows (https://www.torproject.org/)" 2>&1
        exit 1;
    fi
done

echo "Extracting WinDivert..."
unzip -o $WINDIVERT.zip

echo "Building TorWall..."
cd ..
make

echo "Copying \"tor_wall.exe\"..."
cp tor_wall.exe install/.

for FILE in "$PRIVOXY.exe" "$MGWZ.dll" "$TOR.exe" "$LIBEAY32.dll" \
       "$SSLEAY32.dll" \
       "$WINDIVERT/amd64/WinDivert.sys" \
       "$WINDIVERT/amd64/WinDivert.inf" \
       "$WINDIVERT/amd64/WinDivert.dll" \
       "$WINDIVERT/amd64/WdfCoInstaller01009.dll"
do
    echo "Copying \"$FILE\"..."
    cp contrib/"$FILE" install/.
done
cd config
for FILE in *
do
    echo "Copying \"$FILE\"..."
    cp "$FILE" ../install/.
done
cd ..

echo "Building installation package..."
cd install
cp ../install.nsi .
makensis install.nsi
mv TorWall-install.exe ..
cd ..

echo "Cleaning up..."
rm -f install/*
make clean

echo "Done!"

