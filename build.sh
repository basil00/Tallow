#!/bin/bash
#
# (C) 2014, all rights reserved,
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

WINDIVERT=WinDivert-1.1.5-MINGW
TOR=tor

echo "Checking for dependencies..."
cd contrib
if [ ! -e "$WINDIVERT.zip" ]
then
    echo "ERROR: missing \"$WINDIVERT.zip\"; download from" \
        "(http://reqrypt.org/windivert.html)" 2>&1
    exit 1
fi
for FILE in "$TOR.exe" 
do
    if [ ! -e "$FILE" ]
    then
        echo "ERROR: missing \"$FILE\"; download and extract from the Tor" \
            "Expert Bundle for Windows (https://www.torproject.org/)" 2>&1
        exit 1;
    fi
done

echo "Extracting WinDivert..."
unzip -o $WINDIVERT.zip

echo "Building Tallow..."
cd ..
make

echo "Copying \"tallow.exe\"..."
cp tallow.exe install/.
echo "Copying \"hosts.deny\"..."
cp hosts.deny install/.

for FILE in "$TOR.exe" \
       "$WINDIVERT/amd64/WinDivert64.sys" \
       "$WINDIVERT/x86/WinDivert32.sys" \
       "$WINDIVERT/x86/WinDivert.dll"
do
    echo "Copying \"$FILE\"..."
    cp contrib/"$FILE" install/.
done

echo "Building installation package..."
cd install

zip -r ../TallowBundle-files.zip *
cp ../install.nsi .

makensis install.nsi
mv TallowBundle-install.exe ..
cd ..

echo "Cleaning up..."
rm -f install/*
make clean

echo "Done!"

