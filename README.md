TorWall
=======

TorWall -- transparent Tor for Windows.

In a nutshell, TorWall sets up the following configuration:

    +-----------+        +-----------+        +-----------+        +----------+
    |  BROWSER  |------->|  PRIVOXY  |------->|    TOR    |------->|  SERVER  |
    |  a.b.c.d  |<-------|  a.b.c.d  |<-------|  a.b.c.d  |<-------|  x.y.z.w |
    +-----------+        +-----------+        +-----------+        +----------+

Here (a.b.c.d) represents the local address, and (x.y.z.w) represents a remote
web server.

TorWall works by redirecting your web traffic to a local instance of
Privoxy/Tor.  This configuration is completely transparent to the web browser,
i.e. the web browser sees a normal internet connection (albeit slower).

Unlike the TorBrowserBundle, TorWall works with any browser, including Chrome,
Safari, Opera, Firefox, Internet Explorer, etc.  This may have some
disadvantages too, e.g. some browsers may leak information.  To help mitigate
this risk, TorWall routes all web traffic through Privoxy.

To prevent non-browser related leaks, TorWall also blocks all non-Tor traffic
when it is running.  Furthermore, TorWall poisons DNS traffic with fake
responses to prevent leaks whilst still maintaining transparency for the
browser.

Limitations
===========

Currently HTTPS (port 443) is not supported.  This is because Privoxy cannot
intercept such traffic.

Support for HTTPS in "passthru" mode may be added later.

Building
========

To build TorWall you need MinGW w64 cross-compiler for Linux.

You also need to download and place the following external dependencies and
place them in the contrib/ directory:

* [WinDivert-1.0.5-MINGW.zip](http://reqrypt.org/windivert.html).
* The following files extracted from the [Privoxy](http://www.privoxy.org/)
  installation package: 
   - privoxy.exe
   - mgwz.dll
* The following files extracted from the
  [Tor Browser Bundle](https://www.torproject.org/):
   - tor.exe
   - libaey32.dll
   - sslea32.dll

Then simply run the build.sh script.

Warning
=======

TorWall is *experimental* software.  It should not be relied on if you need
strong anonymity.  For this you should still use the TorBrowserBundle.

