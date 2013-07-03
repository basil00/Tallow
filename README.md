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

Building
========

To build TorWall you need:
* [WinDivert-1.0.5-MINGW](http://reqrypt.org/windivert.html).
* [Privoxy.exe](http://www.privoxy.org/) (extract from installation package).
* [Tor.exe](https://www.torproject.org/) (extract from installation package).
* MinGW w64 cross-compiler for Linux.

TODO

Warning
=======

TorWall is *experimental* software.  It should not be relied on if you need
strong anonymity.  For this you should still use the TorBrowserBundle.

