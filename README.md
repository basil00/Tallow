Tallow (formally TorWall) - Transparent Tor for Windows
=======================================================

Tallow is a small program that redirects all outbound traffic from a Windows
machine via the Tor anonymity network.  Any traffic that cannot be handled by
Tor, e.g. UDP, is blocked.  Tallow also intercepts and handles DNS requests
preventing potential leaks.

Tallow has several applications, including:

* "Tor-ifying" applications there were never designed to use Tor
* Filter circumvention -- if you wish to bypass a local filter and are
  not so concerned about anonymity
* *Better-than-nothing-Tor* -- Some Tor may be better than no Tor.

Note that, by itself, Tallow is not designed to be a complete strong anonymity
solution.  See the warnings below.

Usage
=====

Using the Tallow GUI, simply press the big "Tor" button to start redirecting
traffic via the Tor network.  Press the button again to stop Tor redirection.
Note that your Internet connection may be temporarily interrupted each time
you toggle the button.

To test if Tor redirection is working, please visit the following site:
[https://check.torproject.org](https://check.torproject.org).

Technical
=========

Tallow uses the following configuration to connect to the Internet:

    +-----------+        +-----------+        +----------+
    |    PC     |------->|    TOR    |------->|  SERVER  |
    |  a.b.c.d  |<-------|  a.b.c.d  |<-------|  x.y.z.w |
    +-----------+        +-----------+        +----------+

Here (a.b.c.d) represents the local address, and (x.y.z.w) represents a remote
server.

Tallow uses [WinDivert](http://reqrypt.org/windivert.html) to intercept
all traffic to/from your PC.  Tallow handles two main traffic types: DNS
traffic and TCP streams.

DNS queries are intercepted and handled by Tallow itself.  Instead of finding
the real IP address of a domain, Tallow generates a pseudo-random "fake"
domain (in the range 44.0.0.0/24) and uses this address in the query response.
The fake-IP is also associated with the domain and recorded in a table for
later reference.  The alternative would be to look up the real IP via the Tor
(which supports DNS).  However, since Tallow uses SOCKS4a the real IP is not
necessary.  Handling DNS requests locally is significantly faster.

TCP connections are also intercepted.  Tallow "reflects" outbound TCP connects
into inbound SOCKS4a connects to the Tor program.  If the connection is to
a fake-IP, Tallow looks up the corresponding domain and uses this for the
SOCKS4a connection.  Otherwise the connection is blocked (by default) or a
SOCKS4 direct connection via Tor is used.  Connecting TCP to SOCKS4(a) is
possible with a bit of magic (see redirect.c).

All other traffic is simply blocked.  This includes all inbound (non-Tor)
traffic and outbound traffic that is not TCP nor DNS.  In addition, Tallow
blocks all domains listed in the hosts.deny file.  This includes domains such
as Windows update, Windows phone home, and some common ad servers, to help
prevent Tor bandwidth wastage.  It is possible to edit and customize your
hosts.deny file as you see fit.

Note that Tallow does not intercept TCP ports 9001 and 9030 that are used by
Tor.  As a side-effect, Tallow will not work on any other program that uses
these ports.

History
=======

Tallow was derived from the TorWall prototype (where "tallow" is an
anagram of "torwall" minus the 'r').

Tallow works slightly differently, and aims to redirect all traffic rather
than just HTTP port 80.  Also, unlike the prototype, Tallow does *not* use
Privoxy nor does it alter the content of any TCP streams in any way (see
warnings below).

Building
========

To build Tallow you need the MinGW cross-compiler for Linux.

You also need to download and place the following external dependencies and
place them in the contrib/ directory:

* [WinDivert-1.2.0-rc-MINGW.zip](http://reqrypt.org/windivert.html).
* [tor-win32-0.2.6.9.zip](https://www.torproject.org/).

Then simply run the build.sh script.

TODOS
=====

* *More comprehensive hosts.deny*:
  By default Windows will "phone home" on a regular basis for various
  reasons.  Tallow attempts to block most of this traffic by default
  via the *hosts.deny* file.  However, it is unclear how
  comprehensive the current blacklist really is.  Suggestions for new
  entries are welcome.

Warnings
========

Tallow is beta quality software.  There may be bugs.

Currently Tallow makes no attempt to anonymize the content of traffic sent
*through* the Tor network.  This information may be used to de-anonymize you.
See [this
link](https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxyLeaks)
for more information.  Tallow *should not be relied on for strong anonymity*
unless you know what you are doing.

