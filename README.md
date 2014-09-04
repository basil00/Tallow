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

* [WinDivert-1.1.5-MINGW.zip](http://reqrypt.org/windivert.html).
* The following files extracted from the
  [Tor Expert Bundle](https://www.torproject.org/):
   - tor.exe

Then simply run the build.sh script.

Warnings
========

Tallow is beta quality software.  There may be bugs.

Currently Tallow makes no attempt to anonymize the content of traffic sent
*through* the Tor network.  This information may be used to de-anonymize you.
See [this
link](https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxyLeaks)
for more information.  Tallow *should not be relied on for strong anonymity*
unless you know what you are doing.

