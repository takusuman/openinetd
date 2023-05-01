# OpenInetd

![OpenInetd logo](https://i.ibb.co/2WMvpyk/Open-Inetd-1-1-1.png)

(An attempt to create) a portable ``inetd``(8) implementation from OpenBSD.  
Some features have been merged from the NetBSD source tree.

This is a work in progress.

## Why?

As I use to say: competition is good, principally if it's offering more freedom.  
This project aims to provide a good, secure and free alternative to other
``inetd``(8) implementations on Linux (and probably on other UNIX-compatible
systems) --- for instance, GNU Inetutils' inetd, xinetd, etc.

## Where does it run?

Currently, it's running on Slackware Linux 15.0, with GNU C Library 2.33, libbsd
0.11.6, libevent 2.1.12 and libtirpc 1.3.2.   
I do not recommend using this unless you aim to port it to your system and/or
fix it to be used in production. If possible, send your patches with a [pull
request](https://github.com/takusuman/openinetd/pulls).

By the way, it would be great if we could get rid of the dependency on libbsd
and maybe even make libevent and libtirpc "built-in" on the source code tree. It
would make a lot easier to build and use this on many platforms without having
to compile each package separately.

## Bugs

When having an interruption signal (``SIGINT``), the ``die()`` function, for
some reason, doesn't ``unlink``(2) the P.ID. file at ``/var/run`` --- a.k.a
``PID_FILE``.  
There's probably a lot more.

## Licence

BSD 3-Clause

``setproctitle.c`` and ``discard_stupid_environment()`` come from netkit
0.17, patched by the USAGI project.

``strlcpy.c`` comes from the OpenBSD source tree, slightly edited.

``bsd-closefrom.c`` comes from the OpenSSH source tree, slightly edited.
