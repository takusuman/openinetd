# OpenInetd

(An attempt to create) a portable ``inetd``(8) implementation from OpenBSD.  
Some features have been merged from the NetBSD source tree.

This is a work in progress

# Bugs

When having an interruption signal (``SIGINT``), the ``die()`` function, for
some reason, doesn't ``unlink``(2) the P.ID. file at ``/var/run`` --- a.k.a
``PID_FILE``.  
There's must have a lot more, but I haven't discovered it yet.

# Licence

BSD 3-Clause

``setproctitle.c`` and ``discard_stupid_environment()`` come from netkit
0.17, patched by the USAGI project.

``strlcpy.c`` comes from the OpenBSD source tree, slightly edited.

``bsd-closefrom.c`` comes from the OpenSSH source tree, slightly edited.
