.. Resolvers

What are Resolvers?
===================

In ``asyncdns``, Resolvers are the objects that are responsible for taking
:py:class:`Query` objects and returning :py:class:`Reply` objects
corresponding to those queries.

Resolvers don't derive from a single base class, as some of them work quite
differently to others.  Instead, they all implement the following two methods:

.. py:function:: close()

  Cancel all in-progress lookups and shut down the resolver.

.. py:function:: lookup(query)

  :param query: The :py:class:`Query` to process.
  :retval: An :py:class:`asyncio.Future` that will complete with a
           :py:class:`Reply`.

Resolvers are guaranteed to cancel lookups that are in progress when the
resolver itself is destroyed.  Active lookups do not keep a resolver alive.

Individual resolvers may support additional parameters for their
:py:meth:`lookup` method, but those parameters are generally specific to the
workings of the resolver in question.

Resolver
--------

.. py:class:: Resolver

   The core DNS resolver.  This class holds all of the code to perform normal
   DNS queries, including recursive resolution, and maintains its own request
   cache, so that repeatedly querying for the same record won't result in
   unnecessary network traffic or delay.

   .. py:method:: lookup(query, servers=None, should_cache=True,
                         recursive=False, prefer_ipv6=False, force_tcp=False)

     Perform a DNS lookup.

     :param query: The :py:class:`Query` to resolve.
     :param servers: See discussion below.
     :param should_cache: Setting this to False disables the
                          :py:class:`Resolver` cache.
     :param recursive: Whether to perform recursive lookups.
     :param prefer_ipv6: When doing recursive lookup, prefer servers that talk
                         over IPv6.
     :param force_tcp: Prevents the resolver from using UDP for queries that
		       are short enough to fit.
     :retval: An :py:class:`asyncio.Future` that will complete with a
              :py:class:`Reply`.

     The ``servers`` parameter can be:

     * An (*address*, *port*) tuple.
     * A :py:class:`list` of (*address*, *port*) tuples, which will be
       used randomly.
     * An iterable of some sort that yields (*address*, *port*) tuples.  Note
       that if the iterable raises StopIteration, any in-progress queries will
       fail with the StopIteration exception.
     * ``None``, in which case the resolver will be recursive (regardless of
       the setting of the ``recursive`` parameter) and will start with the
       global root servers.  We recommend not using this feature unless
       absolutely necessary, as it puts additional load on the root servers
       and it's usually better to talk to your own nameserver or use one provided
       by your ISP or infrastructure platform.

     ``asyncdns`` provides two useful iterables, :py:class:`RandomServer` and
     :py:class:`RoundRobinServer`, both of which provide an infinite stream of
     tuples given a list of server addresses.

   .. py:function:: flush_cache()

      Flushes the resolver's cache.

HostsResolver
-------------

.. py:class:: HostsResolver

   Resolves names using the contents of ``/etc/hosts`` (or, on Windows,
   ``\Windows\System32\drivers\etc\hosts``).

   .. py:method:: lookup(query)

     :param query: The :py:class:`Query` to resolve.
     :retval: An :py:class:`asyncio.Future` that will complete with a
              :py:class:`Reply`.

     This method only supports A, AAAA and PTR queries.  In addition to names
     listed in ``/etc/hosts``, it knows about the ``.in-addr.arpa`` and
     ``.ip6.arpa`` pseudo-zones.

     The :py:class:`HostsResolver` will automatically re-read ``/etc/hosts``
     if it has changed, but only if the last time it was read was more than 30
     seconds ago.

MulticastResolver
-----------------

.. py:class:: MulticastResolver

   Resolves queries using Multicast DNS (aka MDNS).  You don't need to have
   Apple's mdnsResponder software installed to use this - it will work on any
   system that can run Python and that supports IP multicast.

   .. py:method:: lookup(query, use_ipv6=False, unicast_reply=False)

     :param query: The :py:class:`Query` to resolve.
     :param use_ipv6: Whether to multicast using IPv6 or not.  The default is
                      to use IPv4.
     :param unicast_reply: Whether to request that the reply be sent via
                           unicast. This is intended to reduce multicast
                           traffic.
     :retval: An :py:class:`asyncio.Future` that will complete with a
              :py:class:`Reply`.

SystemResolver
--------------

:py:class:`SystemResolver` is actually a "class cluster", in that there are
separate implementations for Darwin/Mac OS X/macOS, Windows, and generic
UNIX/Linux.  The idea of :py:class:`SystemResolver` is that it works like
:py:class:`Resolver`, but uses the system configured nameservers (and will
automatically update its list of nameservers should the system configuration
change).

There are some limitations here: the UNIX/Linux generic implementation works
by reading ``/etc/resolv.conf``, so any other configuration mechanism that
might be in use will be ignored, while the Windows version uses Windows APIs
that appear to be limited to returning IPv4 nameservers only.  On Windows,
there doesn't seem to be a mechanism to spot changes to the configuration, so
we re-read it at most once every 30 seconds; on UNIX/Linux, we watch
the timestamp on ``/etc/resolv.conf``, again, at most once every 30 seconds.
Some people have suggested using ``res_ninit()`` on UNIX rather than directly
reading ``/etc/resolv.conf``; that's certainly a possibility, but if
``/etc/resolv.conf`` isn't being used to configure the nameservers, we'd end
up in the same situation as on Windows, where we have no way to tell if the
server settings have been updated.

.. py:class:: SystemResolver

   .. py:method:: lookup(query, servers=None, should_cache=True,
                         recursive=False, prefer_ipv6=False, force_tcp=False)

     Perform a DNS lookup.

     :param query: The :py:class:`Query` to resolve.
     :param should_cache: Setting this to False disables the
                          :py:class:`Resolver` cache.
     :param recursive: Whether to perform recursive lookups.
     :param prefer_ipv6: When doing recursive lookup, prefer servers that talk
                         over IPv6.
     :param force_tcp: Prevents the resolver from using UDP for queries that
		       are short enough to fit.
     :retval: An :py:class:`asyncio.Future` that will complete with a
              :py:class:`Reply`.

SmartResolver
-------------

:py:class:`SmartResolver` is a convenience class that accepts a query and
determines which of the other resolvers to use to process it.  Specifically:

  * It first tries :py:class:`HostsResolver`, which means the hosts file can
    override resolution the way people expect.
  * If that fails and the query is for a name ending ``.local``, it uses
    :py:class:`MulticastResolver`.
  * Otherwise, it uses :py:class:`SystemResolver`.

N.B. Pay attention to the security implications of using
:py:class:`MulticastResolver` here; if you are using a server platform where
multicast isn't appropriately restricted, this could open up a security hole
that causes you to send data to an attacker's system instead of the one you
wanted to.
