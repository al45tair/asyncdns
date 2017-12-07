asyncdns - Pure Python asynchronous DNS for asyncio
===================================================

.. image:: https://travis-ci.org/al45tair/asyncdns.svg?branch=master
    :target: https://travis-ci.org/al45tair/asyncdns

.. image:: https://readthedocs.org/projects/asyncdns/badge/?version=latest
    :target: http://asyncdns.readthedocs.io/en/latest/?badge=latest

What is this?
=============

``asyncdns`` is a pure Python asynchronous DNS resolver implementation written
on top of asyncio.  It doesn't require any external libraries, and it doesn't
use threads or blocking functions.

Usage
=====

``asyncdns`` doesn't have an equivalent to the widely used ``gethostbyname()``
or ``getaddrinfo()`` functions.  Instead, you use it by constructing a
``Query`` object specifying the DNS query you wish to run, then pass it to a
``Resolver`` to actually perform the query.

There are a handful of built-in resolvers, but for demonstration purposes the
easiest one to use is the ``SmartResolver``, which automatically makes use of
``/etc/hosts``, multicast DNS and regular DNS as appropriate.

For instance, do a simple lookup for an A record::

  >>> import asyncdns, asyncio
  >>> resolver = asyncdns.SmartResolver()
  >>> loop = asyncio.get_event_loop()
  >>> query = asyncdns.Query('www.example.com', asyncdns.A, asyncdns.IN)
  >>> f = resolver.lookup(query)
  >>> loop.run_until_complete(f)
  >>> print(f.result())
  ;; No error (RD, RA)
  ; 1 answers:
  www.example.com	54950	IN	A	93.184.216.34
  ; 0 authorities:
  ; 0 additional:

Note that you may or may not want to use ``SmartResolver`` in your code,
depending on your requirements - it probably isn't a good idea using multicast
DNS on an untrusted network, for instance.
