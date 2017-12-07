import asyncio
import asyncdns
import socket
import pytest
import errno

def test_simple_lookup():
    """Test a simple lookup using Google's public DNS"""
    resolver = asyncdns.Resolver()
    loop = asyncio.get_event_loop()

    query = asyncdns.Query('www.google.com', asyncdns.A, asyncdns.IN)
    f = resolver.lookup(query, ('8.8.8.8', 53))

    loop.run_until_complete(f)

    print(f.result())

def test_simple_lookup_ipv6():
    """Test a simple lookup over IPv6 using Google's public DNS"""
    resolver = asyncdns.Resolver()
    loop = asyncio.get_event_loop()

    query = asyncdns.Query('www.google.com', asyncdns.A, asyncdns.IN)
    f = resolver.lookup(query, ('2001:4860:4860::8888', 53))

    try:
        loop.run_until_complete(f)
    except OSError as e:
        if e.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
            pytest.skip('No IPv6 connectivity')
        else:
            raise

    print(f.result())
