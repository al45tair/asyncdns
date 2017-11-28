import asyncio
import asyncdns

def test_simple_lookup():
    """Test a simple lookup."""
    resolver = asyncdns.Resolver()
    loop = asyncio.get_event_loop()

    query = asyncdns.Query('www.google.com', asyncdns.A, asyncdns.IN)
    f = resolver.lookup(query, ('192.168.1.1', 53))

    loop.run_until_complete(f)

    print(f.result())
