import asyncio

from .constants import *
from .wireformat import *
from .hosts import HostsResolver
from .system import SystemResolver
from .mdns import MulticastResolver

class SmartResolver(object):

    def __init__(self):
        self.sys = SystemResolver()
        self.hosts = HostsResolver()
        self.mdns = MulticastResolver()

    def lookup(self, query, prefer_ipv6=None, should_cache=True, recursive=False):
        outer = asyncio.Future()

        # First, try looking in /etc/hosts
        f = self.hosts.lookup(query)

        def callback(f):
            if f.cancelled():
                outer.cancel()
                return

            exc = f.exception()
            if exc is not None:
                outer.set_exception(exc)
                return

            reply = f.result()

            if reply.rcode == NXDOMAIN:
                if query.name.endswith(b'.local'):
                    f2 = self.mdns.lookup(query, use_ipv6=prefer_ipv6)
                else:
                    f2 = self.sys.lookup(query, prefer_ipv6,
                                         should_cache, recursive)

                def cb2(f):
                    if f.cancelled():
                        outer.cancel()
                        return

                    exc = f.exception()
                    if exc is not None:
                        outer.set_exception(exc)
                        return

                    outer.set_result(f.result())

                f2.add_done_callback(cb2)
            else:
                outer.set_result(reply)

        f.add_done_callback(callback)

        return outer
