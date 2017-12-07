import re
import ipaddress
import time
import os

from .resolver import Resolver, RoundRobinServer, RandomServer

_space_re = re.compile(b'\\s+')

class SystemResolver(Resolver):

    def __init__(self):
        self._servers = None
        self._servers_timestamp = None

        super(SystemResolver, self).__init__()

    def read_servers(self):
        servers = []
        with open('/etc/resolv.conf', 'rb') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(b'#'):
                    continue

                fields = _space_re.split(line)
                if len(fields) < 2:
                    continue

                if fields[0] != b'nameserver':
                    continue

                try:
                    addr = ipaddress.ip_address(fields[1].decode('ascii'))
                except ValueError:
                    continue

                servers.append((addr, 53))

        self._servers = RoundRobinServer(servers)

    def maybe_read_servers(self):
        now = time.time()
        if self._servers_timestamp is not None \
           and now - self._servers_timestamp < 30:
            return

        s = os.stat('/etc/resolv.conf')
        if self._servers_timestamp is None \
           or s.st_mtime > self._servers_timestamp:
            self._servers_timestamp = s.st_mtime
            self.read_servers()

    def lookup(self, query,
               should_cache=True, recursive=False, prefer_ipv6=False):
        self.maybe_read_servers()
        return super(SystemResolver, self).lookup(query, self._servers,
                                                  should_cache,
                                                  recursive, prefer_ipv6)
