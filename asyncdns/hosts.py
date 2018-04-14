import ipaddress
import re
import os
import os.path
import time
import asyncio
import sys

from . import rr

from .constants import *
from .wireformat import *
from .resolver import Query, Reply

if sys.platform == 'win32':
    _hosts_path = os.path.join(os.environ['WINDIR'],
                               '\\System32\\drivers\\etc\\hosts')
else:
    _hosts_path = '/etc/hosts'

_space_re = re.compile(b'\\s+')
class HostsResolver(object):
    """Resolves queries using the entries in /etc/hosts."""

    def __init__(self):
        self._hosts_timestamp = None
        self._hosts = {}
        self._addrs = {}

    def close(self):
        pass
    
    def check_domain(self, query):
        for label in query.name.split(b'.'):
            if len(label) > 63:
                raise ValueError('DNS label too long')

    def read_hosts(self):
        self._hosts = {}
        self._addrs = {}
        with open(_hosts_path, 'rb') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith(b'#'):
                    continue
                fields = _space_re.split(line)
                if len(fields) < 2:
                    continue
                name = fields[1]
                try:
                    addr = ipaddress.ip_address(fields[0].decode('ascii'))
                except ValueError:
                    continue

                name = name.lower()
                l = self._hosts.get(name, None)
                if l is None:
                    l = []
                    self._hosts[name] = l
                l.append(addr)
                self._addrs[addr] = name

        # Always add localhost if it isn't there already
        lhv4 = ipaddress.ip_address('127.0.0.1')
        lhv6 = ipaddress.ip_address('::1')
        self._hosts[b'localhost'] = [ lhv4, lhv6 ]
        self._addrs[lhv4] = b'localhost'
        self._addrs[lhv6] = b'localhost'

    def maybe_read_hosts(self):
        now = time.time()
        if self._hosts_timestamp is not None \
           and now - self._hosts_timestamp < 30:
            return

        s = os.stat(_hosts_path)
        if self._hosts_timestamp is None \
           or s.st_mtime > self._hosts_timestamp:
            self._hosts_timestamp = s.st_mtime
            self.read_hosts()

    def lookup(self, query):
        f = asyncio.Future()

        self.maybe_read_hosts()

        if query.name.endswith(b'.in-addr.arpa'):
            addr = b'.'.join(query.name[:-13].split(b'.')[::-1])
            try:
                addr = ipaddress.ip_address(addr.decode('ascii'))
            except ValueError:
                addr = None

            hostname = self._addrs.get(addr, None)
            if addr is None or hostname is None:
                reply = Reply(QR, NXDOMAIN, [], [], [])
            elif query.q_class in (IN, ANY) and query.q_type in (PTR, ANY):
                answers = [rr.PTR(query.name, 30, hostname)]
                host = self._hosts[hostname]
                additional = []
                for addr in host:
                    if isinstance(addr, ipaddress.IPv4Address):
                        additional.append(rr.A(hostname, 30, addr))
                    elif isinstance(addr, ipaddress.IPv6Address):
                        additional.append(rr.AAAA(hostname, 30, addr))
                reply = Reply(QR, NOERROR, answers, [], additional)
            else:
                reply = Reply(QR, NOERROR, [], [], [])
        elif query.name.endswith(b'.ip6.arpa'):
            addr = b''.join(query.name[:-9].split(b'.')[::-1])
            addr = b':'.join([addr[n:n+4] for n in range(0,len(addr),4)])
            try:
                addr = ipaddress.ip_address(addr.decode('ascii'))
            except ValueError:
                addr = None

            hostname = self._addrs.get(addr, None)
            if addr is None or hostname is None:
                reply = Reply(QR, NXDOMAIN, [], [], [])
            elif query.q_class in (IN, ANY) and query.q_type in (PTR, ANY):
                answers = [rr.PTR(query.name, 30, hostname)]
                host = self._hosts[hostname]
                additional = []
                for addr in host:
                    if isinstance(addr, ipaddress.IPv4Address):
                        additional.append(rr.A(hostname, 30, addr))
                    elif isinstance(addr, ipaddress.IPv6Address):
                        additional.append(rr.AAAA(hostname, 30, addr))
                reply = Reply(QR, NOERROR, answers, [], additional)
            else:
                reply = Reply(QR, NOERROR, [], [], [])
        elif query.q_class in (IN, ANY) and query.q_type == A:
            host = self._hosts.get(query.name, None)
            if host is None:
                reply = Reply(QR, NXDOMAIN, [], [], [])
            else:
                answers = []
                additional = []
                for addr in host:
                    if isinstance(addr, ipaddress.IPv4Address):
                        answers.append(rr.A(query.name, 30, addr))
                    elif isinstance(addr, ipaddress.IPv6Address):
                        additional.append(rr.AAAA(query.name, 30, addr))
                reply = Reply(QR, NOERROR, answers, [], additional)
        elif query.q_class in (IN, ANY) and query.q_type == AAAA:
            host = self._hosts.get(query.name, None)
            if host is None:
                reply = Reply(QR, NXDOMAIN, [], [], [])
            else:
                answers = []
                additional = []
                for addr in host:
                    if isinstance(addr, ipaddress.IPv4Address):
                        additional.append(rr.A(query.name, 30, addr))
                    elif isinstance(addr, ipaddress.IPv6Address):
                        answers.append(rr.AAAA(query.name, 30, addr))
                reply = Reply(QR, NOERROR, answers, [], additional)
        elif query.q_class in (IN, ANY) and query.q_type == ANY:
            host = self._hosts.get(query.name, None)
            if host is None:
                reply = Reply(QR, NXDOMAIN, [], [], [])
            else:
                answers = []
                for addr in host:
                    if isinstance(addr, ipaddress.IPv4Address):
                        answers.append(rr.A(query.name, 30, addr))
                    elif isinstance(addr, ipaddress.IPv6Address):
                        answers.append(rr.AAAA(query.name, 30, addr))
                reply = Reply(QR, NOERROR, answers, [], [])
        else:
            if query.name in self._hosts:
                reply = Reply(QR, NOERROR, [], [], [])
            else:
                reply = Reply(QR, NXDOMAIN, [], [], [])

        f.set_result(reply)

        return f
