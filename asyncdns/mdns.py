import asyncio
import socket
import weakref
import errno
import random
import struct
import time

from . import rr
from .constants import *
from .utils import decode_domain, decode_pascal_string, rcode_to_string, \
    build_dns_packet, MAX_PACKET_SIZE
from .wireformat import *
from .timeout import Timeout
from .resolver import Query, Reply

TIMEOUT   = 5
MAX_TRIES = 5
MAX_TTL   = 3 * 3600

class MDNSQuery(object):
    """Represents an active MDNS query."""

    def __init__(self, resolver, protocol, query, use_ipv6, unicast_reply):
        self.resolver = weakref.ref(resolver)
        self.protocol = weakref.ref(protocol)
        self.query = query
        self.use_ipv6 = use_ipv6
        self.unicast_reply = unicast_reply

        self._retry_count = 0
        self._waiters = []
        self._timeout = None

    def set_timeout(self, timeout):
        self.cancel_timeout()
        self._timeout = Timeout(timeout, self.timed_out)

    def cancel_timeout(self):
        if self._timeout is not None:
            self._timeout.cancel()
            self._timeout = None

    def timed_out(self):
        self.retry()

    def add_waiter(self, f):
        self._waiters.append(f)

    def fire_waiters(self, reply):
        self.cancel_timeout()
        for f in self._waiters:
            f.set_result(reply)
        self.resolver().query_done(self)

    def cancel_waiters(self):
        self.cancel_timeout()
        for f in self._waiters:
            f.cancel()
        self.resolver().query_done(self)

    def fail_waiters(self, exc):
        self.cancel_timeout()
        for f in self._waiters:
            f.set_exception(exc)
        self.resolver().query_done(self)

    def retry(self):
        self.cancel_timeout()

        self._retry_count += 1
        if self._retry_count >= MAX_TRIES:
            self.fire_waiters(Reply(QR, NXDOMAIN, [], [], []))
            return

        self.set_timeout(TIMEOUT)

        packet = build_dns_packet(0, self.query, False, True)

        if len(packet) > MAX_PACKET_SIZE:
            del packet
            self.fail_waiters(OSError(errno.ETOOBIG))

        self.protocol().send_packet(packet, self.use_ipv6)

_rng = random.SystemRandom()

class MulticastResolver(object):
    """Resolves queries using Multicast DNS (aka MDNS, aka Bonjour)."""

    def __init__(self):
        self._cache = {}
        self._queries = {}
        self._queue = []
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #self._socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)

        # Bind this socket - we need to do this on Windows or we get an
        # exception inside asyncio because it tries to use getsockname().
        while True:
            port = _rng.randrange(1024, 65536)
            try:
                self._socket.bind(('0.0.0.0', port))
                break
            except OSError as e:
                if e.errno not in (errno.EADDRINUSE, EADDRNOTAVAIL):
                    raise

        ip_mreq = b'\xe0\x00\x00\xfb\x00\x00\x00\x00'
        self._socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                ip_mreq)
        self.transport = None
        loop = asyncio.get_event_loop()
        f = asyncio.ensure_future(loop.create_datagram_endpoint(lambda: self,
                                                                sock=self._socket))

        def callback(f):
            if f.cancelled():
                self.cancel_all_waiters()
                return

            exc = f.exception()
            if exc is not None:
                self.fail_all_waiters(exc)
                return

        f.add_done_callback(callback)

    def close(self):
        self.cancel_all_waiters()
        self.transport.abort()

    def __del__(self):
        # On Windows, we can get a (harmless) RuntimeError here from trying
        # to abort the transport after the event loop has finished.
        try:
            self.close()
        except RuntimeError:
            pass
    
    def connection_made(self, transport):
        self.transport = transport
        for item in self._queue:
            transport.sendto(item[0], addr=item[1])
        self._queue = []

    def connection_lost(self, exc):
        if exc is not None:
            self.fail_all_waiters(exc)

    def datagram_received(self, data, addr):
        try:
            self.process_packet(data)
        except:
            pass

    def cancel_all_waiters(self):
        for q in self._queries.values():
            q.cancel_waiters()
        self._queries = {}

    def fail_all_waiters(self, exc):
        for q in self._queries.values():
            q.fail_waiters(exc)
        self._queries = {}

    def check_domain(self, query):
        for label in query.name.split(b'.'):
            if len(label) > 63:
                raise ValueError('DNS label too long')

    def lookup(self, query, use_ipv6=False, unicast_reply=False):
        """Perform an MDNS query."""
        f = asyncio.Future()

        # First see if the result is in the cache - if so, return it
        r = self._cache.get(query, None)
        if r is not None:
            (expiry, reply) = r

            now = time.time()

            if now >= expiry:
                del _cache[query]
            else:
                ttl_ms = expiry - now
                ttl_s = (ttl_ms + 999) / 1000

                reply.update_ttls(ttl_s)

                f.set_result(reply)

                return f

        # Add this future to the list waiting on this query
        r = self._queries.get(query, None)
        if r:
            r.add_waiter(f)
            return f

        # Finally, fire off a new query
        self.check_domain(query)

        new_query = MDNSQuery(self, self, query, use_ipv6, unicast_reply)
        self._queries[query] = new_query
        new_query.add_waiter(f)
        new_query.retry()

        return f

    def query_done(self, query):
        del self._queries[query.query]

    def flush_cache(self):
        self._cache = {}

    def cache_reply(self, query, reply):
        now = time.time()
        has_ttl = False
        min_ttl = 0

        # Find the minimum ttl
        for collection in (reply.answers, reply.authorities, reply.additional):
            for rr in collection:
                ttl = rr.ttl
                if not has_ttl or min_ttl > ttl:
                    has_ttl = True
                    min_ttl = ttl

        # Can't cache things with no TTL or with TTL zero
        if not has_ttl:
            return

        if min_ttl > MAX_TTL:
            min_ttl = MAX_TTL

        self._cache[query] = (now + min_ttl, reply)

    def decode_rr(self, packet, ptr, rcode):
        name, ptr = decode_domain(packet, ptr)

        utype, uclss, ttl, rdlen = struct.unpack(b'>HHLH', packet[ptr:ptr+10])

        ptr += 10

        if utype == OPT:
            rcode |= (ttl >> 20) & 0xff0
            ptr += rdlen
            return (rcode, None, None)

        result = rr.RR.decode(name, utype, uclss, ttl, packet, ptr, rdlen)
        ptr += rdlen

        return (rcode, result, ptr)

    def send_packet(self, packet, use_ipv6=False):
        if use_ipv6:
            addr = ('ff02::fb', 5353)
        else:
            addr = ('224.0.0.251', 5353)

        if self.transport is None:
            self._queue.append((packet, addr))
        else:
            self.transport.sendto(packet, addr=addr)

    def process_packet(self, packet):
        # Decode the header
        uid, flags, qdcount, ancount, nscount, arcount \
            = struct.unpack(b'>HHHHHH', packet[:12])

        # Ignore things other than queries
        if (flags & OPCODE_MASK) != QUERY:
            return

        # Find the rcode
        rcode = flags & RCODE_MASK

        # Ignore anything other than NOERROR
        if rcode != NOERROR:
            return

        # Decode the query
        domain, ptr = decode_domain(packet, 12)

        qtype, qclss = struct.unpack(b'>HH', packet[ptr:ptr+4])
        ptr += 4

        q = Query(domain, qtype, qclss)

        # Look for the query
        found_query = None
        found_mq = None
        for fq,p in self._queries.items():
            if fq == q:
                print('Found')
                found_query = fq
                found_mq = p
                break

        # Decode the reply
        answers = []
        authorities = []
        additional = []

        for count, array in [(ancount, answers),
                             (nscount, authorities),
                             (arcount, additional)]:
            for n in range(0, count):
                rcode, rr, ptr = self.decode_rr(packet, ptr, rcode)
                if rr is not None:
                    array.append(rr)

            reply = Reply(flags,
                          rcode,
                          answers,
                          authorities,
                          additional)

        # For each answer, see if we can find a query that matches
        for answer in answers:
            for fq,p in self._queries.items():
                if fq.name.lower() == answer.name.lower() \
                   and (fq.q_type == ANY or fq.q_type == answer.rr_type) \
                   and (fq.q_class == ANY or fq.q_class == answer.rr_class):
                    self.cache_reply(fq, reply)
                    p.fire_waiters(reply)
