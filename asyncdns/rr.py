import ipaddress
import struct
import encodings

from . import constants, utils
from .utils import rrclass_to_string, rrtype_to_string, escape_string, \
     domain_to_unicode, domain_from_unicode

_rr_registry = {}

class RR(object):
    def __init__(self, name, rr_type, rr_class, ttl):
        self.name = name
        self.unicode_name = domain_to_unicode(name)
        self.rr_type = rr_type
        self.rr_class = rr_class
        self.ttl = ttl

    def __str__(self):
        return '{}\t{}\t{}\t{}'.format(self.name,
                                       self.ttl,
                                       rrclass_to_string(self.rr_class),
                                       rrtype_to_string(self.rr_type))

    @staticmethod
    def register(rr_type, rr_class, pyclass):
        """Register a new RR type."""
        _rr_registry[(rr_class, rr_type)] = pyclass

    @staticmethod
    def decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen):
        pyclass = _rr_registry.get((rr_class, rr_type),
                                   _rr_registry.get((constants.ANY, rr_type),
                                                    Unknown))
        return pyclass.decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen)

def rr(rr_type, rr_class):
    def inner(clss):
        RR.register(rr_type, rr_class, clss)
        return clss
    return inner

@rr(constants.A, constants.IN)
class A(RR):
    def __init__(self, name, ttl, address):
        super(A, self).__init__(name, constants.A, constants.IN, ttl)
        self.address = address

    def __str__(self):
        return '{}\t{}\t{}\t{}\t{}'.format(escape_string(self.name),
                                           self.ttl,
                                           rrclass_to_string(self.rr_class),
                                           rrtype_to_string(self.rr_type),
                                           self.address)

    @staticmethod
    def decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen):
        addr = ipaddress.IPv4Address(packet[ptr:ptr+4])
        return A(name, ttl, addr)

@rr(constants.AAAA, constants.IN)
class AAAA(RR):
    def __init__(self, name, ttl, address):
        super(AAAA, self).__init__(name, constants.AAAA, constants.IN, ttl)
        self.address = address

    def __str__(self):
        return '{}\t{}\t{}\t{}\t{}'.format(escape_string(self.name),
                                           self.ttl,
                                           rrclass_to_string(self.rr_class),
                                           rrtype_to_string(self.rr_type),
                                           self.address)

    @staticmethod
    def decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen):
        addr = ipaddress.IPv6Address(packet[ptr:ptr+16])
        return AAAA(name, ttl, addr)

@rr(constants.CNAME, constants.IN)
class CNAME(RR):
    def __init__(self, name, ttl, cname):
        super(CNAME, self).__init__(name, constants.CNAME, constants.IN, ttl)
        self.cname = cname
        self.unicode_cname = domain_to_unicode(cname)

    def __str__(self):
        return '{}\t{}\t{}\t{}\t{}'.format(escape_string(self.name),
                                           self.ttl,
                                           rrclass_to_string(self.rr_class),
                                           rrtype_to_string(self.rr_type),
                                           escape_string(self.cname))

    @staticmethod
    def decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen):
        cname, _ = utils.decode_domain(packet, ptr)
        return CNAME(name, ttl, cname)

@rr(constants.HINFO, constants.IN)
class HINFO(RR):
    def __init__(self, name, ttl, cpu, os):
        super(HINFO, self).__init__(name, constants.HINFO, constants.IN, ttl)
        self.cpu = cpu
        self.os = os

    def __str__(self):
        return '{}\t{}\t{}\t{}\t{}\t{}'.format(escape_string(self.name),
                                               self.ttl,
                                               rrclass_to_string(self.rr_class),
                                               rrtype_to_string(self.rr_type),
                                               escape_string(self.cpu),
                                               escape_string(self.os))

    @staticmethod
    def decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen):
        cpu, ptr = utils.decode_pascal_string(packet, ptr)
        os, ptr = utils.decode_pascal_string(packet, ptr)
        return HINFO(name, ttl, cpu, os)

@rr(constants.MB, constants.IN)
class MB(RR):
    def __init__(self, name, ttl, host):
        super(MB, self).__init__(name, constants.MB, constants.IN, ttl)
        self.host = host
        self.unicode_host = domain_to_unicode(host)

    def __str__(self):
        return '{}\t{}\t{}\t{}\t{}'.format(escape_string(self.name),
                                           self.ttl,
                                           rrclass_to_string(self.rr_class),
                                           rrtype_to_string(self.rr_type),
                                           escape_string(self.host))

    @staticmethod
    def decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen):
        host, _ = utils.decode_domain(packet, ptr)
        return MB(name, ttl, host)

@rr(constants.MF, constants.IN)
class MF(RR):
    def __init__(self, name, ttl, host):
        super(MF, self).__init__(name, constants.MF, constants.IN, ttl)
        self.host = host
        self.unicode_host = domain_to_unicode(host)

    def __str__(self):
        return '{}\t{}\t{}\t{}\t{}'.format(escape_string(self.name),
                                           self.ttl,
                                           rrclass_to_string(self.rr_class),
                                           rrtype_to_string(self.rr_type),
                                           escape_string(self.host))

    @staticmethod
    def decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen):
        host, _ = utils.decode_domain(packet, ptr)
        return MF(name, ttl, host)

@rr(constants.MG, constants.IN)
class MG(RR):
    def __init__(self, name, ttl, mailbox):
        super(MG, self).__init__(name, constants.MG, constants.IN, ttl)
        self.mailbox = mailbox
        self.unicode_mailbox = domain_to_unicode(mailbox)

    def __str__(self):
        return '{}\t{}\t{}\t{}\t{}'.format(escape_string(self.name),
                                           self.ttl,
                                           rrclass_to_string(self.rr_class),
                                           rrtype_to_string(self.rr_type),
                                           escape_string(self.mailbox))

    @staticmethod
    def decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen):
        mailbox, _ = utils.decode_domain(packet, ptr)
        return MG(name, ttl, mailbox)

@rr(constants.MINFO, constants.IN)
class MINFO(RR):
    def __init__(self, name, ttl, rmailbox, emailbox):
        super(MINFO, self).__init__(name, constants.MINFO, constants.IN, ttl)
        self.rmailbox = rmailbox
        self.emailbox = emailbox
        self.unicode_rmailbox = domain_to_unicode(rmailbox)
        self.unicode_emailbox = domain_to_unicode(emailbox)

    def __str__(self):
        return '{}\t{}\t{}\t{}\t{}\t{}'.format(escape_string(self.name),
                                               self.ttl,
                                               rrclass_to_string(self.rr_class),
                                               rrtype_to_string(self.rr_type),
                                               escape_string(self.rmailbox),
                                               escape_string(self.emailbox))

    @staticmethod
    def decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen):
        rmailbox, ptr = utils.decode_domain(packet, ptr)
        emailbox, ptr = utils.decode_domain(packet, ptr)
        return MINFO(name, ttl, rmailbox, emailbox)

@rr(constants.MR, constants.IN)
class MR(RR):
    def __init__(self, name, rr_class, ttl, mailbox):
        super(MR, self).__init__(name, constants.MR, rr_class, ttl)
        self.mailbox = mailbox

    def __str__(self):
        return '{}\t{}\t{}\t{}\t{}'.format(escape_string(self.name),
                                           self.ttl,
                                           rrclass_to_string(self.rr_class),
                                           rrtype_to_string(self.rr_type),
                                           escape_string(self.mailbox))

    @staticmethod
    def decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen):
        mailbox, _ = utils.decode_domain(packet, ptr)
        return MG(name, ttl, mailbox)

@rr(constants.MX, constants.IN)
class MX(RR):
    def __init__(self, name, ttl, preference, exchange):
        super(MX, self).__init__(name, constants.MX, constants.IN, ttl)
        self.preference = preference
        self.exchange = exchange
        self.unicode_exchange = domain_to_unicode(exchange)

    def __str__(self):
        return '{}\t{}\t{}\t{}\t{}\t{}'.format(escape_string(self.name),
                                               self.ttl,
                                               rrclass_to_string(self.rr_class),
                                               rrtype_to_string(self.rr_type),
                                               self.preference,
                                               escape_string(self.exchange))

    @staticmethod
    def decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen):
        preference, = struct.unpack(b'>H', packet[ptr:ptr+2])
        exchange, _ = utils.decode_domain(packet, ptr+2)
        return MX(name, ttl, preference, exchange)

@rr(constants.NUL, constants.IN)
class NUL(RR):
    def __init__(self, name, ttl, data):
        super(NULL, self).__init__(name, constants.NUL, constants.IN, ttl)
        self.data = data

    def __str__(self):
        return '{}\t{}\t{}\t{}\t({})'.format(escape_string(self.name),
                                             self.ttl,
                                             rrclass_to_string(self.rr_class),
                                             rrtype_to_string(self.rr_type),
                                             utils.base64(self.data))

    @staticmethod
    def decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen):
        return NUL(name, ttl, packet[ptr:ptr+rdlen])

@rr(constants.NS, constants.IN)
class NS(RR):
    def __init__(self, name, ttl, host):
        super(NS, self).__init__(name, constants.NS, constants.IN, ttl)
        self.host = host
        self.unicode_host = domain_to_unicode(host)

    def __str__(self):
        return '{}\t{}\t{}\t{}\t{}'.format(escape_string(self.name),
                                           self.ttl,
                                           rrclass_to_string(self.rr_class),
                                           rrtype_to_string(self.rr_type),
                                           escape_string(self.host))

    @staticmethod
    def decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen):
        host, _ = utils.decode_domain(packet, ptr)
        return NS(name, ttl, host)

@rr(constants.PTR, constants.IN)
class PTR(RR):
    def __init__(self, name, ttl, dname):
        super(PTR, self).__init__(name, constants.PTR, constants.IN, ttl)
        self.address = None

        try:
            if name.endswith(b'.in-addr.arpa'):
                addr = b'.'.join(name[:-13].split(b'.')[::-1])
                self.address = ipaddress.ip_address(addr.decode('ascii'))
            elif name.endswith(b'.ip6.arpa'):
                addr = b'.'.join(name[:-9].split(b'.')[::-1])
                addr = b':'.join([addr[n:n+4] for n in range(0,len(addr),4)])
                self.address = ipaddress.ip_address(addr.decode('ascii'))
        except ValueError:
            pass

        self.dname = dname
        self.unicode_dname = domain_to_unicode(dname)

    def __str__(self):
        return '{}\t{}\t{}\t{}\t{}'.format(escape_string(self.name),
                                           self.ttl,
                                           rrclass_to_string(self.rr_class),
                                           rrtype_to_string(self.rr_type),
                                           escape_string(self.dname))

    @staticmethod
    def decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen):
        dname, _ = utils.decode_domain(packet, ptr)
        return PTR(name, ttl, dname)

@rr(constants.SOA, constants.IN)
class SOA(RR):
    def __init__(self, name, ttl, mname, rname, serial,
                 refresh, retry, expire, minimum):
        super(SOA, self).__init__(name, constants.SOA, constants.IN, ttl)
        self.mname = mname
        self.unicode_mname = domain_to_unicode(mname)
        self.rname = rname
        self.unicode_rname = domain_to_unicode(rname)
        self.serial = serial
        self.refresh = refresh
        self.retry = retry
        self.expire = expire
        self.minimum = minimum

    def __str__(self):
        return '{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}'.format(
            escape_string(self.name),
            self.ttl,
            rrclass_to_string(self.rr_class),
            rrtype_to_string(self.rr_type),
            escape_string(self.mname), escape_string(self.rname),
            self.serial, self.refresh,
            self.expire, self.minimum)

    @staticmethod
    def decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen):
        mname, ptr = utils.decode_domain(packet, ptr)
        rname, ptr = utils.decode_domain(packet, ptr)
        serial, refresh, retry, expire, minimum = struct.unpack('>LLLLL',
                                                                packet[ptr:ptr+20])
        return SOA(name, ttl, mname, rname, serial,
                   refresh, retry, expire, minimum)

@rr(constants.TXT, constants.IN)
class TXT(RR):
    def __init__(self, name, ttl, text):
        super(TXT, self).__init__(name, constants.TXT, constants.IN, ttl)
        self.text = text

    def __str__(self):
        return '{}\t{}\t{}\t{}\t{}'.format(escape_string(self.name),
                                           self.ttl,
                                           rrclass_to_string(self.rr_class),
                                           rrtype_to_string(self.rr_type),
                                           escape_string(self.text))

    @staticmethod
    def decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen):
        text = []
        end = ptr + rdlen
        while ptr < end:
            chunk, ptr = utils.decode_pascal_string(packet, ptr)
            text.append(chunk)
        text = b''.join(text)
        return TXT(name, ttl, text)

@rr(constants.WKS, constants.IN)
class WKS(RR):
    def __init__(self, name, ttl, address, protocol, bitmap):
        super(WKS, self).__init__(name, constants.WKS, constants.IN, ttl)
        self.address = address
        self.protocol = protocol
        self.bitmap = bitmap

    def __str__(self):
        bits = []
        base = 0
        for b in self.bitmap:
            for o in range(0, 8):
                bit = 0x80 >> o
                if b & bit:
                    bits.push_back(base + o)
            base += 8

        return '{}\t{}\t{}\t{}\t{}\t{}\t({})'.format(
            escape_string(self.name),
            self.ttl,
            rrclass_to_string(self.rr_class),
            rrtype_to_string(self.rr_type),
            self.address,
            self.protocol,
            ', '.join(str(bit) for bit in bits))

    @staticmethod
    def decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen):
        addr = ipaddress.IPv4Address(packet[ptr:ptr+4])
        protocol = packet[ptr+4]
        bitmap = packet[ptr+5:]
        return WKS(name, ttl, addr, protocol, bitmap)

class Unknown(RR):
    def __init__(self, name, rr_type, rr_class, ttl, data):
        super(Unknown, self).__init__(name, rr_type, rr_class, ttl)
        self.data = data

    def __str__(self):
        return '{}\t{}\t{}\t{}\t({})'.format(escape_string(self.name),
                                             self.ttl,
                                             rrclass_to_string(self.rr_class),
                                             rrtype_to_string(self.rr_type),
                                             utils.base64(self.data))

    @staticmethod
    def decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen):
        return Unknown(name, rr_type, rr_class, ttl, packet[ptr:ptr+rdlen])
