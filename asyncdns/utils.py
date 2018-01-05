import base64 as b64
import struct
import encodings

from .wireformat import *
from . import constants

MAX_PACKET_SIZE = 4000

_rcode_strings = [ 'No error',
                   'Format error',
                   'Server failure',
                   'Non-existent domain',
                   'Not implemented',
                   'Query refused',
                   'Name exists when it should not',
                   'RR set exists when it should not',
                   'RR set that should exist does not',
                   'Server not authoritative for zone',
                   'Name not contained in zone',
                   None,
                   None,
                   None,
                   None,
                   None,
                   'Bad OPT version OR TSIG signature failure',
                   'Key not recognized',
                   'Signature out of time window',
                   'Bad TKEY mode',
                   'Duplicate key name',
                   'Algorithm not supported' ]

_rrtype_strings = [ None, 'A', 'NS', 'MD', 'MF', 'CNAME', 'SOA', 'MB', 'MG', 'MR',
                    'NUL', 'WKS', 'PTR', 'HINFO', 'MINFO', 'MX', 'TXT', 'RP',
                    'AFSDB', 'X25', 'ISDN', 'RT', 'NSAP', 'NSAPPTR', 'SIG',
                    'KEY', 'PX', 'GPOS',
                    'AAAA', 'LOC', 'NXT', 'EID', 'NIMLOC', 'SRV', 'ATMA', 'NAPTR',
                    'KX', 'CERT', 'A6', 'DNAME', 'SINK', 'OPT', 'APL', 'DS',
                    'SSHFP', 'IPSECKEY', 'RRSIG', 'NSEC', 'DNSKEY', 'DHCID',
                    'NSEC3', 'NSEC3PARAM', 'TLSA', None, None, 'HIP', None,
                    None, None, 'CDS', 'CDNSKEY', 'OPENPGPKEY' ]
_rrtype_extras = { 99: 'SPF', 100: 'UINFO', 101: 'UID', 102: 'GID', 103: 'UNSPEC',
                   249: 'TKEY', 250: 'TSIG', 251: 'IXFR', 252: 'AXFR',
                   253: 'MAILB', 254: 'MAILA', 255: 'ANY', 256: 'URI',
                   257: 'CAA', 32768: 'TA', 32769: 'DLV' }

_rrclass_strings = [ None, 'IN', 'CS', 'CH', 'HS' ]

def escape_string(byte_string):
    try:
        ustr = byte_string.decode('ascii')
        return ustr
    except UnicodeError:
        ustr = byte_string.decode('ascii', 'backslashreplace').replace('"', '\\"')
        return '"{}"'.format(ustr)

def base64(byte_string):
    return b64.b64encode(byte_string).decode('ascii')

def rcode_to_string(rcode):
    """Convert an RCODE to a string"""
    try:
        s = _rcode_strings[rcode]
    except KeyError:
        s = None
    if s is None:
        s = 'Unknown ({})'.format(rcode)
    return s

def rrtype_to_string(rrt):
    """Convert an RR type to a string"""
    try:
        s = _rrtype_strings[rrt]
    except KeyError:
        s = _rrtype_extras.get(rrt, None)

    if s is None:
        s = 'TYPE{}'.format(rrt)

    return s

def rrclass_to_string(rrt):
    """Convert an RR class to a string"""
    try:
        s = _rrclass_strings[rrt]
    except KeyError:
        s = None

    if s is None:
        if rrt == NONE:
            s = 'NONE'
        elif rrt == ANY:
            s = 'ANY'
        else:
            s = 'CLASS{}'.format(rrt)

    return s

def decode_domain(packet, ptr):
    result = []
    saved = False
    saved_ptr = None

    while True:
        length = packet[ptr]
        ptr += 1

        if not length:
            break

        if length < 64:
            result.append(packet[ptr:ptr+length])
            ptr += length
        elif (length & 0xc0) == 0xc0:
            low = packet[ptr]
            ptr += 1

            offset = ((length & 0x3f) << 8) | low

            if offset > len(packet):
                raise ValueError('Bad reply to DNS query')

            if not saved:
                saved = True
                saved_ptr = ptr

            ptr = offset

    if saved:
        ptr = saved_ptr

    return (b'.'.join(result), ptr)

def domain_to_unicode(domain):
    return '.'.join([encodings.idna.ToUnicode(label)
                     for label in domain.split(b'.')])

def domain_from_unicode(domain):
    domain = domain.rstrip('.')
    return b'.'.join([encodings.idna.ToASCII(label)
                      for label in domain.split('.')])

def decode_pascal_string(packet, ptr):
    slen = packet[ptr]
    ptr += 1
    s = packet[ptr:ptr+slen]
    ptr += slen
    return (s, ptr)

def build_dns_packet(uid, query, wants_recursion=False, unicast=False):
    flags = QUERY
    if wants_recursion:
        flags |= RD
    header = struct.pack(b'>HHHHHH', uid, flags, 1, 0, 0, 1)
    packet = [header]

    for label in query.name.split(b'.'):
        if len(label) > 63:
            raise ValueError('DNS label too long')

        if len(label) == 0:
            continue

        packet.append(struct.pack(b'>B', len(label)))
        packet.append(label)

    q_class = query.q_class
    if unicast:
        q_class |= 0x8000
    packet.append(struct.pack(b'>BHH', 0, query.q_type, q_class))

    # Add an OPT record to indicate EDNS support
    packet.append(struct.pack(b'>BHHLH', 0, constants.OPT, MAX_PACKET_SIZE,
                              DO, 0))

    return b''.join(packet)
