import struct
import datetime

from . import constants, utils
from .rr import rr, RR

@rr(constants.DNSKEY, constants.ANY)
class DNSKEY(RR):
    def __init__(self, name, rr_class, ttl, flags, protocol, algorithm, key):
        super(DNSKEY, self).__init__(name, constants.DNSKEY, rr_class, ttl)
        self.flags = flags
        self.protocol = protocol
        self.algorithm = algorithm
        self.key = key

    def __str__(self):
        return '{}\t{}\t{}\t{}\t{}\t{}\t{}\t({})'\
            .format(utils.escape_string(self.name),
                    self.ttl,
                    utils.rrclass_to_string(self.rr_class),
                    utils.rrtype_to_string(self.rr_type),
                    self.flags,
                    self.protocol,
                    self.algorithm,
                    utils.base64(self.key))

    @staticmethod
    def decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen):
        flags, protocol, algorithm = struct.unpack(b'>HBB', packet[ptr:ptr+4])
        key = packet[ptr+4:ptr+rdlen]
        return DNSKEY(name, rr_class, ttl, flags, protocol, algorithm, key)

@rr(constants.RRSIG, constants.ANY)
class RRSIG(RR):
    def __init__(self, name, rr_class, ttl, type_covered, algorithm, labels,
                 orig_ttl, sig_expiration, sig_inception, key_tag, signer_name,
                 signature):
        super(RRSIG, self).__init__(name, constants.RRSIG, rr_class, ttl)
        self.type_covered = type_covered
        self.algorithm = algorithm
        self.labels = labels
        self.orig_ttl = orig_ttl
        self.sig_expiration = sig_expiration
        self.sig_inception = sig_inception
        self.key_tag = key_tag
        self.signer_name = signer_name
        self.signature = signature

    def __str__(self):
        return '{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t({})'\
            .format(utils.escape_string(self.name), self.ttl,
                    utils.rrclass_to_string(self.rr_class),
                    utils.rrtype_to_string(self.rr_type),
                    self.type_covered,
                    self.algorithm,
                    self.labels,
                    self.orig_ttl,
                    self.sig_expiration.strftime('%Y%m%d%H%M%S'),
                    self.sig_inception.strftime('%Y%m%d%H%M%S'),
                    self.key_tag,
                    utils.escape_string(self.signer_name),
                    utils.base64(self.signature))

    @staticmethod
    def decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen):
        tc, alg, labels, orig_ttl, sig_exp, sig_inc, key_tag \
            = struct.unpack(b'>HBBLLLH', packet[ptr:ptr+18])
        signer, pt2 = utils.decode_domain(packet, ptr+18)
        signature = packet[pt2:ptr+rdlen]
        sig_exp = datetime.datetime.fromtimestamp(sig_exp)
        sig_inc = datetime.datetime.fromtimestamp(sig_inc)
        return RRSIG(name, rr_class, ttl, tc, alg, labels, orig_ttl,
                     sig_exp, sig_inc, key_tag, signer, signature)

@rr(constants.NSEC, constants.ANY)
class NSEC(RR):
    def __init__(self, name, rr_class, ttl, next_domain, types):
        super(NSEC, self).__init__(name, constants.NSEC, rr_class, ttl)
        self.next_domain = next_domain
        self.types = types

    def __str__(self):
        return '{}\t{}\t{}\t{}\t{}\t({})'\
            .format(utils.escape_string(self.name), self.ttl,
                    utils.rrclass_to_string(self.rr_class),
                    utils.rrtype_to_string(self.rr_type),
                    utils.escape_string(self.next_domain),
                    ', '.join([utils.rrtype_to_string(t) for t in self.types]))

    @staticmethod
    def decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen):
        end = ptr + rdlen
        next_domain, ptr = utils.decode_domain(packet, ptr)
        types = set()
        while ptr < end:
            window = packet[ptr]
            wlen = packet[ptr + 1]
            ptr += 2

            bmp = packet[ptr:ptr+wlen]

            for n,b in enumerate(bmp):
                mask = 0x1
                for m in range(0, 8):
                    if b & mask:
                        t = n + m
                        if t not in (constants.OPT, constants.IXFR,
                                     constants.AXFR, constants.ANY):
                            types.add(n + m)
                    mask <<= 1
        return NSEC(name, rr_class, ttl, next_domain, types)

@rr(constants.DS, constants.ANY)
class DS(RR):
    def __init__(self, name, rr_class, ttl, key_tag, algorithm,
                 digest_type, digest):
        super(DS, self).__init__(name, constants.DS, rr_class, ttl)
        self.key_tag = key_tag
        self.algorithm = algorithm
        self.digest_type = digest_type
        self.digest = digest

    def __str__(self):
        return '{}\t{}\t{}\t{}\t{}\t{}\t{}\t({})'\
            .format(utils.escape_string(self.name), self.ttl,
                    utils.rrclass_to_string(self.rr_class),
                    utils.rrtype_to_string(self.rr_type),
                    self.key_tag,
                    self.algorithm,
                    self.digest_type,
                    utils.base64(self.digest))

    @staticmethod
    def decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen):
        key_tag, algorithm, digest_type \
            = struct.unpack(b'>HBB', packet[ptr:ptr+4])
        digest = packet[4:]
        return DS(name, rr_class, ttl, key_tag, algorithm, digest_type, digest)
