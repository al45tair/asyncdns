#
# A Windows-specific SystemResolver implementation that gets the DNS server
# list from the Windows API
#
import ipaddress
import time

from ctypes import *

from .resolver import Resolver, RoundRobinServer, RandomServer

iphlpapi = windll.iphlpapi

UINT = c_uint
DWORD = c_uint32
ULONG = c_ulong
PULONG = POINTER(c_ulong)

class IP_ADDRESS_STRING(Structure):
    _fields_ = [('String', c_char * (4 * 4))]

IP_MASK_STRING = IP_ADDRESS_STRING

class IP_ADDR_STRING(Structure):
    pass

IP_ADDR_STRING._fields_ = [('Next', POINTER(IP_ADDR_STRING)),
                           ('IpAddress', IP_ADDRESS_STRING),
                           ('IpMask', IP_MASK_STRING),
                           ('Context', DWORD)]

PIP_ADDR_STRING = POINTER(IP_ADDR_STRING)

MAX_HOSTNAME_LEN = 128
MAX_DOMAIN_NAME_LEN = 128
MAX_SCOPE_ID_LEN = 256
class FIXED_INFO(Structure):
    _fields_ = [('HostName', c_char * (MAX_HOSTNAME_LEN + 4)),
                ('DomainName', c_char * (MAX_DOMAIN_NAME_LEN + 4)),
                ('CurrentDnsServer', PIP_ADDR_STRING),
                ('DnsServerList', IP_ADDR_STRING),
                ('NodeType', UINT),
                ('ScopeId', c_char * (MAX_SCOPE_ID_LEN + 4)),
                ('EnableRouting', UINT),
                ('EnableProxy', UINT),
                ('EnableDns', UINT)]
PFIXED_INFO = POINTER(FIXED_INFO)

ERROR_SUCCESS = 0
ERROR_BUFFER_OVERFLOW = 111

GetNetworkParams = iphlpapi.GetNetworkParams
GetNetworkParams.restype = DWORD
GetNetworkParams.args = [PFIXED_INFO, PULONG]

class SystemResolver(Resolver):

    def __init__(self):
        self._servers = None
        self._servers_timestamp = None

        super(SystemResolver, self).__init__()

    def read_servers(self):
        servers = []

        outLen = ULONG(0)
        ret = GetNetworkParams(None, byref(outLen))
        if ret != ERROR_BUFFER_OVERFLOW:
            raise Exception('Unexpected error {:08x}'.format(ret))
        buf = create_string_buffer(outLen.value)
        pfi = cast(buf, PFIXED_INFO)
        GetNetworkParams(pfi, byref(outLen))
        fi = pfi.contents

        try:
            saddr = fi.DnsServerList.IpAddress.String
            addr = ipaddress.ip_address(saddr.decode('ascii'))
            servers.append((addr, 53))
        except ValueError:
            pass

        pipa = fi.DnsServerList.Next
        while pipa:
            try:
                saddr = pipa.contents.IPAddress.String
                addr = ipaddress.ip_address(saddr.decode('ascii'))
                servers.append((addr, 53))
            except ValueError:
                pass
            pipa = pipa.contents.Next

        self._servers = RoundRobinServer(servers)

    def maybe_read_servers(self):
        now = time.time()
        if self._servers_timestamp is not None \
           and now - self._servers_timestamp < 30:
            return

        self.read_servers()

    def lookup(self, query, should_cache=True, recursive=False,
               prefer_ipv6=False):
        self.maybe_read_servers()
        return super(SystemResolver, self).lookup(query, self._servers,
                                                  should_cache,
                                                  recursive, prefer_ipv6)
