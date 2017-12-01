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
    _fields_ = [('Next', POINTER(IP_ADDR_STRING)),
                ('IpAddress', IP_ADDRESS_STRING),
                ('IpMask', IP_MASK_STRING),
                ('Context', DWORD)]
PIP_ADDR_STRING = POINTER(IP_ADDR_STRING)

MAX_HOSTNAME_LEN = ###
MAX_DOMAIN_NAME_LEN = ###
MAX_SCOPE_ID_LEN = ###
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
ERROR_BUFFER_OVERFLOW = ###FIXME

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
        GetNetworkParams(None, byref(outLen))
        buf = create_string_buffer(outLen)
        pfi = cast(buf, PFIXED_INFO)
        GetNetworkParams(pfi, byref(outLen))
        fi = pfi.contents

        try:
            addr = ipaddress.ip_address(fi.DnsServerList.IpAddress.String)
            servers.append((addr, 53))
        except ValueError:
            pass

        pipa = fi.DnsServerList.Next
        while pipa != None:
            try:
                addr = ipaddress.ip_address(pipa.contents.IPAddress.String)
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

    def lookup(self, query, prefer_ipv6=False,
               should_cache=True, recursive=False):
        self.maybe_read_servers()
        return super(SystemResolver, self).lookup(query, self._servers,
                                                  prefer_ipv6, should_cache,
                                                  recursive)
