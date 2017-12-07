# -- rcodes

# RFC 1035
NOERROR  = 0
FORMERR  = 1
SERVFAIL = 2
NXDOMAIN = 3
NOTIMP   = 4
REFUSED  = 5

# RFC 2136
YXDOMAIN = 6
YXRRSET  = 7
NXRRSET  = 8
NOTAUTH  = 9
NOTZONE  = 10

# RFC 2671
BADVERS  = 16

# RFC 2845
BADSIG   = 16
BADKEY   = 17
BADTIME  = 18

# RFC 2930
BADMODE  = 19
BADNAME  = 20
BADALG   = 21

# Which RFC??
BADTRUNC  = 22
BADCOOKIE = 23

# -- RR types

A          = 1
NS         = 2
MD         = 3
MF         = 4
CNAME      = 5
SOA        = 6
MB         = 7
MG         = 8
MR         = 9
NUL        = 10
WKS        = 11
PTR        = 12
HINFO      = 13
MINFO      = 14
MX         = 15
TXT        = 16
RP         = 17
AFSDB      = 18
X25        = 19
ISDN       = 20
RT         = 21
NSAP       = 22
NSAPPTR    = 23
SIG        = 24
KEY        = 25
PX         = 26
GPOS       = 27
AAAA       = 28
LOC        = 29
NXT        = 30
EID        = 31
NIMLOC     = 32
SRV        = 33
ATMA       = 34
NAPTR      = 35
KX         = 36
CERT       = 37
A6         = 38
DNAME      = 39
SINK       = 40
OPT        = 41
APL        = 42
DS         = 43
SSHFP      = 44
IPSECKEY   = 45
RRSIG      = 46
NSEC       = 47
DNSKEY     = 48
DHCID      = 49
NSEC3      = 50
NSEC3PARAM = 51
TLSA       = 52
HIP        = 55
CDS        = 59
CDNSKEY    = 60
OPENPGPKEY = 61

SPF        = 99
UINFO      = 100
UID        = 101
GID        = 102
UNSPEC     = 103

TKEY       = 249
TSIG       = 250
IXFR       = 251
AXFR       = 252
MAILB      = 253
MAILA      = 254
ANY        = 255
URI        = 256

CAA        = 257
TA         = 32768
DLV        = 32769

# -- RR class

IN   = 1
CH   = 3
HS   = 4

NONE = 254
#ANY  = 255  # But we've already defined this above
