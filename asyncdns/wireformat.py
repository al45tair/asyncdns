# These are for DNS messages
QR          = 0x8000
OPCODE_MASK = 0x7800
QUERY       = 0x0000
IQUERY      = 0x0800
STATUS      = 0x1000
#           = 0x1800
NOTIFY      = 0x2000
UPDATE      = 0x2800

AA          = 0x0400
TC          = 0x0200
RD          = 0x0100
RA          = 0x0080
Z           = 0x0040
AD          = 0x0020
CD          = 0x0010

DO          = 0x8000

RCODE_MASK  = 0x000f
