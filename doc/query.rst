.. Queries

Queries
=======

DNS queries are represented by :py:class:`Query` objects, which hold a name to
look up, a query type and a query class.

.. py:class:: Query(name, q_type, q_class)

   Represents a DNS query.

  :param name: The name to query.
  :type name: str
  :type name: bytes
  :type name: ipaddress.IPv4Address
  :type name: ipaddress.IPv6Address
  :param int q_type: The RR type you're querying for.
  :param int q_class: The RR class you're querying for.

  `name` may be specified as a Python string (in which case, IDNA is applied
  if necessary); or as a Python :py:class:`bytes` object (in which case the
  bytes are used literally, subject to the usual rules on DNS labels); or an
  IP address using the :py:mod:`ipaddress` module's :py:class:`IPv4Address`
  or :py:class:`IPv6Address` objects, in which case the address will be
  automatically turned into the appropriate form for a reverse lookup.

  There are constants for most query types in the :py:mod:`asyncdns` module,
  e.g. ``asyncdns.A``, ``asyncdns.AAAA`` and so on, but you can use the
  numeric value if required.  Possible values are:

     ===================== ======== =============================================
     Constant              Value    Meaning
     --------------------- -------- ---------------------------------------------
     :py:data:`A`          1        IPv4 address
     :py:data:`NS`         2        Nameserver
     :py:data:`MD`         3        Mail destination (obsolete)
     :py:data:`MF`         4        Mail forwarder (obsolete)
     :py:data:`CNAME`      5        Canonical name record - an alias
     :py:data:`SOA`        6        Start Of Authority
     :py:data:`MB`         7        Mailbox domain name (obsolete)
     :py:data:`MG`         8        Mail group member (obsolete)
     :py:data:`MR`         9        Mail rename (obsolete)
     :py:data:`NUL`        10       Null
     :py:data:`WKS`        11       Well Known Service description (obsolete)
     :py:data:`PTR`        12       Pointer - for inverse queries
     :py:data:`HINFO`      13       Host information (obsolete)
     :py:data:`MINFO`      14       Mailbox or list information (obsolete)
     :py:data:`MX`         15       Mail eXchanger
     :py:data:`TXT`        16       Free format text
     :py:data:`RP`         17       Responsible person
     :py:data:`AFSDB`      18       AFS database record
     :py:data:`X25`        19       X.121 address, as used on X.25 networks
     :py:data:`ISDN`       20       ISDN address
     :py:data:`RT`         21       Route record, for X.25 or ISDN
     :py:data:`NSAP`       22       OSI NSAP address
     :py:data:`NSAPPTR`    23       NSAP Pointer - for inverse queries
     :py:data:`SIG`        24       (Old) DNSSEC signature (obsolete)
     :py:data:`KEY`        25       (Old) DNSSEC key (obsolete)
     :py:data:`PX`         26       X.400 mail mapping information (obsolete)
     :py:data:`GPOS`       27       Geographical location (obsolete)
     :py:data:`AAAA`       28       IPv6 address
     :py:data:`LOC`        29       Geographical location
     :py:data:`NXT`        30       (Old) DNSSEC Next record (obsolete)
     :py:data:`EID`        31       Nimrod Endpoint Identifier (obsolete)
     :py:data:`NIMLOC`     32       Nimrod Locator (obsolete)
     :py:data:`SRV`        33       Service locator
     :py:data:`ATMA`       34       ATM address
     :py:data:`NAPTR`      35       Naming Authority Pointer - regex rewriting
     :py:data:`KX`         36       Key exchanger record
     :py:data:`CERT`       37       Certificate record
     :py:data:`A6`         38       Intended to replace AAAA (obsolete)
     :py:data:`DNAME`      39       Alias for a name *and all subnames*
     :py:data:`SINK`       40       Kitchen sink (joke, obsolete)
     :py:data:`OPT`        41       EDNS option (PSEUDO-RR)
     :py:data:`APL`        42       Address Prefix List
     :py:data:`DS`         43       Delegation Signer record
     :py:data:`SSHFP`      44       SSH public key fingerprint
     :py:data:`IPSECKEY`   45       IPsec key
     :py:data:`RRSIG`      46       DNSSEC signature
     :py:data:`NSEC`       47       Next Secure record - to prove non-existence
     :py:data:`DNSKEY`     48       DNSSEC key record
     :py:data:`DHCID`      49       DHCP identifier
     :py:data:`NSEC3`      50       Next Secure record (v3)
     :py:data:`NSEC3PARAM` 51       NSEC3 parameter record
     :py:data:`TLSA`       52       TLSA cetificate association
     :py:data:`HIP`        55       Host Identity Protocol record
     :py:data:`CDS`        59       Child DS record
     :py:data:`CDNSKEY`    60       Child DNSKEY
     :py:data:`OPENPGPKEY` 61       OpenPGP public key
     :py:data:`SPF`        99       SPF record (obsolete)
     :py:data:`UINFO`      100      Reserved
     :py:data:`UID`        101      Reserved
     :py:data:`GID`        102      Reserved
     :py:data:`UNSPEC`     103      Reserved
     :py:data:`TKEY`       249      Transaction key
     :py:data:`TSIG`       250      Transaction signature
     :py:data:`IXFR`       251      Incremental zone transfer (PSEUDO-RR)
     :py:data:`AXFR`       252      Authoritative zone transfers (PSEUDO-RR)
     :py:data:`MAILB`      253      Used to get MB/MG/MR/MINFO records (obsolete)
     :py:data:`MAILA`      254      Used to retrieve MD or MF records (obsolete)
     :py:data:`ANY`        255      Return all record types (PSEUDO-RR)
     :py:data:`URI`        256      Maps a hostname to a URI
     :py:data:`CAA`        257      Certificate Authority Authorization
     :py:data:`TA`         32768    DNSSEC Trust Authorities
     :py:data:`DLV`        32769    DNSSEC Lookaside Validation record
     ===================== ======== =============================================

  The query class will almost always be ``asyncdns.IN``.  Possible values
  are:

     ====================  =======  ============
     Constant              Value    Meaning
     --------------------  -------  ------------
     :py:data:`IN`         1        Internet
     :py:data:`CH`         3        Chaos
     :py:data:`HS`         4        Hesiod
     :py:data:`NONE`       254
     :py:data:`ANY`        255
     ====================  =======  ============

  .. py:method:: __lt__(other)
  .. py:method:: __eq__(other)
  .. py:method:: __ne__(other)
  .. py:method:: __gt__(other)
  .. py:method:: __ge__(other)
  .. py:method:: __le__(other)
  
  Query provides comparison and ordering operators.

  .. py:method:: __hash__()
  
  Query is also hashable, so it can be used as a key in a :py:class:`dict` or
  :py:class:`set`.

  .. py:method:: __repr__()

  Returns a debug representation.
