.. Replies

Replies
=======

Replies are represented by :py:class:`Reply` objects, which hold the flags,
RCODE, and three sets of returned RRs (answers, authorities and additional).

.. py:class:: Reply

  .. py:attribute:: flags
 
     The flags returned by the server.  These are as follows:

       ==========  ======  ===========================
       Constant    Value   Meaning
       ----------  ------  ---------------------------
       AA          0x0400  Authoritative Answer
       TC          0x0200  Truncated Response
       RD          0x0100  Recursion Desired
       RA          0x0080  Recursion Allowed
       Z           0x0040  Reserved
       AD          0x0020  Authentic Data (DNSSEC)
       CD          0x0010  Checking Disabled (DNSSEC)
       ==========  ======  ===========================

  .. py:attribute:: rcode

     The RCODE returned by the server.  Possible values are:

       ==========  ======  ===============================================
       Constant    Value   Meaning
       ----------  ------  -----------------------------------------------
       NOERROR     0       Successful query
       FORMERR     1       Format failure
       SERVFAIL    2       Server failure
       NXDOMAIN    3       Non-existent domain
       NOTIMP      4       Not implemented
       REFUSED     5       Query refursed
       YXDOMAIN    6       Name exists when it should not
       YXRRSET     7       RR set exists when it should not
       NXRRSET     8       RR set that should exist does not
       NOTAUTH     9       Server not authoritative OR Not authorized
       NOTZONE     10      Name not contained in zone
       BADVERS     16      Bad OPT version
       BADSIG      16      TSIG signature failure
       BADKEY      17      Key not recognized
       BADTIME     18      Signature out of time window
       BADMODE     19      Bad TKEY mode
       BADNAME     20      Duplicate key name
       BADALG      21      Algorithm not supported
       BADTRUNC    22      Bad truncation
       BADCOOKIE   23      Bad/missing server cookie
       ==========  ======  ===============================================

  .. py:attribute:: answers

     A list of :py:class:`rr.RR` returned by the server in the Answers section
     of the reply.

  .. py:attribute:: authorities

     A list of :py:class:`rr.RR` returned by the server in the Authorities
     section of the reply.

  .. py:attribute:: additional

     A list of additional :py:class:`rr.RR` returned by the server.

RRs
---

RRs are represented by subclasses of :py:class:`rr.RR`; a handful of common RR
types have special subclasses that decode the RDATA field in the DNS reply for
you.  If you are using some other type of RR, you can create your own subclass
and register it using :py:meth:`rr.RR.register`, or you can just decode the
data in your own code.

.. py:class:: rr.RR(name, rr_type, rr_class, ttl)

  The base class of all RRs.  You won't get a raw :py:class:`rr.RR` in a
  Reply - RRs that we don't understand are mapped to :py:class:`rr.Unknown`.

  .. py:attribute:: name

     The associated domain name, in the form given in the DNS packet (a
     :py:class:`bytes`).

  .. py:attribute:: unicode_name

     The associated domain name, after IDNA processing (a :py:class:`str`)

  .. py:attribute:: rr_type

     The RR type (see :py:class:`query` for a list).

  .. py:attribute:: rr_class

     The RR class (see :py:class:`query` for a list).

  .. py:attribute:: ttl

     The remaining time to live for this RR, in seconds.  Note that this field
     is only updated 

  .. py:method:: register(rr_type, rr_class, pyclass)

    Register a subclass of :py:class:`rr.RR`; when we decode a response from
    the DNS server, we will create an instance of the specified class to
    represent RRs of the specified type and class.

    :param int rr_type: The RR type to map.
    :param int rr_class: The RR class to map, or :py:data:`ANY` if the mapping
                         should operate for any class.
    :param pyclass: The Python class we should use for RRs of the specified
                    type and class.

  .. py:method:: decode(name, rr_type, rr_class, ttl, packet, ptr, rdlen)

    Decode an RR from a DNS packet, returning a new :py:class:`rr.RR` instance
    representing it.  The implementation in :py:class:`rr.RR` looks up the
    correct Python class and calls its :py:meth:`decode` method; if it
    doesn't find a class registered for the RR type with which it's presented,
    it will use :py:class:`rr.Unknown`.

    :param bytes name: The domain name.
    :param int rr_type: The RR type.
    :param int rr_class: The RR class.
    :param int ttl: The remaining time to live for this RR.
    :param bytes packet: The entire DNS response packet.
    :param int ptr: The current offset within the DNS packet.
    :param int rdlen: The length of the RR's data, starting from ptr.

.. py:class:: rr.A(name, ttl, address)

   .. py:attribute:: address

      The IPv4 address (an :py:class:`ipaddress.IPv4Address`).

.. py:class:: rr.AAAA(name, ttl, address)

   .. py:attribute:: address

      The IPv6 address (an :py:class:`ipaddress.IPv6Address`).

.. py:class:: rr.CNAME(name, ttl, address)

   .. py:attribute:: cname

      The aliased name, in the form given in the DNS packet (a
      :py:class:`bytes`).

   .. py:attribute:: unicode_cname

      The aliased name after IDNA processing (a :py:class:`str`)

.. py:class:: rr.HINFO(name, ttl, cpu, os)

   .. py:attribute:: cpu

      The CPU model (as a string).

   .. py:attribute:: os

      The operating system (as a string).

   Note that the RFC does not specify the encoding of either string, so for
   maximum robustness we decode the data as ISO Latin 1.  In most cases we
   would expect the two fields to be ASCII; if they are not, each code point
   in the resulting string with have the same value as the byte in the byte
   string.

.. py:class:: rr.MB(name, ttl, host)

   .. py:attribute:: host

      The host specified in the record.

   .. py:attribute:: unicode_host

      The host name after IDNA processing.

.. py:class:: rr.MF(name, ttl, host)

   .. py:attribute:: host

      The host specified in the record.

   .. py:attribute:: unicode_host

      The host name after IDNA processing.

.. py:class:: rr.MG(name, ttl, mailbox)

   .. py:attribute:: mailbox

      The mailbox specified in the record.

   .. py:attribute:: unicode_mailbox

      The mailbox name after IDNA processing.

.. py:class:: rr.MINFO(name, ttl, mailbox)

   .. py:attribute:: rmailbox
   .. py:attribute:: emailbox

      The mailboxes specified in the record.

   .. py:attribute:: unicode_rmailbox
   .. py:attribute:: unicode_emailbox

      The mailbox names after IDNA processing.

.. py:class:: rr.MR(name, ttl, mailbox)

   .. py:attribute:: mailbox

      The mailbox specified in the record.

   .. py:attribute:: unicode_mailbox

      The mailbox name after IDNA processing.

.. py:class:: rr.MX(name, ttl, preference, exchange)

   .. py:attribute:: preference

      The mail exchanger priority from the DNS record.

   .. py:attribute:: exchange

      The mail exchanger hostname as found in the DNS packet.

   .. py:attribute:: unicode_exchange

      The mail exchanger hostname after IDNA processing.

.. py:class:: rr.NUL(name, ttl, data)

   .. py:attribute:: data

      The RDATA from the record.

.. py:class:: rr.NS(name, ttl, host)

   .. py:attribute:: host

      The hostname of the nameserver.

   .. py:attribute:: unicode_host

      The hostname of the nameserver after IDNA processing.

.. py:class:: rr.PTR(name, ttl, dname)

   .. py:attribute:: address

      The IPv4 or IPv6 address, decoded from `name`, or ``None`` if no address
      could be decoded.

   .. py:attribute:: dname

      The name pointed to by this record.

   .. py:attribute:: unicode_host

      The name poitned to by this record, after IDNA processing.

.. py:class:: rr.SOA(name, ttl, mname, rname, serial, refresh, retry, expire,
              minimum)

   .. py:attribute:: mname

      The name of the primary mailserver for the zone.

   .. py:attribute:: unicode_mname

      Same as above, but after IDNA processing.

   .. py:attribute:: rname

      The mailbox name of the person responsible for the zone.

   .. py:attribute:: unicode_rname

      As above, but after IDNA processing.

   .. py:attribute:: serial

      The zone's serial number; this is used to detect changes to a zone (it
      must be incremented every time a zone is changed).

   .. py:attribute:: refresh

      The number of seconds for which a secondary nameserver may assume the
      zone data has not changed - controls how often the secondary checks the
      zone serial number.

   .. py:attribute:: retry

      The number of seconds a secondary should wait to retry a refresh if the
      primary nameserver is busy.

   .. py:attribute:: expire

      The number of seconds a secondary nameserver can cache the data before
      it is no longer authoritative.

   .. py:attribute:: minimum

      The minimum time to live for RRs in the zone.

.. py:class:: rr.TXT(name, ttl, text)

   .. py:attribute:: text

      The stored text.  Since no encoding is specified, this is decoded as ISO
      Latin 1 (since that is the most robust option).

.. py:class:: rr.WKS(name, ttl, address, protocol, bitmap)

   .. py:attribute:: address

      The IPv4 address for this record.

   .. py:attribute:: protocol

      The IP protocol number for this record (typically 6, for TCP, or 17, for
      UDP).

   .. py:attribute:: bitmap

      A :py:class:`bytes` holding the port bitmap.

.. py:class:: rr.Unknown(name, ttl, rr_type, rr_class, ttl, data)

   This subclass of :py:class:`rr.RR` is used when we don't know how to decode
   the RR found in the data packet.

   .. py:attribute:: data

      The RDATA from the record.

