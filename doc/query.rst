.. Queries

Queries
=======

DNS queries are represented by :py:class:`Query` objects, which hold a name to
look up, a query type and a query class.

.. py:class:: Query

   .. :param name:

   The name to query.  This may be specified as a Python string (in which
   case, IDNA is applied if necessary); or as a Python :py:class:`bytes`
   object (in which case the bytes are used literally, subject to the usual
   rules on DNS labels); or an IP address using the :py:module:`ipaddress`
   module's :py:class:`IPv4Address` or :py:class:`IPv6Address` objects, in
   which case the address will be automatically turned into the appropriate
   form for a reverse lookup.

   .. :param int q_type:

   The DNS query type.  There are constants for most query types in the
   :py:module:`asyncdns` module, e.g. ``asyncdns.A``, ``asyncdns.AAAA`` and so
   on, but you can use the numeric value if required.  Possible values are:

     ================   =======  ============
     Constant           Value    Meaning
     ================   =======  ============
     :py:data:`A`       1        IPv4 address
     :py:data:`NS`      2        Nameserver
     :py:data:`MD`      3        Mail destination (obsolete)
     :py:data:`MF`      4        Mail forwarder (obsolete)
     :py:data:`CNAME`   5        Canonical name record - an alias
     :py:data:`SOA`     6        Start Of Authority
     :py:data:`MB`      7        Mailbox domain name (obsolete)
     :py:data:`MG`      8        Mail group member (obsolete)
     :py:data:`MR`      9        Mail rename (obsolete)
     :py:data:`NUL`     10       Null
     :py:data:`WKS`     11       Well Known Service description (obsolete)
     :py:data:`PTR`     12       Pointer - for inverse queries
     :py:data:`HINFO`   13       Host information (obsolete)
     :py:data:`MINFO`   14       Mailbox or list information (obsolete)
     :py:data:`MX`      15       Mail eXchanger
     :py:data:`TXT`     16       Free format text
     :py:data:`RP`      17       Responsible person
     :py:data:`AFSDB`   18       AFS database record
     :py:data:`X25`     19       X.121 address, as used on X.25 networks
     :py:data:`ISDN`    20       ISDN address
     :py:data:`RT`      21       Route record, for X.25 or ISDN
     :py:data:`NSAP`    22       OSI NSAP address
     :py:data:`NSAPPTR` 23       NSAP Pointer - for inverse queries
     :py:data:`SIG`     24       (Old) DNSSEC signature (obsolete)
     :py:data:`KEY`     25       (Old) DNSSEC key (obsolete)
     :py:data:

   .. :param int q_class:

   The DNS query class.  This will almost always be ``asyncdns.IN``.

   .. 
