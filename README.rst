``aiosasl``, pure python generic asyncio SASL library
#####################################################

``aiosasl`` provides a generic, asyncio-based SASL library. It can be used with
any protocol, provided the neccessary interface code is provided by the
application or protocol implementation.

Dependencies
------------

* Python ≥ 3.4 (or Python = 3.3 with tulip)

Supported SASL mechanisms
-------------------------

* ``PLAIN``: authenticate with plaintext password (RFC 4616)
* ``ANONYMOUS``: anonymous "authentication" (RFC 4505)
* ``SCRAM-SHA-1``, ``SCRAM-SHA-224``, , ``SCRAM-SHA-512``, ``SCRAM-SHA-384``,
  and ``SCRAM-SHA-256``: Salted Challenge Response Authentication (RFC 5802)
