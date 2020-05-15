``aiosasl``, pure python generic asyncio SASL library
#####################################################

.. image:: https://travis-ci.com/horazont/aiosasl.svg?branch=devel
  :target: https://travis-ci.com/horazont/aiosasl

.. image:: https://coveralls.io/repos/github/horazont/aiosasl/badge.svg?branch=devel
  :target: https://coveralls.io/github/horazont/aiosasl?branch=devel

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
* ``SCRAM-SHA-1`` and ``SCRAM-SHA-256`` (and the ``-PLUS`` variants with
  channel binding): Salted Challenge Response Authentication (RFC 5802)

Documentation
-------------

Official documentation can be built with sphinx and is available online
`on our servers <https://docs.zombofant.net/aiosasl/0.4/>`_.

Supported channel binding methods
---------------------------------

* ``tls-unique`` and ``tls-server-end-point`` with a pyOpenSSL connection
* all methods supported by the Python standard library when using the
  ``ssl`` module
