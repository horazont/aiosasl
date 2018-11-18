.. aiosasl documentation master file, created by
   sphinx-quickstart on Wed Dec  9 12:45:22 2015.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to aiosasl's documentation!
===================================

:mod:`aiosasl` is a generic SASL implementation for use with :mod:`asyncio`
protocols. It makes very few assumptions about the protocol which uses SASL,
making it usable in different contexts. The assumptions are:

* It uses SASL, i.e. you can perform SASL initiation, responses and abortions.

* Those actions can be encapsulated in :mod:`asyncio` coroutines which return
  the server response.

API Reference
=============

.. automodule:: aiosasl

.. automodule:: aiosasl.channel_binding_methods

Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
