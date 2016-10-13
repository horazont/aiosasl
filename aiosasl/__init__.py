########################################################################
# File name: __init__.py
# This file is part of: aiosasl
#
# LICENSE
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program.  If not, see
# <http://www.gnu.org/licenses/>.
#
########################################################################
"""
Using SASL in a protocol
========================

To make use of SASL over an existing protocol, you first need to subclass and
implement :class:`SASLInterface`.

The usable mechanisms need to be detected by your application using the
protocol over which to implement SASL. This is generally protocol-specific. For
example, XMPP uses stream features to announce which SASL mechanisms are
supported by the server.

When a set of SASL mechanism strings has been obtained by the server (let us
call a set with the mechanism strings ``sasl_mechanisms``), the mechanisms
supported by your application (a list of :class:`SASLMechanism` subclass
instances, let us call it ``mechanism_impls``) can be queried for support::

    # intf = <instance of your subclass of SASLInterface>
    for impl in mechanism_impl:
        token = impl.any_supported(sasl_mechanisms)
        if token is not None:
            sm = aiosasl.SASLStateMachine(intf)
            try:
                yield from impl.authenticate(sm, token)
            except aiosasl.AuthenticationFailure:
                # handle authentication failure
                # it is generally not sensible to re-try with other mechanisms
            except aiosasl.SASLFailure:
                # this is a protocol problem, it is sensible to re-try other
                # mechanisms
            else:
                # authentication was successful!

The instances for the mechanisms can be re-used; they do not save any state,
the state is held by :class:`SASLStateMachine` instead. The different
mechanisms require different arguments (the password-based mechanisms generally
require a callback which provides credentials).

The mechanisms which are currently supported by :mod:`aiosasl` are summarised
below:

.. autosummary::

   PLAIN
   SCRAM

Interface for protocols using SASL
==================================

To implement SASL on an existing protocol, you need to subclass
:class:`SASLInterface` and implement the abstract methods:

.. autoclass:: SASLInterface

SASL mechansims
===============

.. autoclass:: PLAIN

.. autoclass:: SCRAM

.. autoclass:: ANONYMOUS

Base class
----------

.. autoclass:: SASLMechanism

SASL state machine
==================

.. autoclass:: SASLStateMachine

Exception classes
=================

.. autoclass:: SASLError

.. autoclass:: SASLFailure

.. autoclass:: AuthenticationFailure

Version information
===================

.. autodata:: __version__

.. autodata:: version_info

"""

import abc
import asyncio
import base64
import functools
import hashlib
import hmac
import itertools
import logging
import operator
import random
import time

from aiosasl.stringprep import saslprep, trace

from .version import version, __version__, version_info  # NOQA

logger = logging.getLogger(__name__)

#: The imported :mod:`aiosasl` version as a tuple.
#:
#: The components of the tuple are, in order: `major version`, `minor version`,
#: `patch level`, and `pre-release identifier`.
version_info = version_info

#: The imported :mod:`aiosasl` version as a string.
#:
#: The version number is dot-separated; in pre-release or development versions,
#: the version number is followed by a hypen-separated pre-release identifier.
__version__ = __version__


_system_random = random.SystemRandom()

try:
    from hashlib import pbkdf2_hmac as pbkdf2
except ImportError:
    # this is untested if you have pbkdf2_hmac
    def pbkdf2(hashfun_name, input_data, salt, iterations, dklen=None):
        """
        Derivate a key from a password. `input_data` is taken as the bytes
        object resembling the password (or other input). `hashfun` must be a
        callable returning a :mod:`hashlib`-compatible hash function. `salt` is
        the salt to be used in the PBKDF2 run, `iterations` the count of
        iterations. `dklen` is the length in bytes of the key to be derived.

        Return the derived key as :class:`bytes` object.
        """

        if dklen is not None and dklen <= 0:
            raise ValueError("Invalid length for derived key: {}".format(
                dklen))

        hashfun = lambda: hashlib.new(hashfun_name)

        hlen = hashfun().digest_size
        if dklen is None:
            dklen = hlen

        block_count = (dklen + (hlen - 1)) // hlen

        mac_base = hmac.new(input_data, None, hashfun)

        def do_hmac(data):
            mac = mac_base.copy()
            mac.update(data)
            return mac.digest()

        def calc_block(i):
            u_prev = do_hmac(salt + i.to_bytes(4, "big"))
            u_accum = u_prev
            for k in range(1, iterations):
                u_curr = do_hmac(u_prev)
                u_accum = bytes(itertools.starmap(
                    operator.xor,
                    zip(u_accum, u_curr)))
                u_prev = u_curr

            return u_accum

        result = b"".join(
            calc_block(i)
            for i in range(1, block_count + 1))

        return result[:dklen]


class SASLError(Exception):
    """
    Base class for a SASL related error. `opaque_error` may be anything but
    :data:`None` which helps your application re-identify the error at the
    outer layers. `kind` is a string which helps identifying the class of the
    error; this is set implicitly by the constructors of :class:`SASLFailure`
    and :class:`AuthenticationFailure`, which you are encouraged to use.

    `text` may be a human-readable string describing the error condition in
    more detail.

    `opaque_error` is set to :data:`None` by :class:`SASLMechanism`
    implementations to indicate errors which originate from the local mechanism
    implementation.

    .. attribute:: opaque_error

       The value passed to the respective constructor argument.

    .. attribute:: text

       The value passed to the respective constructor argument.

    """

    def __init__(self, opaque_error, kind, text=None):
        msg = "{}: {}".format(opaque_error, kind)
        if text:
            msg += ": {}".format(text)
        super().__init__(msg)
        self.opaque_error = opaque_error
        self.text = text


class SASLFailure(SASLError):
    """
    A SASL protocol failure which is unrelated to the credentials passed. This
    may be raised by :class:`SASLInterface` methods.
    """

    def __init__(self, opaque_error, text=None):
        super().__init__(opaque_error, "SASL failure", text=text)

    def promote_to_authentication_failure(self):
        return AuthenticationFailure(
            self.opaque_error,
            self.text)


class AuthenticationFailure(SASLError):
    """
    A SASL error which indicates that the provided credentials are
    invalid. This may be raised by :class:`SASLInterface` methods.
    """

    def __init__(self, opaque_error, text=None):
        super().__init__(opaque_error, "authentication failed", text=text)


class SASLInterface(metaclass=abc.ABCMeta):
    """
    This class serves as an abstract base class for interfaces for use with
    :class:`SASLStateMachine`. Specific protocols using SASL (such as XMPP,
    IMAP or SMTP) can subclass this interface to implement SASL on top of the
    existing protocol.

    The interface class does not need to implement any state checking. State
    checking is done by the :class:`SASLStateMachine`. The following interface
    must be implemented by subclasses.

    The return values of the methods below are tuples of the following form:

    * ``("success", payload)`` -- After successful authentication, success is
      returned. Depending on the mechanism, a payload (as :class:`bytes`
      object) may be attached to the result, otherwise, ``payload`` is
      :data:`None`.

    * ``("challenge", payload)`` -- A challenge was sent by the server in reply
      to the previous command.

    * ``("failure", None)`` -- This is only ever returned by :meth:`abort`. All
      other methods **must** raise errors as :class:`SASLFailure`.

    .. automethod:: initiate

    .. automethod:: respond

    .. automethod:: abort

    """

    @abc.abstractmethod
    @asyncio.coroutine
    def initiate(self, mechanism, payload=None):
        """
        Send a SASL initiation request for the given `mechanism`. Depending on
        the `mechanism`, an initial `payload` *may* be given. The `payload` is
        then a :class:`bytes` object which needs to be passed as initial
        payload during the initiation request.

        Wait for a reply by the peer and return the reply as a next-state tuple
        in the format documented at :class:`SASLInterface`.
        """

    @abc.abstractmethod
    @asyncio.coroutine
    def respond(self, payload):
        """
        Send a response to a challenge. The `payload` is a :class:`bytes`
        object which is to be sent as response.

        Wait for a reply by the peer and return the reply as a next-state tuple
        in the format documented at :class:`SASLInterface`.
        """

    @abc.abstractmethod
    @asyncio.coroutine
    def abort(self):
        """
        Abort the authentication. The result is either the failure tuple
        (``("failure", None)``) or a :class:`SASLFailure` exception if
        the response from the peer did not indicate abortion (e.g. another
        error was returned by the peer or the peer indicated success).
        """


class SASLStateMachine:
    """
    A state machine to reduce code duplication during SASL handshake.

    The state methods change the state and return the next client state of the
    SASL handshake, optionally with server-supplied payload.

    Note that, with the notable exception of :meth:`abort`, ``failure`` states
    are never returned but thrown as :class:`SASLFailure` instead.

    The initial state is never returned.
    """

    def __init__(self, interface):
        super().__init__()
        self.interface = interface
        self._state = "initial"

    @asyncio.coroutine
    def initiate(self, mechanism, payload=None):
        """
        Initiate the SASL handshake and advertise the use of the given
        `mechanism`. If `payload` is not :data:`None`, it will be base64
        encoded and sent as initial client response along with the ``<auth />``
        element.

        Return the next state of the state machine as tuple (see
        :class:`SASLStateMachine` for details).
        """

        if self._state != "initial":
            raise RuntimeError("initiate has already been called")

        try:
            next_state, payload = yield from self.interface.initiate(
                mechanism,
                payload=payload)
        except SASLFailure:
            self._state = "failure"
            raise

        self._state = next_state
        return next_state, payload

    @asyncio.coroutine
    def response(self, payload):
        """
        Send a response to the previously received challenge, with the given
        `payload`. The payload is encoded using base64 and transmitted to the
        server.

        Return the next state of the state machine as tuple (see
        :class:`SASLStateMachine` for details).
        """
        if self._state != "challenge":
            raise RuntimeError(
                "no challenge has been made or negotiation failed")

        try:
            next_state, payload = yield from self.interface.respond(payload)
        except SASLFailure:
            self._state = "failure"
            raise

        self._state = next_state
        return next_state, payload

    @asyncio.coroutine
    def abort(self):
        """
        Abort an initiated SASL authentication process. The expected result
        state is ``failure``.
        """
        if self._state == "initial":
            raise RuntimeError("SASL authentication hasn't started yet")

        try:
            return (yield from self.interface.abort())
        finally:
            self._state = "failure"


class SASLMechanism(metaclass=abc.ABCMeta):
    """
    Implementation of a SASL mechanism. Two methods must be implemented by
    subclasses:

    .. automethod:: any_supported

    .. automethod:: authenticate

    .. note:: Administrative note

       Patches for new SASL mechanisms are welcome!

    """

    @abc.abstractclassmethod
    def any_supported(cls, mechanisms):
        """
        Determine whether this class can perform any SASL mechanism in the set
        of strings ``mechanisms``.

        If the class cannot perform any of the SASL mechanisms in
        ``mechanisms``, it must return :data:`None`.

        Otherwise, it must return a non-:data:`None` value. Applications must
        not assign any meaning to any value (except that :data:`None` is a sure
        indicator that the class cannot perform any of the listed mechanisms)
        and must not alter any value returned by this function. Note that even
        :data:`False` indicates success!

        The return value must be passed as second argument to
        :meth:`authenticate`. :meth:`authenticate` must not be called with a
        :data:`None` value.
        """

    @asyncio.coroutine
    @abc.abstractmethod
    def authenticate(self, sm, token):
        """
        Execute the mechanism identified by `token` (the non-:data:`None` value
        which has been returned by :meth:`any_supported` before) using the
        given :class:`SASLStateMachine` `sm`.

        If authentication fails, an appropriate exception is raised
        (:class:`AuthenticationFailure`). If the authentication fails for a
        reason unrelated to credentials, :class:`SASLFailure` is raised.
        """


class PLAIN(SASLMechanism):
    """
    The password-based ``PLAIN`` SASL mechanism (see :rfc:`4616`).

    .. warning::

       This is generally unsafe over unencrypted connections and should not be
       used there. Exclusion of the ``PLAIN`` mechanism over unsafe connections
       is out of scope for :mod:`aiosasl` and needs to be handled by the
       protocol implementation!

    `credential_provider` must be coroutine which returns a ``(user,
    password)`` tuple.
    """
    def __init__(self, credential_provider):
        super().__init__()
        self._credential_provider = credential_provider

    @classmethod
    def any_supported(cls, mechanisms):
        if "PLAIN" in mechanisms:
            return "PLAIN"
        return None

    @asyncio.coroutine
    def authenticate(self, sm, mechanism):
        logger.info("attempting PLAIN mechanism")
        username, password = yield from self._credential_provider()
        username = saslprep(username).encode("utf8")
        password = saslprep(password).encode("utf8")

        state, _ = yield from sm.initiate(
            mechanism="PLAIN",
            payload=b"\0" + username + b"\0" + password)

        if state != "success":
            raise SASLFailure(
                None,
                text="SASL protocol violation")

        return True


class SCRAM(SASLMechanism):
    """
    The password-based SCRAM (non-PLUS) SASL mechanism (see :rfc:`5802`).

    .. note::

       As "non-PLUS" suggests, this does not support channel binding. Patches
       welcome.

       It may make sense to implement the -PLUS mechanisms as separate
       :class:`SASLMechanism` subclass or at least allow disabling them via an
       optional argument (defaulting to disabled). Channel binding may not be
       reliably available in all cases.

    `credential_provider` must be coroutine which returns a ``(user,
    password)`` tuple.
    """

    def __init__(self, credential_provider):
        super().__init__()
        self._credential_provider = credential_provider
        self.nonce_length = 15

    _supported_hashalgos = {
        # the second argument is for preference ordering (highest first)
        # if anyone has a better hash ordering suggestion, I’m open for it
        # a value of 1 is added if the -PLUS variant is used
        # -- JWI
        "SHA-1": ("sha1", 1),
        "SHA-224": ("sha224", 224),
        "SHA-512": ("sha512", 512),
        "SHA-384": ("sha384", 384),
        "SHA-256": ("sha256", 256),
    }

    @classmethod
    def any_supported(cls, mechanisms):
        supported = []
        for mechanism in mechanisms:
            if not mechanism.startswith("SCRAM-"):
                continue
            if mechanism.endswith("-PLUS"):
                # channel binding is not supported
                continue

            hashfun_key = mechanism[6:]

            try:
                hashfun_name, quality = cls._supported_hashalgos[hashfun_key]
            except KeyError:
                continue

            supported.append(((1, quality), (mechanism, hashfun_name,)))

        if not supported:
            return None
        supported.sort()

        return supported.pop()[1]

    @classmethod
    def parse_message(cls, msg):
        parts = (
            part
            for part in msg.split(b",")
            if part)

        for part in parts:
            key, _, value = part.partition(b"=")
            if len(key) > 1 or key == b"m":
                raise Exception("SCRAM protocol violation / unknown "
                                "future extension")
            if key == b"n" or key == b"a":
                value = value.replace(b"=2C", b",").replace(b"=3D", b"=")

            yield key, value

    @asyncio.coroutine
    def authenticate(self, sm, token):
        mechanism, hashfun_name, = token
        logger.info("attempting %s mechanism (using %s hashfun)",
                    mechanism,
                    hashfun_name)
        # this is pretty much a verbatim implementation of RFC 5802.

        hashfun_factory = functools.partial(hashlib.new, hashfun_name)
        digest_size = hashfun_factory().digest_size

        # we don’t support channel binding
        gs2_header = b"n,,"
        username, password = yield from self._credential_provider()
        username = saslprep(username).encode("utf8")
        password = saslprep(password).encode("utf8")

        our_nonce = base64.b64encode(_system_random.getrandbits(
            self.nonce_length * 8
        ).to_bytes(
            self.nonce_length, "little"
        ))

        auth_message = b"n=" + username + b",r=" + our_nonce
        _, payload = yield from sm.initiate(
            mechanism,
            gs2_header + auth_message)

        auth_message += b"," + payload

        payload = dict(self.parse_message(payload))

        try:
            iteration_count = int(payload[b"i"])
            nonce = payload[b"r"]
            salt = base64.b64decode(payload[b"s"])
        except (ValueError, KeyError):
            yield from sm.abort()
            raise SASLFailure(
                None,
                text="malformed server message: {!r}".format(payload))

        if not nonce.startswith(our_nonce):
            yield from sm.abort()
            raise SASLFailure(
                None,
                text="server nonce doesn't fit our nonce")

        t0 = time.time()

        salted_password = pbkdf2(
            hashfun_name,
            password,
            salt,
            iteration_count)

        logger.debug("pbkdf2 timing: %f seconds", time.time() - t0)

        client_key = hmac.new(
            salted_password,
            b"Client Key",
            hashfun_factory).digest()

        stored_key = hashfun_factory(client_key).digest()

        reply = b"c=" + base64.b64encode(b"n,,") + b",r=" + nonce

        auth_message += b"," + reply

        client_proof = (
            int.from_bytes(
                hmac.new(
                    stored_key,
                    auth_message,
                    hashfun_factory).digest(),
                "big") ^
            int.from_bytes(client_key, "big")).to_bytes(digest_size, "big")

        logger.debug("response generation time: %f seconds", time.time() - t0)
        try:
            state, payload = yield from sm.response(
                reply + b",p=" + base64.b64encode(client_proof)
            )
        except SASLFailure as err:
            raise err.promote_to_authentication_failure() from None

        if state != "success":
            raise SASLFailure(
                "malformed-request",
                text="SCRAM protocol violation")

        server_signature = hmac.new(
            hmac.new(
                salted_password,
                b"Server Key",
                hashfun_factory).digest(),
            auth_message,
            hashfun_factory).digest()

        payload = dict(self.parse_message(payload))

        if base64.b64decode(payload[b"v"]) != server_signature:
            raise SASLFailure(
                None,
                "authentication successful, but server signature invalid")

        return True


class ANONYMOUS(SASLMechanism):
    """
    The ANONYMOUS SASL mechanism (see :rfc:`4505`).

    .. versionadded:: 0.3
    """

    def __init__(self, token):
        super().__init__()
        self._token = trace(token).encode("utf-8")

    @classmethod
    def any_supported(self, mechanisms):
        if "ANONYMOUS" in mechanisms:
            return "ANONYMOUS"
        return None

    @asyncio.coroutine
    def authenticate(self, sm, mechanism):
        logger.info("attempting ANONYMOUS mechanism")

        state, _ = yield from sm.initiate(
            mechanism="ANONYMOUS",
            payload=self._token
        )

        if state != "success":
            raise SASLFailure(
                None,
                text="SASL protocol violation")

        return True
