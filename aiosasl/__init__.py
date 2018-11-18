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
   SCRAMPLUS

Interface for protocols using SASL
==================================

To implement SASL on an existing protocol, you need to subclass
:class:`SASLInterface` and implement the abstract methods:

.. autoclass:: SASLInterface

.. autoclass:: SASLState

SASL mechansims
===============

.. autoclass:: PLAIN

.. autoclass:: SCRAM(credential_provider, *[, after_scram_plus=False][, enforce_minimum_iteration_count=True])

.. autoclass:: SCRAMPLUS(credential_provider, cb_provider, *[, enforce_minimum_iteration_count=True])

.. autoclass:: ANONYMOUS

Base class
----------

.. autoclass:: SASLMechanism

A note for implementers
-----------------------

The :class:`SASLStateMachine` unwraps `(SASLState.SUCCESS, payload)` messages
passed in from a :class:`SASLInterface` to the equivalent sequence
`(SASLState.CHALLENGE, payload)` (requiring the empty string as response) and
`(SASLState.SUCCESS, None)`. The two forms are equivalent as per the SASL
specification and this unwrapping allows uniform treatment of both
forms by the :class:`SASLMechanism` implementations.

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
import collections
import enum
import functools
import hashlib
import hmac
import logging
import random
import time

from aiosasl.stringprep import saslprep, trace
from aiosasl.utils import xor_bytes

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
                u_accum = xor_bytes(u_accum, u_curr)
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


class SASLState(enum.Enum):
    """
    The states of the SASL state machine.

    .. attribute:: CHALLENGE

       the server sent a SASL challenge

    .. attribute:: SUCCESS

       the authentication was successful

    .. attribute:: FAILURE

       the authentication failed

    Internal states used by the state machine:

    .. attribute:: INITIAL

       the state of the state machine before the
       authentication is started

    .. attribute:: SUCCESS_SIMULATE_CHALLENGE

       used to unwrap success replies that carry final data

    These internal states *must not* be returned by the
    :class:`SASLInterface` methods as first component of the result
    tuple.

    The following method is used to process replies returned
    by the :class:`SASLInterface` methods:

    .. method:: from_reply
    """

    INITIAL = "initial"
    CHALLENGE = "challenge"
    SUCCESS = "success"
    FAILURE = "failure"
    SUCCESS_SIMULATE_CHALLENGE = "success-simulate-challenge"

    @classmethod
    def from_reply(cls, state):
        """
        Comptaibility layer for old :class:`SASLInterface`
        implementations.

        Accepts the follwing set of :class:`SASLState` or strings and
        maps the strings to :class:`SASLState` elements as follows:

          ``"challenge"``
            :member:`SASLState.CHALLENGE`

           ``"failue"``
             :member:`SASLState.FAILURE`

           ``"success"``
             :member:`SASLState.SUCCESS`
        """
        if state in (SASLState.FAILURE, SASLState.SUCCESS,
                     SASLState.CHALLENGE):
            return state

        if state in ("failure", "success", "challenge"):
            return SASLState(state)
        else:
            raise RuntimeError("invalid SASL state", state)


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

    * ``(SASLState.SUCCESS, payload)`` -- After successful
      authentication, success is returned. Depending on the mechanism,
      a payload (as :class:`bytes` object) may be attached to the
      result, otherwise, ``payload`` is :data:`None`.

    * ``(SASLState.CHALLENGE, payload)`` -- A challenge was sent by
      the server in reply to the previous command.

    * ``(SASLState.FAILURE, None)`` -- This is only ever returned by
      :meth:`abort`. All other methods **must** raise errors as
      :class:`SASLFailure`.

    .. versionchanged:: 0.4

       The first element of the returned tuples are now elements of
       :class:`SASLState`. For compatibility with previous versions of
       ``aiosasl`` the first elements of the string may be one of the
       strings ``"success"``, ``"failure"`` or "``challenge``". For
       more information see :meth:`SASLState.from_reply`.

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
        (``(SASLState.FAILURE, None)``) or a :class:`SASLFailure` exception if
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
        self._state = SASLState.INITIAL

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

        if self._state != SASLState.INITIAL:
            raise RuntimeError("initiate has already been called")

        try:
            next_state, payload = yield from self.interface.initiate(
                mechanism,
                payload=payload)
        except SASLFailure:
            self._state = SASLState.FAILURE
            raise

        next_state = SASLState.from_reply(next_state)
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
        if self._state == SASLState.SUCCESS_SIMULATE_CHALLENGE:
            if payload != b"":
                # XXX: either our mechanism is buggy or the server
                # sent SASLState.SUCCESS before all challenge-response
                # messages defined by the mechanism were sent
                self._state = SASLState.FAILURE
                raise SASLFailure(
                    None,
                    "protocol violation: mechanism did not"
                    " respond with an empty response to a"
                    " challenge with final data – this suggests"
                    " a protocol-violating early success from the server."
                )
            self._state = SASLState.SUCCESS
            return SASLState.SUCCESS, None

        if self._state != SASLState.CHALLENGE:
            raise RuntimeError(
                "no challenge has been made or negotiation failed")

        try:
            next_state, payload = yield from self.interface.respond(payload)
        except SASLFailure:
            self._state = SASLState.FAILURE
            raise

        next_state = SASLState.from_reply(next_state)

        # unfold the (SASLState.SUCCESS, payload) to a sequence of
        # (SASLState.CHALLENGE, payload), (SASLState.SUCCESS, None) for the SASLMethod
        # to allow uniform treatment of both cases
        if next_state == SASLState.SUCCESS and payload is not None:
            self._state = SASLState.SUCCESS_SIMULATE_CHALLENGE
            return SASLState.CHALLENGE, payload

        self._state = next_state
        return next_state, payload

    @asyncio.coroutine
    def abort(self):
        """
        Abort an initiated SASL authentication process. The expected result
        state is ``failure``.
        """
        if self._state == SASLState.INITIAL:
            raise RuntimeError("SASL authentication hasn't started yet")

        if self._state == SASLState.SUCCESS_SIMULATE_CHALLENGE:
            raise RuntimeError("SASL message exchange already over")

        try:
            return (yield from self.interface.abort())
        finally:
            self._state = SASLState.FAILURE


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

        if state != SASLState.SUCCESS:
            raise SASLFailure(
                None,
                text="SASL protocol violation")

        return True


SCRAMHashInfo = collections.namedtuple(
    "SCRAMHashInfo",
    [
        "hashfun_name",
        "quality",
        "minimum_iteration_count",
    ]
)


class SCRAMBase:
    """
    Shared implementation of SCRAM and SCRAMPLUS.
    """

    def __init__(self, credential_provider, *, nonce_length=15,
                 enforce_minimum_iteration_count=True):
        super().__init__()
        self._credential_provider = credential_provider
        self.nonce_length = nonce_length
        self.enforce_minimum_iteration_count = enforce_minimum_iteration_count

    _supported_hashalgos = {
        # the second argument is for preference ordering (highest first)
        # if anyone has a better hash ordering suggestion, I’m open for it
        # a value of 1 is added if the -PLUS variant is used
        # -- JSC
        # the minimum iteration count is obtained from
        # <https://www.iana.org/assignments/sasl-mechanisms/sasl-mechanisms.xhtml>
        "SHA-1": SCRAMHashInfo("sha1", 1, 4096),
        "SHA-256": SCRAMHashInfo("sha256", 256, 4096),
    }

    @classmethod
    def any_supported(cls, mechanisms):
        supported = []
        for mechanism in mechanisms:
            if not mechanism.startswith("SCRAM-"):
                continue

            hashfun_key = mechanism[6:]

            if cls._channel_binding:
                if not mechanism.endswith("-PLUS"):
                    continue
                hashfun_key = hashfun_key[:-5]
            else:
                if mechanism.endswith("-PLUS"):
                    continue

            try:
                info = cls._supported_hashalgos[hashfun_key]
            except KeyError:
                continue

            supported.append(((1, info.quality), (mechanism, info,)))

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
        mechanism, info, = token
        logger.info("attempting %s mechanism (using %s hashfun)",
                    mechanism,
                    info)
        # this is pretty much a verbatim implementation of RFC 5802.

        hashfun_factory = functools.partial(hashlib.new, info.hashfun_name)

        gs2_header = self._get_gs2_header()
        username, password = yield from self._credential_provider()
        username = saslprep(username).encode("utf8")
        password = saslprep(password).encode("utf8")

        our_nonce = base64.b64encode(_system_random.getrandbits(
            self.nonce_length * 8
        ).to_bytes(
            self.nonce_length, "little"
        ))

        auth_message = b"n=" + username + b",r=" + our_nonce
        state, payload = yield from sm.initiate(
            mechanism,
            gs2_header + auth_message)

        if state != SASLState.CHALLENGE or payload is None:
            yield from sm.abort()
            raise SASLFailure(
                None,
                text="protocol violation: expected challenge with payload")

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

        if (self.enforce_minimum_iteration_count and
                iteration_count < info.minimum_iteration_count):
            raise SASLFailure(
                None,
                text="minimum iteration count for {} violated "
                "({} is less than {})".format(
                    mechanism,
                    iteration_count,
                    info.minimum_iteration_count,
                )
            )

        t0 = time.time()

        salted_password = pbkdf2(
            info.hashfun_name,
            password,
            salt,
            iteration_count)

        logger.debug("pbkdf2 timing: %f seconds", time.time() - t0)

        client_key = hmac.new(
            salted_password,
            b"Client Key",
            hashfun_factory).digest()

        stored_key = hashfun_factory(client_key).digest()

        reply = b"c=" + base64.b64encode(self._get_cb_data()) + b",r=" + nonce

        auth_message += b"," + reply

        client_proof = xor_bytes(
            hmac.new(
                stored_key,
                auth_message,
                hashfun_factory).digest(),
            client_key)

        logger.debug("response generation time: %f seconds", time.time() - t0)
        try:
            state, payload = yield from sm.response(
                reply + b",p=" + base64.b64encode(client_proof)
            )
        except SASLFailure as err:
            raise err.promote_to_authentication_failure() from None

        # this is the pseudo-challenge for the server signature
        # we have to reply with the empty string!
        if state != SASLState.CHALLENGE:
            raise SASLFailure(
                "malformed-request",
                text="SCRAM protocol violation")

        state, dummy_payload = yield from sm.response(b"")
        if state != SASLState.SUCCESS or dummy_payload is not None:
            raise SASLFailure(
                None,
                "SASL protocol violation")

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


class SCRAM(SCRAMBase, SASLMechanism):
    """
    The password-based SCRAM (non-PLUS) SASL mechanism (see :rfc:`5802`).

    :param credential_provider: A coroutine function which returns credentials.
    :param after_scram_plus: Flag to indicate that SCRAM-PLUS *is* supported by
        your implementation.
    :type after_scram_plus: :class:`bool`
    :param enforce_minimum_iteration_count: Enforce the minimum iteration
        count specified by the SCRAM specifications.
    :type enforce_minimum_iteration_count: :class:`bool`

    .. note::

       As "non-PLUS" suggests, this does not support channel binding.
       Use :class:`SCRAMPLUS` if you want channel binding.


    `credential_provider` must be coroutine function which returns a ``(user,
    password)`` tuple.

    If this is used after :class:`SCRAMPLUS` in a method list, the
    keyword argument `after_scram_plus` should be set to
    :data:`True`. Then we will use the gs2 header ``y,,`` to prevent
    down-grade attacks by a man-in-the-middle attacker.

    `enforce_minimum_iteration_count` controls the enforcement of the specified
    minimum iteration count for the key derivation function used in SCRAM. By
    default, this enforcement is enabled, and you are strongly advised to not
    disable it: it can be used to make the exchange weaker.

    Disabling `enforce_minimum_iteration_count` only makes sense if the
    authentication exchange would otherwise fall back to using :class:`PLAIN`
    or a similarly weak authentication mechanism.

    .. versionchanged:: 0.4

        The `enforce_minimum_iteration_count` argument and the behaviour to
        enforce the minimum iteration count by default was added.
    """
    _channel_binding = False

    def __init__(self, credential_provider, *, after_scram_plus=False,
                 **kwargs):
        super().__init__(credential_provider, **kwargs)
        self._after_scram_plus = after_scram_plus

    def _get_gs2_header(self):
        if self._after_scram_plus:
            return b"y,,"
        else:
            return b"n,,"

    def _get_cb_data(self):
        return self._get_gs2_header()


class ChannelBindingProvider(metaclass=abc.ABCMeta):
    """
    Interface for a channel binding method.

    The needed external information is supplied to the constructors of
    the specific instances.
    """

    @abc.abstractproperty
    def cb_name(self):
        """
        Return the name of the channel-binding mechanism.
        :rtype: :class:`bytes`
        """
        raise NotImplementedError

    @abc.abstractmethod
    def extract_cb_data(self):
        """
        Return the channel binding data.
        :returns: the channel binding data
        :rtype: :class:`bytes`
        """
        raise NotImplementedError


class SCRAMPLUS(SCRAMBase, SASLMechanism):
    """
    The password-based SCRAM-PLUS SASL mechanism (see :rfc:`5802`).

    :param credential_provider: A coroutine function which returns credentials.
    :param cb_provider: Object which provides channel binding data and
        information.
    :type cb_provider: :class:`ChannelBindingProvider`
    :param after_scram_plus: Flag to indicate that SCRAM-PLUS *is* supported by
        your implementation.
    :type after_scram_plus: :class:`bool`
    :param enforce_minimum_iteration_count: Enforce the minimum iteration
        count specified by the SCRAM specifications.
    :type enforce_minimum_iteration_count: :class:`bool`

    `credential_provider` must be coroutine which returns a ``(user,
    password)`` tuple.

    `cb_provider` must be an instance of
    :class:`ChannelBindingProvider`, which specifies and implements
    the channel binding type to use.

    `enforce_minimum_iteration_count` controls the enforcement of the specified
    minimum iteration count for the key derivation function used in SCRAM. By
    default, this enforcement is enabled, and you are strongly advised to not
    disable it: it can be used to make the exchange weaker.

    .. seealso::

        :class:`SCRAM` for more information on
        `enforce_minimum_iteration_count`.

    .. versionchanged:: 0.4

        The `enforce_minimum_iteration_count` argument and the behaviour to
        enforce the minimum iteration count by default was added.

    """
    _channel_binding = True

    def __init__(self, credential_provider, cb_provider,
                 **kwargs):
        super().__init__(credential_provider, **kwargs)
        self._cb_provider = cb_provider

    def _get_gs2_header(self):
        return b"p=" + self._cb_provider.cb_name + b",,"

    def _get_cb_data(self):
        gs2_header = self._get_gs2_header()
        cb_data = self._cb_provider.extract_cb_data()
        return gs2_header + cb_data


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

        if state != SASLState.SUCCESS:
            raise SASLFailure(
                None,
                text="SASL protocol violation")

        return True
