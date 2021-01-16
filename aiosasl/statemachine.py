########################################################################
# File name: statemachine.py
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
import abc
import typing

from . import common


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
    async def initiate(
            self,
            mechanism: str,
            payload: typing.Optional[bytes] = None,
            ) -> common.NextStateTuple:
        """
        Send a SASL initiation request for the given `mechanism`. Depending on
        the `mechanism`, an initial `payload` *may* be given. The `payload` is
        then a :class:`bytes` object which needs to be passed as initial
        payload during the initiation request.

        Wait for a reply by the peer and return the reply as a next-state tuple
        in the format documented at :class:`SASLInterface`.
        """

    @abc.abstractmethod
    async def respond(
            self,
            payload: bytes,
            ) -> common.NextStateTuple:
        """
        Send a response to a challenge. The `payload` is a :class:`bytes`
        object which is to be sent as response.

        Wait for a reply by the peer and return the reply as a next-state tuple
        in the format documented at :class:`SASLInterface`.
        """

    @abc.abstractmethod
    async def abort(self) -> None:
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

    def __init__(self, interface: "SASLInterface"):
        super().__init__()
        self.interface = interface
        self._state = common.SASLState.INITIAL

    async def initiate(
            self,
            mechanism: str,
            payload: typing.Optional[bytes] = None,
            ) -> common.NextStateTuple:
        """
        Initiate the SASL handshake and advertise the use of the given
        `mechanism`. If `payload` is not :data:`None`, it will be base64
        encoded and sent as initial client response along with the ``<auth />``
        element.

        Return the next state of the state machine as tuple (see
        :class:`SASLStateMachine` for details).
        """

        if self._state != common.SASLState.INITIAL:
            raise RuntimeError("initiate has already been called")

        try:
            next_state, payload = await self.interface.initiate(
                mechanism,
                payload=payload)
        except common.SASLFailure:
            self._state = common.SASLState.FAILURE
            raise

        next_state = common.SASLState.from_reply(next_state)
        self._state = next_state
        return next_state, payload

    async def response(
            self,
            payload: bytes,
            ) -> common.NextStateTuple:
        """
        Send a response to the previously received challenge, with the given
        `payload`. The payload is encoded using base64 and transmitted to the
        server.

        Return the next state of the state machine as tuple (see
        :class:`SASLStateMachine` for details).
        """
        if self._state == common.SASLState.SUCCESS_SIMULATE_CHALLENGE:
            if payload != b"":
                # XXX: either our mechanism is buggy or the server
                # sent SASLState.SUCCESS before all challenge-response
                # messages defined by the mechanism were sent
                self._state = common.SASLState.FAILURE
                raise common.SASLFailure(
                    None,
                    "protocol violation: mechanism did not"
                    " respond with an empty response to a"
                    " challenge with final data – this suggests"
                    " a protocol-violating early success from the server."
                )
            self._state = common.SASLState.SUCCESS
            return common.SASLState.SUCCESS, None

        if self._state != common.SASLState.CHALLENGE:
            raise RuntimeError(
                "no challenge has been made or negotiation failed")

        try:
            next_state, response_payload = await self.interface.respond(
                payload,
            )
        except common.SASLFailure:
            self._state = common.SASLState.FAILURE
            raise

        next_state = common.SASLState.from_reply(next_state)

        # unfold the (SASLState.SUCCESS, payload) to a sequence of
        # (SASLState.CHALLENGE, payload), (SASLState.SUCCESS, None) for the
        # SASLMethod to allow uniform treatment of both cases
        if (next_state == common.SASLState.SUCCESS and
                response_payload is not None):
            self._state = common.SASLState.SUCCESS_SIMULATE_CHALLENGE
            return common.SASLState.CHALLENGE, response_payload

        self._state = next_state
        return next_state, response_payload

    async def abort(self) -> None:
        """
        Abort an initiated SASL authentication process. The expected result
        state is ``failure``.
        """
        if self._state == common.SASLState.INITIAL:
            raise RuntimeError("SASL authentication hasn't started yet")

        if self._state == common.SASLState.SUCCESS_SIMULATE_CHALLENGE:
            raise RuntimeError("SASL message exchange already over")

        try:
            return await self.interface.abort()
        finally:
            self._state = common.SASLState.FAILURE


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
    def any_supported(
            cls,
            mechanisms: typing.Iterable[str],
            ) -> typing.Any:
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

    async def authenticate(
            self,
            sm: SASLStateMachine,
            token: typing.Any,
            ) -> None:
        """
        Execute the mechanism identified by `token` (the non-:data:`None` value
        which has been returned by :meth:`any_supported` before) using the
        given :class:`SASLStateMachine` `sm`.

        If authentication fails, an appropriate exception is raised
        (:class:`AuthenticationFailure`). If the authentication fails for a
        reason unrelated to credentials, :class:`SASLFailure` is raised.
        """
