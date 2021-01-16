########################################################################
# File name: common.py
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
import enum
import typing


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

    def __init__(
            self,
            opaque_error: typing.Any,
            kind: str,
            text: typing.Optional[str] = None):
        msg = "{}: {}".format(opaque_error, kind)
        if text:
            msg += ": {}".format(text)
        super().__init__(msg)
        self.opaque_error = opaque_error
        self.text = text


class AuthenticationFailure(SASLError):
    """
    A SASL error which indicates that the provided credentials are
    invalid. This may be raised by :class:`SASLInterface` methods.
    """

    def __init__(
            self,
            opaque_error: typing.Any,
            text: typing.Optional[str] = None):
        super().__init__(opaque_error, "authentication failed", text=text)


class SASLFailure(SASLError):
    """
    A SASL protocol failure which is unrelated to the credentials passed. This
    may be raised by :class:`SASLInterface` methods.
    """

    def __init__(
            self,
            opaque_error: typing.Any,
            text: typing.Optional[str] = None):
        super().__init__(opaque_error, "SASL failure", text=text)

    def promote_to_authentication_failure(self) -> AuthenticationFailure:
        return AuthenticationFailure(
            self.opaque_error,
            self.text)


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
    def from_reply(cls, state: "SASLState") -> "SASLState":
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


NextStateTuple = typing.Tuple[SASLState, typing.Optional[bytes]]

CredentialProvider = typing.Callable[
    [], typing.Coroutine[typing.Any, typing.Any, typing.Tuple[str, str]]
]
