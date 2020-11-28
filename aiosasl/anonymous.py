########################################################################
# File name: anonymous.py
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
import logging
import typing

from . import common, statemachine, stringprep


logger = logging.getLogger()


class ANONYMOUS(statemachine.SASLMechanism):
    """
    The ANONYMOUS SASL mechanism (see :rfc:`4505`).

    .. versionadded:: 0.3
    """

    def __init__(self, token: str) -> None:
        super().__init__()
        self._token = stringprep.trace(token).encode("utf-8")

    @classmethod
    def any_supported(
            self,
            mechanisms: typing.Iterable[str],
            ) -> typing.Optional[str]:
        if "ANONYMOUS" in mechanisms:
            return "ANONYMOUS"
        return None

    async def authenticate(
            self,
            sm: statemachine.SASLStateMachine,
            mechanism: typing.Any) -> None:
        logger.info("attempting ANONYMOUS mechanism")

        state, _ = await sm.initiate(
            mechanism="ANONYMOUS",
            payload=self._token
        )

        if state != common.SASLState.SUCCESS:
            raise common.SASLFailure(
                None,
                text="SASL protocol violation")
