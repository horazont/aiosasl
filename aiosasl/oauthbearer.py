########################################################################
# File name: oauthbearer.py
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
import json

from . import common, statemachine


logger = logging.getLogger(__name__)


class OAUTHBEARER(statemachine.SASLMechanism):
    """
    The OAUTHBEARER SASL mechanism (see :rfc:`7628`).

    `credential_provider` must be coroutine which that takes a dict and returns
    a ``(user, token)`` tuple.

    .. versionadded:: devel
    """

    def __init__(self, credential_provider) -> None:
        super().__init__()
        self._credential_provider = credential_provider

    @classmethod
    def any_supported(
        self,
        mechanisms: typing.Iterable[str],
    ) -> typing.Optional[str]:
        if "OAUTHBEARER" in mechanisms:
            return "OAUTHBEARER"
        return None

    async def authenticate(
        self, sm: statemachine.SASLStateMachine, mechanism: typing.Any
    ) -> None:
        logger.info("attempting OAUTHBEARER mechanism")

        infos = None
        while True:
            authz, headers = await self._credential_provider(infos)
            if headers is str:
                headers = {"auth": "Bearer " + headers}

            kvsep = b"\1"
            client_resp = kvsep
            kvpairs = b"".join(
                [
                    k.encode("utf-8") + b"=" + v.encode("utf-8") + kvsep
                    for k, v in kv.items()
                ]
            )
            gs2_header = b""

            client_resp = gs2_header + kvsep + kvpairs + kvsep

            state, payload = await sm.initiate(
                mechanism="OAUTHBEARER", payload=client_resp
            )

            if state == common.SASLState.CHALLENGE:
                await sm.respond(b"\1")
                infos = json.decode(payload)
            else:
                break

        if state != common.SASLState.SUCCESS:
            raise common.SASLFailure(None, text="SASL protocol violation")

        # SUCCESS?
