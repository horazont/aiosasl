########################################################################
# File name: channel_binding_methods.py
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
Channel binding methods
=======================

The module :mod:`aiosasl.channel_binding_methods` provides
implementations of the :class:`~aiosasl.ChannelBindingProvider`
interface for use with :mod:`ssl` respective :mod:`OpenSSL`.

.. autoclass:: StdlibTLS

.. autoclass:: TLSUnique

.. autoclass:: TLSServerEndPoint
"""
import functools
import ssl

try:
    import OpenSSL  # for mypy
except ImportError:
    pass

from . import ChannelBindingProvider


class StdlibTLS(ChannelBindingProvider):
    """
    Provider for channel binding for :mod:`ssl`.

    :param connection: the SSL connection
    :type connection: :class:`ssl.SSLSocket`
    :param type_: the channel binding type
    :type type_: :class:`str`
    """

    def __init__(
            self,
            connection: ssl.SSLSocket,
            type_: str):
        super().__init__()
        self._connection = connection
        self._type = type_

    @property
    def cb_name(self) -> bytes:
        return self._type.encode("us-ascii")

    def extract_cb_data(self) -> bytes:
        return self._connection.get_channel_binding(self._type)  # type:ignore


class TLSUnique(ChannelBindingProvider):
    """
    Provider for the channel binding ``tls-unique`` as specified by
    :rfc:`5929` for :mod:`OpenSSL`.

    .. warning::

       This only supports connections that were not created by session
       resumption.

    :param connection: the SSL connection
    :type connection: :class:`OpenSSL.SSL.Connection`
    """

    def __init__(self, connection: "OpenSSL.SSL.Connection"):
        super().__init__()
        self._connection = connection

    @property
    def cb_name(self) -> bytes:
        return b"tls-unique"

    def extract_cb_data(self) -> bytes:
        return self._connection.get_finished()


def parse_openssl_digest(
        digest: bytes,
        ) -> bytes:
    return bytes(map(functools.partial(int, base=16), digest.split(b":")))


class TLSServerEndPoint(ChannelBindingProvider):
    """
    Provider for the channel binding ``tls-server-end-point`` as
    specified by :rfc:`5929` for :mod:`OpenSSL`.

    :param connection: the SSL connection
    :type connection: :class:`OpenSSL.SSL.Connection`
    """

    def __init__(
            self,
            connection: "OpenSSL.SSL.Connection"):
        super().__init__()
        self._connection = connection

    @property
    def cb_name(self) -> bytes:
        return b"tls-server-end-point"

    def extract_cb_data(self) -> bytes:
        cert = self._connection.get_peer_certificate()
        algo, part, _ = cert.get_signature_algorithm().lower().partition(
            b"with")
        if not part:
            raise NotImplementedError
        if algo in (b"sha1", b"md5"):
            algo = b"sha256"
        return parse_openssl_digest(cert.digest(algo.decode("us-ascii")))
