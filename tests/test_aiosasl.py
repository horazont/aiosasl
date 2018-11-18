########################################################################
# File name: test_aiosasl.py
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
import asyncio
import base64
import hashlib
import hmac
import unittest
import unittest.mock

import aiosasl

from aiosasl.channel_binding_methods import TLSUnique
from aiosasl.utils import xor_bytes


def run_coroutine(coroutine, timeout=1.0, loop=None):
    if not loop:
        loop = asyncio.get_event_loop()
    return loop.run_until_complete(
        asyncio.wait_for(
            coroutine,
            timeout=timeout))


class CoroutineMock(unittest.mock.Mock):
    delay = 0

    @asyncio.coroutine
    def __call__(self, *args, **kwargs):
        result = super().__call__(*args, **kwargs)
        yield from asyncio.sleep(self.delay)
        return result


class SASLInterfaceMock(aiosasl.SASLInterface):
    def __init__(self, testobj, action_sequence):
        super().__init__()
        self._testobj = testobj
        self._action_sequence = action_sequence

    def _check_action(self, action, payload):
        try:
            (next_action,
             next_payload,
             new_state,
             result_payload) = self._action_sequence.pop(0)
        except ValueError:
            raise AssertionError(
                "SASL action performed unexpectedly: "
                "{} with payload {}".format(
                    action,
                    payload))

        self._state = new_state

        self._testobj.assertEqual(
            action,
            next_action,
            "SASL action sequence violated")

        self._testobj.assertEqual(
            payload,
            next_payload,
            "SASL payload expectation violated")

        if new_state == "failure" and action != "abort":
            opaque_error, text = result_payload
            raise aiosasl.SASLFailure(opaque_error, text=text)

        if result_payload is not None:
            result_payload = result_payload

        return new_state, result_payload

    @asyncio.coroutine
    def initiate(self, mechanism, payload=None):
        return self._check_action("auth;"+mechanism, payload)

    @asyncio.coroutine
    def respond(self, payload):
        return self._check_action("response", payload)

    @asyncio.coroutine
    def abort(self):
        return self._check_action("abort", None)

    def finalize(self):
        self._testobj.assertFalse(
            self._action_sequence,
            "Not all actions performed")


class TestSASLState(unittest.TestCase):

    def test_from_reply(self):
        self.assertEqual(
            aiosasl.SASLState.from_reply("success"),
            aiosasl.SASLState.SUCCESS
        )

        self.assertEqual(
            aiosasl.SASLState.from_reply("failure"),
            aiosasl.SASLState.FAILURE
        )

        self.assertEqual(
            aiosasl.SASLState.from_reply("challenge"),
            aiosasl.SASLState.CHALLENGE
        )

        self.assertEqual(
            aiosasl.SASLState.from_reply(aiosasl.SASLState.SUCCESS),
            aiosasl.SASLState.SUCCESS
        )

        self.assertEqual(
            aiosasl.SASLState.from_reply(aiosasl.SASLState.FAILURE),
            aiosasl.SASLState.FAILURE
        )

        self.assertEqual(
            aiosasl.SASLState.from_reply(aiosasl.SASLState.CHALLENGE),
            aiosasl.SASLState.CHALLENGE
        )

        with self.assertRaises(RuntimeError):
            aiosasl.SASLState.from_reply("initial"),

        with self.assertRaises(RuntimeError):
            aiosasl.SASLState.from_reply("success-simulate-initial"),

        with self.assertRaises(RuntimeError):
            aiosasl.SASLState.from_reply(aiosasl.SASLState.INITIAL),

        with self.assertRaises(RuntimeError):
            aiosasl.SASLState.from_reply(
                aiosasl.SASLState.SUCCESS_SIMULATE_CHALLENGE),


class TestSASLStateMachine(unittest.TestCase):
    def setUp(self):
        self.loop = asyncio.get_event_loop()
        self.intf = unittest.mock.Mock()
        self.intf.initiate = CoroutineMock()
        self.intf.respond = CoroutineMock()
        self.intf.abort = CoroutineMock()
        self.sm = aiosasl.SASLStateMachine(self.intf)

        self.intf.initiate.return_value = (aiosasl.SASLState.SUCCESS, None)

    def test_initiate_calls_to_interface(self):
        result = run_coroutine(
            self.sm.initiate("foo", b"bar")
        )

        self.intf.initiate.assert_called_with(
            "foo",
            payload=b"bar")

        self.assertEqual(
            run_coroutine(self.intf.initiate()),
            result
        )

    def test_reject_double_initiate(self):
        run_coroutine(self.sm.initiate("foo", b"bar"))

        with self.assertRaisesRegexp(RuntimeError,
                                     "has already been called"):
            run_coroutine(self.sm.initiate("foo"))

    def test_reject_double_initiate_after_error(self):
        opaque_error = object()
        self.intf.initiate.side_effect = aiosasl.SASLFailure(
            opaque_error
        )

        with self.assertRaises(aiosasl.SASLFailure):
            run_coroutine(self.sm.initiate("foo", b"bar"))

        with self.assertRaisesRegexp(RuntimeError,
                                     "has already been called"):
            run_coroutine(self.sm.initiate("foo"))

    def test_reject_response_without_challenge(self):
        with self.assertRaisesRegexp(RuntimeError,
                                     "no challenge"):
            run_coroutine(self.sm.response(b"bar"))

    def test_response_calls_to_interface(self):
        self.sm._state = aiosasl.SASLState.CHALLENGE
        self.intf.respond.return_value = (aiosasl.SASLState.SUCCESS, None)

        result = run_coroutine(
            self.sm.response(b"bar")
        )

        self.intf.respond.assert_called_with(b"bar")

        self.assertEqual(
            run_coroutine(self.intf.initiate()),
            result
        )

    def test_response_failure(self):
        opaque_error = object()
        self.sm._state = aiosasl.SASLState.CHALLENGE
        self.intf.respond.side_effect = aiosasl.SASLFailure(
            opaque_error
        )

        with self.assertRaises(aiosasl.SASLFailure):
            run_coroutine(
                self.sm.response(b"bar")
            )

        self.assertEqual(self.sm._state, aiosasl.SASLState.FAILURE)

    def test_reject_abort_without_initiate(self):
        with self.assertRaises(RuntimeError):
            run_coroutine(self.sm.abort())

    def test_abort_calls_to_interface(self):
        self.sm._state = "challenge"
        self.intf.abort.return_value = ("failure", None)

        self.assertEqual(
            ("failure", None),
            run_coroutine(self.sm.abort())
        )

        self.intf.abort.assert_called_with()
        self.assertEqual(self.sm._state, aiosasl.SASLState.FAILURE)

    def test_abort_set_to_failure_and_re_raise_exceptions(self):
        exc = Exception()
        self.sm._state = aiosasl.SASLState.CHALLENGE
        self.intf.abort.side_effect = exc

        with self.assertRaises(Exception) as ctx:
            run_coroutine(self.sm.abort())

        self.assertIs(ctx.exception, exc)

        self.intf.abort.assert_called_with()
        self.assertEqual(self.sm._state, aiosasl.SASLState.FAILURE)

    def test_success_simulated_challenge(self):
        self.sm._state = aiosasl.SASLState.CHALLENGE
        self.intf.respond.return_value = ("success", b"payload")
        state, payload = run_coroutine(self.sm.response(b"foobar"))
        self.assertEqual(self.sm._state,
                         aiosasl.SASLState.SUCCESS_SIMULATE_CHALLENGE)
        self.assertEqual(state, aiosasl.SASLState.CHALLENGE)
        self.assertEqual(payload, b"payload")
        state, payload = run_coroutine(self.sm.response(b""))
        self.assertEqual(state, aiosasl.SASLState.SUCCESS)
        self.assertEqual(payload, None)

    def test_success_simulated_challenge_protocol_violation(self):
        self.sm._state = aiosasl.SASLState.SUCCESS_SIMULATE_CHALLENGE
        with self.assertRaises(aiosasl.SASLFailure):
            run_coroutine(self.sm.response(b"not-empty"))
        self.assertEqual(self.sm._state, aiosasl.SASLState.FAILURE)

    def tearDown(self):
        del self.sm
        del self.intf
        del self.loop


class TestPLAIN(unittest.TestCase):
    def test_rfc(self):
        user = "tim"
        password = "tanstaaftanstaaf"

        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;PLAIN",
                 b"\0tim\0tanstaaftanstaaf",
                 "success",
                 None)
            ]))

        @asyncio.coroutine
        def provide_credentials(*args):
            return user, password

        def run():
            plain = aiosasl.PLAIN(provide_credentials)
            result = yield from plain.authenticate(
                smmock,
                "PLAIN")
            self.assertTrue(result)

        asyncio.get_event_loop().run_until_complete(run())

        smmock.interface.finalize()

    def test_fail_on_protocol_violation(self):
        user = "tim"
        password = "tanstaaftanstaaf"

        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;PLAIN",
                 b"\0tim\0tanstaaftanstaaf",
                 "challenge",
                 b"foo")
            ]))

        @asyncio.coroutine
        def provide_credentials(*args):
            return user, password

        def run():
            plain = aiosasl.PLAIN(provide_credentials)
            yield from plain.authenticate(
                smmock,
                "PLAIN")

        with self.assertRaisesRegexp(aiosasl.SASLFailure,
                                     "protocol violation") as ctx:
            asyncio.get_event_loop().run_until_complete(run())

        self.assertEqual(
            None,
            ctx.exception.opaque_error
        )

        smmock.interface.finalize()

    def test_reject_NUL_bytes_in_username(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
            ]))

        @asyncio.coroutine
        def provide_credentials(*args):
            return "\0", "foo"

        with self.assertRaises(ValueError):
            run_coroutine(
                aiosasl.PLAIN(provide_credentials).authenticate(
                    smmock,
                    "PLAIN")
            )

    def test_reject_NUL_bytes_in_password(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
            ]))

        @asyncio.coroutine
        def provide_credentials(*args):
            return "foo", "\0"

        with self.assertRaises(ValueError):
            run_coroutine(
                aiosasl.PLAIN(provide_credentials).authenticate(smmock, "PLAIN")
            )

    def test_supports_PLAIN(self):
        self.assertEqual(
            "PLAIN",
            aiosasl.PLAIN.any_supported(["PLAIN"])
        )

    def test_does_not_support_SCRAM(self):
        self.assertIsNone(
            aiosasl.PLAIN.any_supported(["SCRAM-SHA-1"])
        )


class TestSCRAMNegotiation(unittest.TestCase):
    def test_supports_SCRAM_famliy(self):
        hashes = ["SHA-1", "SHA-256"]

        for hashname in hashes:
            mechanism = "SCRAM-{}".format(hashname)
            self.assertEqual(
                (mechanism, unittest.mock.ANY),
                aiosasl.SCRAM.any_supported([mechanism])
            )

    def test_supports_SCRAMPLUS_famliy(self):
        hashes = ["SHA-1", "SHA-256"]

        for hashname in hashes:
            mechanism = "SCRAM-{}-PLUS".format(hashname)
            self.assertEqual(
                (mechanism, unittest.mock.ANY),
                aiosasl.SCRAMPLUS.any_supported([mechanism])
            )

    def test_pick_longest_hash_SCRAM(self):
        self.assertEqual(
            ("SCRAM-SHA-256", unittest.mock.ANY),
            aiosasl.SCRAM.any_supported([
                "SCRAM-SHA-1",
                "SCRAM-SHA-256",
                "PLAIN",
            ])
        )

    def test_no_support_for_unregistered_functions(self):
        self.assertEqual(
            ("SCRAM-SHA-256", unittest.mock.ANY),
            aiosasl.SCRAM.any_supported([
                "SCRAM-SHA-1",
                "SCRAM-SHA-256",
                "SCRAM-SHA-512",
                "PLAIN",
            ])
        )

    def test_pick_longest_hash_SCRAMPLUS(self):
        self.assertEqual(
            ("SCRAM-SHA-256-PLUS", unittest.mock.ANY),
            aiosasl.SCRAMPLUS.any_supported([
                "SCRAM-SHA-1-PLUS",
                "SCRAM-SHA-256-PLUS",
                "SCRAM-SHA-224-PLUS",
                "PLAIN",
            ])
        )

    def test_reject_scram_plus_SCRAM(self):
        hashes = ["SHA-1", "SHA-224", "SHA-256",
                  "SHA-512", "SHA-384", "SHA-256"]

        for hashname in hashes:
            mechanism = "SCRAM-{}-PLUS".format(hashname)
            self.assertIsNone(
                aiosasl.SCRAM.any_supported([mechanism])
            )

    def test_reject_scram_SCRAMPLUS(self):
        hashes = ["SHA-1", "SHA-256"]

        for hashname in hashes:
            mechanism = "SCRAM-{}".format(hashname)
            self.assertIsNone(
                aiosasl.SCRAMPLUS.any_supported([mechanism])
            )

    def test_reject_md5_SCRAM(self):
        self.assertIsNone(
            aiosasl.SCRAM.any_supported(["SCRAM-MD5"])
        )

    def test_reject_md5_SCRAMPLUS(self):
        self.assertIsNone(
            aiosasl.SCRAMPLUS.any_supported(["SCRAM-MD5-PLUS"])
        )

    def test_reject_unknown_hash_functions_SCRAM(self):
        self.assertIsNone(
            aiosasl.SCRAM.any_supported(["SCRAM-FOOBAR"])
        )

    def test_reject_unknown_hash_functions_SCRAMPLUS(self):
        self.assertIsNone(
            aiosasl.SCRAM.any_supported(["SCRAM-FOOBAR-PLUS"])
        )

    def test_parse_message_reject_long_keys_SCRAM(self):
        with self.assertRaisesRegexp(Exception, "protocol violation"):
            list(aiosasl.SCRAM.parse_message(b"foo=bar"))

    def test_parse_message_reject_long_keys_SCRAMPLUS(self):
        with self.assertRaisesRegexp(Exception, "protocol violation"):
            list(aiosasl.SCRAMPLUS.parse_message(b"foo=bar"))

    def test_parse_message_reject_m_key_SCRAM(self):
        with self.assertRaisesRegexp(Exception, "protocol violation"):
            list(aiosasl.SCRAM.parse_message(b"m=bar"))

    def test_parse_message_reject_m_key_SCRAMPLUS(self):
        with self.assertRaisesRegexp(Exception, "protocol violation"):
            list(aiosasl.SCRAMPLUS.parse_message(b"m=bar"))

    def test_parse_message_unescape_n_and_a_payload_SCRAM(self):
        data = list(aiosasl.SCRAM.parse_message(b"n=foo=2Cbar=3Dbaz,"
                                             b"a=fnord=2Cfunky=3Dfunk"))
        self.assertSequenceEqual(
            [
                (b"n", b"foo,bar=baz"),
                (b"a", b"fnord,funky=funk")
            ],
            data
        )

    def test_parse_message_unescape_n_and_a_payload_SCRAMPLUS(self):
        data = list(aiosasl.SCRAMPLUS.parse_message(
            b"n=foo=2Cbar=3Dbaz,a=fnord=2Cfunky=3Dfunk"))
        self.assertSequenceEqual(
            [
                (b"n", b"foo,bar=baz"),
                (b"a", b"fnord,funky=funk")
            ],
            data
        )


class TestSCRAMImpl:
    def setUp(self):
        self.hashfun_factory = hashlib.sha1
        self.digest_size = self.hashfun_factory().digest_size
        self.user = b"user"
        self.password = b"pencil"
        self.salt = b"QSXCR+Q6sek8bf92"

        aiosasl._system_random = unittest.mock.MagicMock()
        aiosasl._system_random.getrandbits.return_value = int.from_bytes(
            b"foo",
            "little")

        self.salted_password = aiosasl.pbkdf2(
            "sha1",
            self.password,
            self.salt,
            4096,
            self.digest_size)

        self.salted_password_4000 = aiosasl.pbkdf2(
            "sha1",
            self.password,
            self.salt,
            4000,
            self.digest_size)

        self.salted_password_5000 = aiosasl.pbkdf2(
            "sha1",
            self.password,
            self.salt,
            5000,
            self.digest_size)

        self.client_key = hmac.new(
            self.salted_password,
            b"Client Key",
            self.hashfun_factory).digest()

        self.client_key_4000 = hmac.new(
            self.salted_password_4000,
            b"Client Key",
            self.hashfun_factory).digest()

        self.client_key_5000 = hmac.new(
            self.salted_password_5000,
            b"Client Key",
            self.hashfun_factory).digest()

        self.stored_key = self.hashfun_factory(
            self.client_key).digest()

        self.stored_key_4000 = self.hashfun_factory(
            self.client_key_4000).digest()

        self.stored_key_5000 = self.hashfun_factory(
            self.client_key_5000).digest()

        self.client_first_message_bare = b"n=user,r=Zm9vAAAAAAAAAAAAAAAA"
        self.server_first_message = b"".join([
            b"r=Zm9vAAAAAAAAAAAAAAAA3rfcNHYJY1ZVvWVs7j,s=",
            base64.b64encode(self.salt),
            b",i=4096"
        ])
        self.server_first_message_4000 = b"".join([
            b"r=Zm9vAAAAAAAAAAAAAAAA3rfcNHYJY1ZVvWVs7j,s=",
            base64.b64encode(self.salt),
            b",i=4000"
        ])
        self.server_first_message_5000 = b"".join([
            b"r=Zm9vAAAAAAAAAAAAAAAA3rfcNHYJY1ZVvWVs7j,s=",
            base64.b64encode(self.salt),
            b",i=5000"
        ])

        if self._scram_plus == 'no':
            self.client_final_message_without_proof = (
                b"c=biws,r=Zm9vAAAAAAAAAAAAAAAA3rfcNHYJY1ZVvWVs7j")
        elif self._scram_plus == 'supported':
            self.client_final_message_without_proof = (
                b"c=eSws,r=Zm9vAAAAAAAAAAAAAAAA3rfcNHYJY1ZVvWVs7j")
        elif self._scram_plus == 'active':
            self.client_final_message_without_proof = (
                b"c=cD10bHMtdW5pcXVlLCxjaGFubmVsIGJpbmRpbmcgZGF0YQ==,"
                b"r=Zm9vAAAAAAAAAAAAAAAA3rfcNHYJY1ZVvWVs7j")
        else:
            raise Exception("invalid scram mode")

        self.auth_message = b",".join([
            self.client_first_message_bare,
            self.server_first_message,
            self.client_final_message_without_proof
        ])

        self.auth_message_4000 = b",".join([
            self.client_first_message_bare,
            self.server_first_message_4000,
            self.client_final_message_without_proof
        ])

        self.auth_message_5000 = b",".join([
            self.client_first_message_bare,
            self.server_first_message_5000,
            self.client_final_message_without_proof
        ])

        self.client_signature = hmac.new(
            self.stored_key,
            self.auth_message,
            self.hashfun_factory).digest()

        self.client_signature_4000 = hmac.new(
            self.stored_key_4000,
            self.auth_message_4000,
            self.hashfun_factory).digest()

        self.client_signature_5000 = hmac.new(
            self.stored_key_5000,
            self.auth_message_5000,
            self.hashfun_factory).digest()

        self.client_proof = xor_bytes(self.client_signature, self.client_key)
        self.client_proof_4000 = xor_bytes(self.client_signature_4000,
                                           self.client_key_4000)
        self.client_proof_5000 = xor_bytes(self.client_signature_5000,
                                           self.client_key_5000)

        self.server_key = hmac.new(
            self.salted_password,
            b"Server Key",
            self.hashfun_factory).digest()
        self.server_key_4000 = hmac.new(
            self.salted_password_4000,
            b"Server Key",
            self.hashfun_factory).digest()
        self.server_key_5000 = hmac.new(
            self.salted_password_5000,
            b"Server Key",
            self.hashfun_factory).digest()
        self.server_signature = hmac.new(
            self.server_key,
            self.auth_message,
            self.hashfun_factory).digest()
        self.server_signature_4000 = hmac.new(
            self.server_key_4000,
            self.auth_message_4000,
            self.hashfun_factory).digest()
        self.server_signature_5000 = hmac.new(
            self.server_key_5000,
            self.auth_message_5000,
            self.hashfun_factory).digest()

        self._tls_connection = unittest.mock.Mock()
        self._tls_connection.get_finished = unittest.mock.Mock()
        self._tls_connection.get_finished.return_value = \
            b'channel binding data'

    @asyncio.coroutine
    def _provide_credentials(self, *args):
        return ("user", "pencil")

    def _run(self, smmock, scram):
        info = aiosasl.SCRAMBase._supported_hashalgos["SHA-1"]
        if self._scram_plus in ('no', 'supported'):
            token = ("SCRAM-SHA-1", info)
        else:
            token = ("SCRAM-SHA-1-PLUS", info)

        result = asyncio.get_event_loop().run_until_complete(
            scram.authenticate(smmock, token)
        )
        smmock.interface.finalize()
        return result

    def tearDown(self):
        import random
        aiosasl._system_random = random.SystemRandom()


class TestSCRAM(TestSCRAMImpl, unittest.TestCase):
    _scram_plus = 'no'

    def test_rfc(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 self.client_final_message_without_proof +
                     b",p="+base64.b64encode(self.client_proof),
                 "success",
                 b"v="+base64.b64encode(self.server_signature))
            ]))

        self.assertTrue(self._run(
            smmock,
            aiosasl.SCRAM(self._provide_credentials)
        ))

    def test_malformed_reply(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,,"+self.client_first_message_bare,
                 "challenge",
                 b"s=hut,t=hefu,c=kup,d=onny"),
                ("abort", None,
                 "failure", ("aborted", None))
            ]))

        with self.assertRaises(aiosasl.SASLFailure) as ctx:
            self._run(smmock, aiosasl.SCRAM(self._provide_credentials))

        self.assertIn(
            "malformed",
            str(ctx.exception).lower()
        )

    def test_other_malformed_reply(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,,"+self.client_first_message_bare,
                 "challenge",
                 b"i=sometext,s=ABC,r=Zm9vAAAAAAAAAAAAAAAA3rfcNHYJY1ZVvWVs7j"),
                ("abort", None,
                 "failure", ("aborted", None))
            ]))

        with self.assertRaises(aiosasl.SASLFailure) as ctx:
            self._run(smmock, aiosasl.SCRAM(self._provide_credentials))

        self.assertIn(
            "malformed",
            str(ctx.exception).lower()
        )

    def test_incorrect_nonce(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,,"+self.client_first_message_bare,
                 "challenge",
                 b"r=foobar,s="+base64.b64encode(self.salt)+b",i=4096"),
                ("abort", None,
                 "failure", ("aborted", None))
            ]))

        with self.assertRaisesRegexp(aiosasl.SASLFailure, "nonce") as ctx:
            self._run(smmock, aiosasl.SCRAM(self._provide_credentials))

        self.assertIsNone(ctx.exception.opaque_error)

    def test_invalid_signature(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 self.client_final_message_without_proof +
                     b",p="+base64.b64encode(self.client_proof),
                 "success",
                 b"v="+base64.b64encode(b"fnord"))
            ]))

        with self.assertRaises(aiosasl.SASLFailure) as ctx:
            self._run(smmock, aiosasl.SCRAM(self._provide_credentials))

        self.assertIsNone(ctx.exception.opaque_error)
        self.assertIn(
            "signature",
            str(ctx.exception).lower()
        )

    def test_promote_failure_to_authentication_failure(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 self.client_final_message_without_proof +
                     b",p="+base64.b64encode(self.client_proof),
                 "failure",
                 ("credentials-expired", None))
            ]))

        with self.assertRaises(aiosasl.AuthenticationFailure) as ctx:
            self._run(smmock, aiosasl.SCRAM(self._provide_credentials))

        self.assertEqual(
            "credentials-expired",
            ctx.exception.opaque_error
        )

    def test_reject_protocol_violation_1(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 self.client_final_message_without_proof +
                     b",p="+base64.b64encode(self.client_proof),
                 "success",
                 None),
            ]))

        with self.assertRaisesRegexp(aiosasl.SASLFailure,
                                     "protocol violation") as ctx:
            self._run(smmock, aiosasl.SCRAM(self._provide_credentials))

        self.assertEqual(
            "malformed-request",
            ctx.exception.opaque_error
        )

    def test_reject_protocol_violation_2(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,,"+self.client_first_message_bare,
                 "success", None),
                ("abort", None,
                 "failure", ("aborted", None)),
            ]))

        with self.assertRaisesRegexp(aiosasl.SASLFailure,
                                     "protocol violation") as ctx:
            self._run(smmock, aiosasl.SCRAM(self._provide_credentials))

        self.assertEqual(
            None,
            ctx.exception.opaque_error
        )

    def test_too_low_iteration_count(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message.replace(b",i=4096", b",i=4095")),
                ("abort", None,
                 "failure", ("aborted", None)),
            ]))

        with self.assertRaisesRegexp(
                aiosasl.SASLFailure,
                r"minimum iteration count for SCRAM-SHA-1 violated "
                r"\(4095 is less than 4096\)") as ctx:
            self._run(smmock, aiosasl.SCRAM(self._provide_credentials))

        self.assertEqual(
            None,
            ctx.exception.opaque_error
        )

    def test_too_low_iteration_count_without_enforcement(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message_4000),
                ("response",
                 self.client_final_message_without_proof +
                     b",p="+base64.b64encode(self.client_proof_4000),
                 "success",
                 b"v="+base64.b64encode(self.server_signature_4000))
            ]))

        self.assertTrue(self._run(
            smmock,
            aiosasl.SCRAM(
                self._provide_credentials,
                enforce_minimum_iteration_count=False,
            )
        ))

    def test_high_iteration_count(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"n,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message_5000),
                ("response",
                 self.client_final_message_without_proof +
                     b",p="+base64.b64encode(self.client_proof_5000),
                 "success",
                 b"v="+base64.b64encode(self.server_signature_5000))
            ]))

        self.assertTrue(self._run(
            smmock,
            aiosasl.SCRAM(self._provide_credentials)
        ))


class TestSCRAMDowngradeProtection(TestSCRAMImpl, unittest.TestCase):
    _scram_plus = 'supported'

    def test_rfc_with_downgrade_protection(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1",
                 b"y,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 self.client_final_message_without_proof +
                     b",p="+base64.b64encode(self.client_proof),
                 "success",
                 b"v="+base64.b64encode(self.server_signature))
            ]))

        self.assertTrue(self._run(
            smmock,
            aiosasl.SCRAM(self._provide_credentials, after_scram_plus=True)
        ))


class TestSCRAMPLUS(TestSCRAMImpl, unittest.TestCase):
    _scram_plus = 'active'

    def test_rfc(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1-PLUS",
                 b"p=tls-unique,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 self.client_final_message_without_proof +
                     b",p="+base64.b64encode(self.client_proof),
                 "success",
                 b"v="+base64.b64encode(self.server_signature))
            ]))

        self.assertTrue(self._run(
            smmock,
            aiosasl.SCRAMPLUS(
                self._provide_credentials,
                TLSUnique(self._tls_connection)
            )
        ))

    def test_malformed_reply(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1-PLUS",
                 b"p=tls-unique,,"+self.client_first_message_bare,
                 "challenge",
                 b"s=hut,t=hefu,c=kup,d=onny"),
                ("abort", None,
                 "failure", ("aborted", None))
            ]))

        with self.assertRaises(aiosasl.SASLFailure) as ctx:
            self._run(
                smmock,
                aiosasl.SCRAMPLUS(
                    self._provide_credentials,
                    TLSUnique(self._tls_connection)
                )
            )

        self.assertIn(
            "malformed",
            str(ctx.exception).lower()
        )

    def test_other_malformed_reply(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1-PLUS",
                 b"p=tls-unique,,"+self.client_first_message_bare,
                 "challenge",
                 b"i=sometext,s=ABC,r=Zm9vAAAAAAAAAAAAAAAA3rfcNHYJY1ZVvWVs7j"),
                ("abort", None,
                 "failure", ("aborted", None))
            ]))

        with self.assertRaises(aiosasl.SASLFailure) as ctx:
            self._run(
                smmock,
                aiosasl.SCRAMPLUS(
                    self._provide_credentials,
                    TLSUnique(self._tls_connection)
                )
            )

        self.assertIn(
            "malformed",
            str(ctx.exception).lower()
        )

    def test_incorrect_nonce(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1-PLUS",
                 b"p=tls-unique,,"+self.client_first_message_bare,
                 "challenge",
                 b"r=foobar,s="+base64.b64encode(self.salt)+b",i=4096"),
                ("abort", None,
                 "failure", ("aborted", None))
            ]))

        with self.assertRaisesRegexp(aiosasl.SASLFailure, "nonce") as ctx:
            self._run(
                smmock,
                aiosasl.SCRAMPLUS(
                    self._provide_credentials,
                    TLSUnique(self._tls_connection)
                )
            )

        self.assertIsNone(ctx.exception.opaque_error)

    def test_invalid_signature(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1-PLUS",
                 b"p=tls-unique,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 self.client_final_message_without_proof +
                     b",p="+base64.b64encode(self.client_proof),
                 "success",
                 b"v="+base64.b64encode(b"fnord"))
            ]))

        with self.assertRaises(aiosasl.SASLFailure) as ctx:
            self._run(
                smmock,
                aiosasl.SCRAMPLUS(
                    self._provide_credentials,
                    TLSUnique(self._tls_connection)
                )
            )

        self.assertIsNone(ctx.exception.opaque_error)
        self.assertIn(
            "signature",
            str(ctx.exception).lower()
        )

    def test_promote_failure_to_authentication_failure(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1-PLUS",
                 b"p=tls-unique,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 self.client_final_message_without_proof +
                     b",p="+base64.b64encode(self.client_proof),
                 "failure",
                 ("credentials-expired", None))
            ]))

        with self.assertRaises(aiosasl.AuthenticationFailure) as ctx:
            self._run(
                smmock,
                aiosasl.SCRAMPLUS(
                    self._provide_credentials,
                    TLSUnique(self._tls_connection)
                )
            )

        self.assertEqual(
            "credentials-expired",
            ctx.exception.opaque_error
        )

    def test_reject_protocol_violation(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;SCRAM-SHA-1-PLUS",
                 b"p=tls-unique,,"+self.client_first_message_bare,
                 "challenge",
                 self.server_first_message),
                ("response",
                 self.client_final_message_without_proof +
                     b",p="+base64.b64encode(self.client_proof),
                 "challenge",
                 b"foo"),
                ("response", b"", "success", b"bar")
            ]))

        with self.assertRaisesRegexp(aiosasl.SASLFailure,
                                     "protocol violation") as ctx:
            self._run(
                smmock,
                aiosasl.SCRAMPLUS(
                    self._provide_credentials,
                    TLSUnique(self._tls_connection)
                )
            )

        self.assertEqual(
            None,
            ctx.exception.opaque_error
        )


class TestANONYMOUS(unittest.TestCase):
    def test_accepts_ANONYMOUS(self):
        self.assertIsNotNone(
            aiosasl.ANONYMOUS.any_supported(["ANONYMOUS"])
        )

    def test_passes_token_through_trace(self):
        with unittest.mock.patch("aiosasl.trace") as trace:
            trace.return_value = "traced"

            anon = aiosasl.ANONYMOUS(unittest.mock.sentinel.token)

        trace.assert_called_with(unittest.mock.sentinel.token)

        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;ANONYMOUS",
                 b"traced",
                 "success",
                 None)
            ]))

        def run():
            result = yield from anon.authenticate(
                smmock,
                "ANONYMOUS")
            self.assertTrue(result)

        asyncio.get_event_loop().run_until_complete(run())

        smmock.interface.finalize()

    def test_simply_sends_token(self):
        smmock = aiosasl.SASLStateMachine(SASLInterfaceMock(
            self,
            [
                ("auth;ANONYMOUS",
                 b"sirhc",
                 "success",
                 None)
            ]))

        def run():
            anon = aiosasl.ANONYMOUS("sirhc")
            result = yield from anon.authenticate(
                smmock,
                "ANONYMOUS")
            self.assertTrue(result)

        asyncio.get_event_loop().run_until_complete(run())

        smmock.interface.finalize()
