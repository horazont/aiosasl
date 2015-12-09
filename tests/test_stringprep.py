import unittest

from aiosasl.stringprep import (
    saslprep,
    check_bidi
)


class Testcheck_bidi(unittest.TestCase):
    # some test cases which are not covered by the other tests
    def test_empty_string(self):
        check_bidi("")

    def test_L_RAL_violation(self):
        with self.assertRaises(ValueError):
            check_bidi("\u05be\u0041")


class TestSASLprep(unittest.TestCase):
    def test_map_to_nothing_rfcx(self):
        self.assertEqual(
            "IX",
            saslprep("I\u00ADX"),
            "SASLprep requirement: map SOFT HYPHEN to nothing")

    def test_map_to_space(self):
        self.assertEqual(
            "I X",
            saslprep("I\u00A0X"),
            "SASLprep requirement: map SOFT HYPHEN to nothing")

    def test_identity_rfcx(self):
        self.assertEqual(
            "user",
            saslprep("user"),
            "SASLprep requirement: identity transform")

    def test_case_preservation_rfcx(self):
        self.assertEqual(
            "USER",
            saslprep("USER"),
            "SASLprep requirement: preserve case")

    def test_nfkc_rfcx(self):
        self.assertEqual(
            "a",
            saslprep("\u00AA"),
            "SASLprep requirement: NFKC")
        self.assertEqual(
            "IX",
            saslprep("\u2168"),
            "SASLprep requirement: NFKC")

    def test_prohibited_character_rfcx(self):
        with self.assertRaises(
                ValueError,
                msg="SASLprep requirement: prohibited character (C.2.1)"):
            saslprep("\u0007")

        with self.assertRaises(
                ValueError,
                msg="SASLprep requirement: prohibited character (C.8)"):
            saslprep("\u200E")

    def test_bidirectional_check_rfcx(self):
        with self.assertRaises(
                ValueError,
                msg="SASLprep requirement: bidirectional check"):
            saslprep("\u0627\u0031")

    def test_unassigned(self):
        with self.assertRaises(
                ValueError,
                msg="SASLprep requirement: unassigned"):
            saslprep("\u0221", allow_unassigned=False)

        with self.assertRaises(
                ValueError,
                msg="enforce no unassigned by default"):
            saslprep("\u0221")

        self.assertEqual(
            "\u0221",
            saslprep("\u0221", allow_unassigned=True))
