"""
Unit tests for functions in module ygate2
Yaesu APRS IGate V 2.0
"""
from unittest import TestCase, mock
from unittest.mock import patch
import ygate2


class TestFunctions(TestCase):

    # todo complete unit tests

    def setUp(self) -> None:
        junk = 1

    def test_decode_ascii(self):
        print("Test decode_ascii:")
        b_str = b'test byte string with 2\xb0 invalid\xef chars'
        r_str = ygate2.ygate2.decode_ascii(b_str)
        self.assertEqual(r_str[0], 2)
        print(r_str[1])
        b_str = b'test byte string with all valid ASCII chars'
        r_str = ygate2.ygate2.decode_ascii(b_str)
        print(r_str[1])
        self.assertEqual(r_str[0], 0)

    @patch("ygate2.ygate2.is_internet")
    def test_is_internet(self, mocked_method):
        # Make sure we call the module only 1 time
        mocked_method.return_value = True
        self.assertEqual(ygate2.ygate2.is_internet(), True)
        self.assertEqual(mocked_method.called, True)
        self.assertEqual(mocked_method.call_count, 1)
        self.assertEqual(ygate2.ygate2.is_internet("yaesu.com"), True)
        self.assertEqual(mocked_method.call_count, 2)

    def test_t_wrap(self):
        txt = "00:00:00 [MSG] The quick brown fox jumps over the lazy dog."
        f_txt = ygate2.ygate2.t_wrap(txt, 9)
        self.assertEqual(f_txt, txt + "\r\n")
        txt = "00:00:00 [MSG] The quick brown fox jumps over the lazy dog. " \
              "The quick brown fox jumps over the lazy dog. " \
              "The quick brown fox jumps over the lazy dog. "
        f_txt = f"00:00:00 [MSG] The quick brown fox jumps over the lazy dog. " \
                f"The quick brown fox jumps over the lazy dog. The quick brown\r\n" \
                f"               fox jumps over the lazy dog.\r\n"
        t_txt = ygate2.ygate2.t_wrap(txt, 15)
        self.assertEqual(t_txt, f_txt)

