"""
Unit tests for module ygate2
Yaesu APRS IGate
"""
from unittest import TestCase, mock
from unittest.mock import patch
from ygate2 import Ygate2

class TestYgate2(TestCase):

    def setUp(self) -> None:
        self.lcl_ygate2 = Ygate2()

    def test_init_ok(self):
        self.assertTrue(self.lcl_ygate2)

    def test_is_class(self):
        self.assertIsInstance(self.lcl_ygate2, Ygate2)

