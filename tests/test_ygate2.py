"""
Unit tests for module ygate2
Yaesu APRS IGate
"""
from unittest import TestCase, mock
from unittest.mock import patch
from ygate2 import Ygate2


class TestYgate2(TestCase):

    # todo: complete unit tests

    def setUp(self) -> None:
        self.lcl_ygate2 = Ygate2()

    def test_init_ok(self):
        self.assertTrue(self.lcl_ygate2)

    def test_is_class(self):
        self.assertIsInstance(self.lcl_ygate2, Ygate2)

    def test_get_data_type(self):
        d_typ = Ygate2.get_data_type(":DU1KG    : DY1P APRS 10 Watts RF-IS-RF Digipeater")
        print(d_typ)
        self.assertEqual(d_typ, "MSG ")
        d_typ = Ygate2.get_data_type("=0000.00N/00000.00E$ Test Arduino TNC")
        print(d_typ)
        self.assertEqual(d_typ, "POS ")
        d_typ = Ygate2.get_data_type(":BLN0     :Stay at home. Keep Safe Everyone. DX0STAYHOME")
        print(d_typ)
        self.assertEqual(d_typ, "BLN ")
        d_typ = Ygate2.get_data_type("`1_xl -/`de DU1OC Mobile 73!_)")
        print(d_typ)
        self.assertEqual(d_typ, "MICE")


