"""
Unit tests for module ygate2
Yaesu APRS IGate
"""
from unittest import TestCase, mock
from unittest.mock import patch
from ygate2 import Ygate2
import re


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

    def test_is_routing(self):

        test_true = [
            "4I1AYZ-10>APWW11,WIDE1-1,qAR,4I1AYZ-11::BLN0     :Stay at home.\r\n"
            "DU1KG-10>APZ200,TCPIP*:=/GATAm'8^#JHt Testing \r\n"
            "USNAP1>APOS00,ARISS::OFF"
        ]
        test_false = [
            "4I?AYZ-10>APWW11,WIDE1-1,qAR,4I1AYZ-11::BLN0     :Stay at home. \r\n"
            "DUKG-10>APZ200,TCPIP*:=/GATAm'8^#JHt Testing \r\n"
            "USNAP-1>APOS00,ARISS::OFF\r\n"
        ]
        call = re.compile(r"\d?[A-Z]{1,2}\d{1,4}[A-Z]{1,4}")
        for tst in test_true:
            cs = call.match(tst)
            res = self.lcl_ygate2.is_routing(tst)
            self.assertEqual(res, True, msg=res)
            self.assertIn(cs.group(), self.lcl_ygate2.p_stat["calls"])
        for tst in test_false:
            print(tst)
            res = self.lcl_ygate2.is_routing(tst)
            self.assertEqual(res, False, msg=res)
