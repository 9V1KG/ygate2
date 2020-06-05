"""
Unit tests for functions in module ygate2
Yaesu APRS IGate V 2.0
"""
from unittest import TestCase, mock
from unittest.mock import patch
import aprsutils.aprs_util as aprs


class TestFunctions(TestCase):

    # todo complete unit tests

    def setUp(self) -> None:
        junk = 1

    def test_decode_ascii(self):
        print("Test decode_ascii:")
        b_str = b'test byte string with 2\xb0 invalid\xef chars'
        r_str = aprs.decode_ascii(b_str)
        self.assertEqual(r_str[0], 2)
        print(r_str[1])
        b_str = b'test byte string with all valid ASCII chars'
        r_str = aprs.decode_ascii(b_str)
        print(r_str[1])
        self.assertEqual(r_str[0], 0)

    def test_b91_encode(self):
        # 0 bits set
        self.assertEqual(aprs.b91_encode(0), "")
        # 1 LSB Set
        self.assertEqual(aprs.b91_encode(90), "{")
        self.assertEqual(aprs.b91_encode(91), '"!')
        # 2 LSB Set
        self.assertEqual(aprs.b91_encode(91 + 90), '"{')
        self.assertEqual(aprs.b91_encode(91 ** 2), '"!!')
        self.assertEqual(aprs.b91_encode(91 ** 3), '"!!!')
        # All Bits Set
        self.assertEqual(aprs.b91_encode((91 ** 4) - 1), "{{{{")
        # There are 91**4 -1 possible combinations however.... !!

    def test_b91_decode(self):
        self.assertEqual(aprs.b91_decode(''), 0)
        self.assertEqual(aprs.b91_decode('{'), 90)
        self.assertEqual(aprs.b91_decode('"!'), 91)
        self.assertEqual(aprs.b91_decode('"{'), 91 + 90)
        self.assertEqual(aprs.b91_decode('"!!'), 91 ** 2)
        self.assertEqual(aprs.b91_decode('"!!!'), 91 ** 3)
        self.assertEqual(aprs.b91_decode('{{{{'), (91 ** 4) - 1)

    @patch("aprsutils.aprs_util.is_internet")
    def test_is_internet(self, mocked_method):
        # Make sure we call the module only 1 time
        mocked_method.return_value = True
        self.assertEqual(aprs.is_internet(), True)
        self.assertEqual(mocked_method.called, True)
        self.assertEqual(mocked_method.call_count, 1)
        self.assertEqual(aprs.is_internet("yaesu.com"), True)
        self.assertEqual(mocked_method.call_count, 2)

    def test_format_position(self):
        self.assertEqual(
            aprs.format_position((14, 8.09, "N"), (119, 55.07, "E")),
            "1408.09N/11955.07E#"
        )
        self.assertEqual(
            aprs.format_position((14, 8.09, "S"), (119, 55.07, "E")),
            "1408.09S/11955.07E#"
        )
        self.assertEqual(
            aprs.format_position((14, 8.09, "N"), (119, 55.07, "W")),
            "1408.09N/11955.07W#"
        )
        self.assertEqual(
            aprs.format_position((14, 8.09, "S"), (119, 55.07, "W")),
            "1408.09S/11955.07W#"
        )
        self.assertEqual(
            aprs.format_position((90, 59.99, "N"), (179, 59.99, "W")),
            "Invalid position input 9059.99N, 17959.99W."
        )
        self.assertEqual(
            aprs.format_position((14, 98.09, "W"), (119, 55.07, "N")),
            "Invalid position input 1498.09W, 11955.07N."
        )

    def test_compress_position(self):
        """
        Check the position compression
        :return:
        """
        lon1 = (10.11, 20.22, "E")
        lat2 = (54.11, 2.22, "N")
        res = aprs.compress_position(lat2, lon1)
        self.assertEqual(res, "/3,6\\Q-:T#   ")
        res = aprs.compress_position(lat2, lon1, alt=(150, "m"))
        self.assertEqual(res, "/3,6\\Q-:T#C)t")

        # As location is calculated to a meter ... adding more accuract in the DD.MMMMM input should change the output
        lon1 = (10.111111, 20.222222, "E")
        lat2 = (54.111111, 2.2222222, "N")
        res = aprs.compress_position(lat2, lon1)
        self.assertEqual(res, "/3,1nQ-<y#   ")
        res = aprs.compress_position(lat2, lon1, alt=(150, "m"))
        self.assertEqual(res, "/3,1nQ-<y#C)t")

    def test_cnv_ch(self):
        self.assertEqual(aprs._cnv_ch("0"), "0")
        self.assertEqual(aprs._cnv_ch("A"), "0")
        self.assertEqual(aprs._cnv_ch("P"), "0")
        self.assertEqual(aprs._cnv_ch("K"), "0")
        self.assertEqual(aprs._cnv_ch("L"), "0")
        self.assertEqual(aprs._cnv_ch("Z"), "0")

    def test_t_wrap(self):
        txt = "00:00:00 [MSG] The quick brown fox jumps over the lazy dog."
        f_txt = aprs.t_wrap(txt, 9)
        self.assertEqual(f_txt, txt + "\r\n")
        txt = "00:00:00 [MSG] The quick brown fox jumps over the lazy dog. " \
              "The quick brown fox jumps over the lazy dog. " \
              "The quick brown fox jumps over the lazy dog. "
        f_txt = f"00:00:00 [MSG] The quick brown fox jumps over the lazy dog. " \
                f"The quick brown fox jumps over the lazy dog. The\r\n" \
                f"               quick brown fox jumps over the lazy dog.\r\n"
        t_txt = aprs.t_wrap(txt, 15)
        self.assertEqual(t_txt, f_txt)

    def test_mice_decode(self):
        packet = {
            "source": "DU1KG-1",
            "dest": "Q4PWQ0",
            "path": ["DY1P", "WIDE1*", "WIDE2-1","qAR", "DU1KG-10"],
            "payload": b'`0V l \x1c-/`":-}435.350MHz DU1KG home 73 Klaus_%'
        }
        decode = aprs.mic_e_decode(packet)
        self.assertEqual(decode, "Pos: 14 7.1'N, 120 58.04'E, In Service, ")
        packet = {
            "source": "",
            "dest": "",
            "path": [],
            "payload": b'`0V l \x1c-/`":-}435.350MHz DU1KG home 73 Klaus_%'
        }
        decode = aprs.mic_e_decode(packet)
        self.assertEqual(decode, "")
        packet = {
            "source": "DU1KG-1",
            "dest": "Q4PWQ0",
            "path": ["DY1P", "WIDE1*", "WIDE2-1", "qAR", "DU1KG-10"],
            "payload": b''
        }
        decode = aprs.mic_e_decode(packet)
        self.assertEqual(decode, "")

    def test_check_routing(self):
        packet = {
            "source": "DU1KG-1",
            "dest": "Q4PWQ0",
            "path": ["DY1P", "WIDE1*", "WIDE2-1", "qAR", "DU1KG-10"],
            "payload": b''
        }
        reason = aprs.check_routing(packet)
        self.assertEqual(reason, "No Payload, not gated")
        packet["payload"] = b'`0V l \x1c-/`":-}435.350MHz DU1KG home 73 Klaus_%'
        reason = aprs.check_routing(packet)
        self.assertEqual(reason, "")

    def test_get_data_type(self):
        dtt = aprs.get_data_type("`0V l \x1c-/`\":-}435.350MHz DU1KG home 73 Klaus_%")
        self.assertEqual(dtt, "MICE")
        dtt = aprs.get_data_type(f":BLN0     :Test message")
        self.assertEqual(dtt, "BLN ")

    def test_packet_prn(self):
        packet = {
            "source": "DU1KG-1",
            "dest": "Q4PWQ0",
            "path": ["DY1P", "WIDE1*", "WIDE2-1", "qAR", "DU1KG-10"],
            "payload": b'',
            "info": ""
        }
        prn = aprs.packet_prn(packet)
        self.assertEqual(prn, "DU1KG-1>Q4PWQ0,DY1P,WIDE1*,WIDE2-1,qAR,DU1KG-10:")
        packet["payload"] = b':BLN1     :DX0STAYHOME: DY1P APRS 10 Watts RF-IS-RF Digipeater'
        prn = aprs.packet_prn(packet)
        self.assertEqual(prn, "DU1KG-1>Q4PWQ0,DY1P,WIDE1*,WIDE2-1,qAR,DU1KG-10:"
                              ":BLN1     :DX0STAYHOME: DY1P APRS 10 Watts RF-IS-RF Digipeater")

    def test_packet_parse(self):
        pck_byt = b'DY1P>APWW11,TCPIP*,qAC,T2NANJING::BLN1     :' \
                  b'DX0STAYHOME: DY1P APRS 10 Watts RF-IS-RF Digipeater'
        res = {
            'source': 'DY1P',
            'dest': 'APWW11',
            'path': ['TCPIP*', 'qAC', 'T2NANJING'],
            'q_constr': 'qAC',
            'dta_id': ':',
            'payload': b':BLN1     :DX0STAYHOME: DY1P APRS 10 Watts RF-IS-RF Digipeater',
            'info': ''
        }
        pck = aprs.packet_parse(pck_byt)
        self.assertEqual(pck, res)

