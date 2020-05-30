"""
Module for interfacing with direwolf
Author: Klaus D Goepel, 9V1KG
"""

import socket


class KissInterface:
    """
    Class with functions for interfacing the Direwolf kiss modem via TCP
    AX25 frame:
    frame = {
        "dest": "",   # 7 bytes, 6 call sign + 1 ssid
        "source": "", # 7 bytes, 6 call sign + 1 ssid
        "path": [],   # 7 bytes, max 8 times
        "message":b'' # byte string, max 256 bytes
    }
    flag is the KISS command 0x00 for data
    The frame is started and ended with FEND 0xC0
    2 bytes fcs frame check sum seems to be calculated within the modem

    If a FEND appears in the data, it is translated into the two byte sequence FESC TFEND
    if a FESC appears in the data, it is replaced with the two character sequence FESC TFESC
    Receiving a FEND marks the end of the current frame.
    FESC puts the receiver into "escaped mode"
    a following TFESC or TFEND is translated back to FESC or FEND
    Receipt of any character other than TFESC or TFEND while in escaped mode is an error;
    TFEND or TESC received while not in escaped mode is treated as an ordinary data character.
    """

    # Kiss modem via TCP
    SERVER = socket.gethostbyname("localhost")
    PORT1 = 8001
    ADDR = (SERVER, PORT1)
    BUFFER = 2048

    # Kiss special chars
    FEND = b'\xc0'  # Frame end
    FESC = b'\xdb'  # Frame escape
    TFEND = b'\xdc'  # Transposed frame end
    TFESC = b'\xdd'  # Transposed frame escape

    FLAG = b'\x00'
    UI_PROTO = b'\x03\xf0'

    # Kiss port
    KISS_PORT = 0  # Has to be zero for direwolf

    # Kiss commands
    KISS_DATA = 0x0
    KISS_TXDEL = 0x1
    KISS_PERS = 0x2
    KISS_SLOTT = 0x3
    KISS_TXTAIL = 0x4
    KISS_FDUP = 0x5

    # Path lists
    VERS = "APZ200"
    PATH_DEF = ["WIDE1-1", "WIDE2-1"]
    PATH1 = ["ARISS", "SGATE"]
    PATH2 = ["YB0X", "SGATE"]

    TCPClient: socket = None

    def __init__(self, my_call="MY_CALL"):
        self.source = [self.VERS, my_call]
        self.kiss_fn = 0  # fileno of the socket

    def _kiss_init(self, port: int):
        """
        Initialize the KISS TNC
        :param port: Kiss port of the tnc (0-15)
        """
        self.kiss_cmd(port, self.KISS_TXDEL, bytearray([40]))
        self.kiss_cmd(port, self.KISS_PERS, bytearray([128]))
        self.kiss_cmd(port, self.KISS_SLOTT, bytearray([3]))
        self.kiss_cmd(port, self.KISS_TXTAIL, bytearray([20]))
        self.kiss_cmd(port, self.KISS_FDUP, bytearray([0]))

    def kiss_con(self) -> bool:
        """
        Connect to kiss modem via tcp
        :return: true if connected, false otherwise
        """
        # todo: error handling
        self.TCPClient = socket.socket(
            socket.AF_INET, proto=socket.IPPROTO_TCP)
        try:
            self.TCPClient.connect(self.ADDR)
        except ConnectionError as err:
            self.TCPClient.close()
            self.TCPClient = None
            return False
        self.kiss_fn = self.TCPClient.fileno()
        self._kiss_init(self.KISS_PORT)
        return True

    def kiss_cmd(self, port: int, command: int, data: bytearray):
        """
        Sends commands and data to the KISS TNC.
        data should be a byte array
        :return
        """
        out = bytearray()
        out.extend(self.FEND)
        out.append((port << 4) + command)
        for _byt in data:
            out.append(_byt)
        out.extend(self.FEND)
        # send via TCP to Kiss modem
        self.TCPClient.sendto(bytes(out), self.ADDR)

    @staticmethod
    def _chunk7(b_arr: bytes) -> list:
        """
        splits bytes into a list of chunks with 7 bytes
        :param b_arr: byte string
        :return: list of chunks, empty list if not multiple of 7
        """
        if len(b_arr) % 7 != 0:
            return[]
        return list(
            b_arr[i_pos: i_pos + 7]
            for i_pos in range(0, len(b_arr), 7)
        )

    @staticmethod
    def _decode_call(bs_call: bytes) -> str:
        """
        AX.25 decode a call sign (7 byte chunk).
        :param bs_call:
        :return: call: call sign as str with ssid
        """
        if len(bs_call) > 7:
            return ""
        call = "".join([chr(int(x) >> 1) for x in bs_call[:-1]])
        ssid = (bs_call[6] >> 1) & 0x0f
        call = call.strip(" ")
        return call if ssid == 0 else call + "-" + str(ssid)

    @staticmethod
    def _encode_call(call: str, final: bool) -> bytearray:
        """
        AX.25 encode a call sign (6 char + ssid)
        :param call: call sign with or without ssid
        :param final: true for last encoded call sign in route
        :return:
        """
        if len(call) > 7:
            return bytearray([0])
        if call.find("-") < 0:
            call = call + "-0"
        call, ssid = call.split("-")
        call = call.ljust(6)
        enc_call = [ord(x) << 1 for x in call]
        enc_ssid = (int(ssid) << 1) | 0x60 | (0x01 if final else 0)
        return bytearray(enc_call + [enc_ssid])

    def encode_msg_frame(self, call_to: str, message: str) -> bytearray:
        """
        Assembles AX25 frame for message data type to be sent to kiss
        :param call_to: addressee, can be empty
        :param message: payload (message)
        :return: kiss encoded frame (no FEND)
        """
        frame: bytearray = bytearray()
        route_l = self.source + self.PATH_DEF
        for dest in route_l[:-1]:
            frame.extend(self._encode_call(dest, False))
        frame.extend(self._encode_call(route_l[-1], True) + self.UI_PROTO)
        payload = message
        if call_to:  # msg id handled already in ygate2
            payload = f":{call_to.ljust(9)}:{message}"
        frame.extend(bytearray(payload, "ascii"))
        frame = frame.replace(self.FESC, self.FESC + self.TFESC)
        frame = frame.replace(self.FEND, self.FESC + self.TFEND)
        return frame

    def hdl_kiss_rx(self) -> bytes:
        """
        Reads frame from Kiss interface via TCP
        :return: decoded packet as bytes
        """
        # todo: replace with try ... except?
        if self.kiss_fn == 0:
            return b''
        frame, _ = self.TCPClient.recvfrom(self.BUFFER)
        if frame == b'':
            return b''
        k_cmd = frame[1]  # has to be zero (data)
        dest = self._decode_call(frame[2:9])
        source = self._decode_call(frame[9:16])
        pid_pos = frame.find(self.UI_PROTO)
        route = ""
        for i in self._chunk7(frame[16:pid_pos]):
            route += self._decode_call(i) + ","
        b_msg = frame[pid_pos + 2:-1]
        # todo: return packet as dict?
        packet = bytes(f"{source}>{dest},{route[:-1]}:", "ascii") + b_msg
        return packet
