"""
    Ygate-n Yaesu igate new version 2

    9V1KG Klaus D Goepel -
    https://klsin.bpmsg.com
    https://github.com/9V1KG/Igate-n

    Version 2 first commit 2020-05-17
"""

import sys
import os
import time
import datetime
import select
import socket
import threading
import re
import textwrap
from collections import namedtuple
import logging
import json
import requests
import serial

WRAP = 120
INDENT = 16

Col = namedtuple(
    'color',
    ['red', 'green', 'yellow', 'blue', 'purple', 'cyan', 'bold', 'end']
)
COL = Col(red="\033[1;31;48m",
          green="\033[1;32;48m",
          yellow="\033[1;33;48m",
          blue="\033[1;34;48m",
          purple="\033[1;35;48m",
          cyan="\033[1;36;48m",
          bold="\033[1;37;48m",
          end="\033[1;37;0m"
          )

APRS_DATA_TYPE = {  # data types for received payload
    "!": "POS ",  # 21 Position without timestamp (no APRS messaging), or Ultimeter 2000 WX Station
    "=": "POS ",  # 3D Position without timestamp (with APRS messaging)
    "@": "POS ",  # 40 Position with timestamp (with APRS messaging)
    "/": "POS ",  # 2F Position with timestamp (no APRS messaging)
    "`": "MICE",  # 60 Current Mic-E Data (not used in TM-D700)
    "'": "MICE",  # 27 Old Mic-E Data (but Current data for TM-D700)
    ":": "MSG ",  # 3A Message or bulletin
    "}": "3PRT",  # 7D Third-party traffic
    "T": "TEL ",  # 54 Telemetry data
    "#": "WX  ",  # 23 Peet Bros U-II Weather Station
    "*": "WX  ",  # 2A Peet Bros U-II Weather Station
    "_": "WX  ",  # 5F Weather Report (without position)
    "$": "NMEA",  # 24 Raw GPS data or Ultimeter 2000
    ";": "OBJ ",  # 22 Object
    ")": "ITEM",  # 29 Item
    "?": "QURY",  # 3F Query
    "<": "CAP ",  # 3C Station Capabilities
    ">": "STAT",  # 3E Status
    ",": "TEST",  # 2C Invalid data or test data
    "{": "USER"  # 7B User-Defined APRS packet format
}


def decode_ascii(b_str: bytes) -> tuple:
    """
    Decodes byte string highlighting decode errors
    :param b_str: Byte string to be decoded
    :return: number of invalid bytes, string with non ascii bytes highlighted
    """
    inv_byt = 0  # number of invalid bytes
    str_dec = ""
    while len(b_str) > 0:
        try:
            str_dec += b_str.decode("ascii").strip("\r\n")
            b_str = b""
        except UnicodeDecodeError as msg:
            inv_byt += 1
            str_dec += f"{b_str[:msg.start]}"[2:-1] \
                       + "\033[1;31;48m" \
                       + f"{b_str[msg.start:msg.end]}"[2:-1] \
                       + "\033[1;37;0m"
            b_str = b_str[msg.end:]
    return inv_byt, str_dec


def t_wrap(text: str, indent: int) -> str:
    """
    Formatting text wrapped and indented
    :param text: input string
    :param indent: indent
    :return: formatted indented string
    """
    lines = textwrap.wrap(text, WRAP)
    if not lines:
        return ""
    f_line = lines.pop(0)
    txt = f_line + "\r\n"
    for line in lines:
        txt += textwrap.indent(line, indent * " ") + "\r\n"
    return txt


def is_internet(url: str = "http://www.google.com/", timeout: int = 30) -> bool:
    """
    Is there an internet connection
    :param url: String pointing to a URL
    :param timeout: How long we wait in seconds
    :return: true when internet available
    """
    try:
        req = requests.get(url, timeout=timeout)
        # HTTP errors are not raised by default, this statement does that
        req.raise_for_status()
        return True
    except requests.HTTPError as h_err:
        print(
            f"{COL.red}Internet connection failed: "
            f"{h_err.response.status_code}{COL.end}"
        )
        logging.warning("is_internet: %s", h_err.response.status_code)
        return False
    except requests.exceptions.ConnectionError as c_err:
        print({c_err})
        logging.warning("is_internet: %s", c_err)
        return False


class Ygate2:
    """
    Yaesu IGate2 class takes packets sent from Yaesu radio via
    serial (data) interface and forwards them to the APRS
    Internet system (APRS-IS)
    """

    RANGE = 150  # Range filter for APRS-IS in km
    # SERIAL = "/dev/tty.usbserial-D21JZ1X2"
    SERIAL = "/dev/tty.usbserial-14110"
    BAUD = 9600  # Baud rate of the Yaesu radio
    BCNTXT = "Testing Yaesu IGate 2.0 program - 73"
    STATUS_TXT = "IGate is up - RF-IS for FTM-400: https://github.com/9V1KG/Ygate2"
    HOST = "rotate.aprs2.net"
    PORT = 14580
    BUF = 512
    HOURLY = 3600.0
    BEACON = 1200.0  # beacon every 20 min
    FORMAT = "ascii"  # APRS uses ASCII
    VERS = "APZ200"  # Software experimental vers 2.00
    SPECIAL_CALLS = ["USNAP1", "PSAT", "PCSAT", "AISAT", "WXYO", "WXBOT"]
    LOG_FILE = "ygate2.log"
    MSG_RETRY = 5

    client = ""
    ser = ""
    queue_list = {}
    ack_list = {"send": []}  # msg_id as str!
    inputs = [sys.stdin]  # Sockets from which we expect to read
    outputs = [sys.stdout]  # Sockets to which we expect to write
    dispatch_in = {}
    dispatch_out = {}
    dispatch_exceptions = {}  # todo: check, if really necessary

    def __init__(self):
        logging.basicConfig(  # logging
            filename=self.LOG_FILE,
            level=logging.INFO,
            format='%(asctime)s %(message)s'
        )
        User = namedtuple("User", ["my_call", "ssid", "secret", "pos"])
        self.user = User(  # user
            my_call="DU1KG",
            ssid=2,
            secret=16892,
            pos=((14, 7.09, "N"), (120, 58.07, "E"), (570, "m"))
        )
        self.p_stat = {  # statistics
            "is_rcvd": 0,  # received from internet
            "ser_rcvd": 0,  # received from the radio
            "gated": 0,  # gated from radio to internet
            "not gated": 0,
            "invalid": 0,
            "msg_sent": 0,
            "msg_sack": 0,
            "msg_rcvd": 0,
            "calls": []
        }
        self.start_datetime = datetime.datetime.now()
        self.msg_id: int = 0

    def _aprs_con(self) -> bool:
        """
        Connect to APRS-IS server
        :return: True or False depending on the success.
        """
        lgi_str = f"user {self.user.my_call}-{self.user.ssid} pass {self.user.secret} " \
                  f"vers 9V1KG-ygate {self.VERS[-3:]} filter m/{self.RANGE}\r\n"
        flg_str = f"{COL.red}Login not successful. Check call sign and verification code.{COL.end}"
        fcn_str = f"{COL.yellow}Cannot connect to APRS server{COL.end}"

        if self.client is not isinstance(self.client, classmethod):
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            # Update dispatch list with new socket
            self.dispatch_in[self.client] = self._hdl_aprs_rx
            self.dispatch_out[self.client] = self._hdl_aprs_tx
        try:
            self.client.connect((self.HOST, self.PORT))
        except (OSError, TimeoutError) as msg:
            print(f"{fcn_str}: {msg}")
            return False
        time.sleep(0.5)
        self.client.sendall(bytes(lgi_str, "utf-8"))  # Login
        resp1 = self.client.recv(self.BUF)  # first response line
        resp2 = self.client.recv(self.BUF)  # second response line
        self.queue_list[sys.stdout] = \
            b"[LGIN] \033[1;32;48m> " + resp1[:-2] + b"\033[1;37;0m\r\n" \
            b"[LGIN] \033[1;32;48m> " + resp2[:-2] + b"\033[1;37;0m\r\n"
        logging.info("[LGIN] %s %s", resp1, resp2)
        if resp2.find(b"# logresp") >= 0 and resp2.find(b" verified") > 0:
            # put into inputs list once logged in!
            if self.client not in self.inputs:
                self.inputs.append(self.client)
            return True
        print(flg_str)  # login not successful
        return False

    def _open_serial(self) -> bool:
        """
        Opens serial port with self.BAUD Bd
        :return: True when serial could be opened
        """
        try:
            self.ser = serial.Serial(
                port=self.SERIAL,
                baudrate=self.BAUD,
                timeout=1
            )  # timeout necessary no to block rest of pgm
        except (serial.SerialException, serial.SerialTimeoutException) as err:
            print(" " * 9 + t_wrap(f"{COL.red}Serial interface: Check connection "
                                   f"and driver name. Error {str(err)}{COL.end}", 9)
                  )
            logging.warning("[ERR ] %s", str(err))
            return False
        print(" " * 9 + f"Serial port {self.ser.name} opened")
        return True

    @staticmethod
    def get_data_type(pay_ld: str) -> str:
        """
        Checks for data id. If type MSG and :...: in payload contains
        "BLN" type is changed from NSG to BLN
        :param pay_ld: payload
        :return: message id, NONE if no type was found
        """
        try:
            d_type = APRS_DATA_TYPE[pay_ld[0]]
        except (KeyError, IndexError):
            return "NONE"
        if d_type in ["MSG ", "3PRT"]:
            rec = re.match(r":([0-9A-Z -]{9}):", pay_ld)
            if rec and "BLN" in rec.group():
                d_type = "BLN "
        return d_type

    def is_routing(self, p_str: str) -> bool:
        """
        Check whether p_str is a valid routing packet, add unique call signs to list
        of received call signs.
        :param p_str: String to be checked
        :return: true if valid p_str starts with a valid call sign
        """
        # check for normal calls
        val_call = re.match(r"\d?[A-Z]{1,2}\d{1,4}[A-Z]{1,4}", p_str)
        if val_call:
            if val_call.group() not in self.p_stat["calls"]:
                self.p_stat["calls"].append(val_call.group())
            return True
        # check for possible aliases/special calls
        val_call = re.match(r"([A-Z\d]{4,7})(-\d{1,2})?", p_str)
        if val_call and val_call.group(1) in self.SPECIAL_CALLS:
            if val_call.group() not in self.p_stat["calls"]:
                self.p_stat["calls"].append(val_call.group())
            return True
        return False

    def get_call_from(self, routing):
        """
        Returns source call sign from the routing part of the packet.
        :param routing:
        :return: call sign found
        """
        f_c = re.compile(r":?((\d?[A-Z]{1,2}\d{1,4}[A-Z]{1,4})-?\d{0,2}) {0,6}[>:]?")
        if f_c.match(routing):  # full call match
            rx_from = f_c.match(routing).group(1)  # call
        else:  # special call or service?
            sp_c = re.match(r"([A-Z\d]{4,7})(-\d{1,2})?", routing)
            rx_from = sp_c.group(1)
            if rx_from not in self.SPECIAL_CALLS:
                self.SPECIAL_CALLS.append(rx_from)
                logging.info("Special call: %s added", rx_from)
                info = f"[INFO] Special call {rx_from} added"
                self.queue_list[sys.stdout] = bytes(info, "utf-8")
        return rx_from

    def check_routing(self, route: str, payld: str) -> str:
        """
        Check whether the packet should be routed to the internet.
        Packets with q constructs will not be routed when parsed
        :param route: routing
        :param payld: payload
        :return: "" if ok for routing, reason otherwise
        """
        if len(payld) == 0:
            reason = "No Payload, not gated"
        elif re.search(r"^}.*,TCP.*:", payld):
            reason = "Third party not gated"
        elif re.match(r"\?", payld):
            reason = "Query, not gated"
        elif "RFONLY" in route:
            reason = "RFONLY, not gated"
        elif "NOGATE" in route:
            reason = "NOGATE, not gated"
        else:
            return ""
        self.p_stat["not gated"] += 1
        return reason

    def _do_gating(self, route: str, payld: bytes):
        """
        Forwards received packet to the internet. q construct and own
        call added.
        :param route: routing string
        :param payld: payload
        :return:
        """
        # add ",qAO,mycall-ssid:"
        route = route + f",qAO,{self.user.my_call}-{self.user.ssid}:"
        packet = bytes(route, "ascii") + payld
        self.queue_list[self.client] = packet  # put into output queue
        if self.client not in self.outputs:
            self.outputs.append(self.client)
        self.p_stat["gated"] += 1

    def _hdl_msg_tx(self, m_id: str):
        """
        Sends aprs message with id m_id from the acknowledge list to
        the aprs internet server. Each time called, the retry
        counter is decremented by one until zero is reached or an
        acknowledgment was received in _hdl_msg_rx. Then the
        message string will then be deleted from the acknowledge list.
        Waiting time (before sending next time is incremented each time the
        fuction is called.
        :param m_id:
        :return:
        """
        if m_id not in self.ack_list:
            return
        index = list(self.ack_list.keys()).index(m_id)
        aprs_str = self.ack_list[m_id]
        retry = self.ack_list["send"][index - 1]
        if retry == 0:  # all retries done
            del self.ack_list["send"][index - 1]
            del self.ack_list[m_id]
            self.p_stat["msg_sent"] += 1
            return
        logging.info("[MSG ] Id %s Retry %i", m_id, retry)
        wait = 25. + (self.MSG_RETRY - retry) * 20
        threading.Timer(wait, self._hdl_msg_tx, (m_id,)).start()
        self.ack_list["send"][index - 1] = retry - 1
        self.queue_list[self.client] = bytes(aprs_str, "ascii")
        if self.client not in self.outputs:
            self.outputs.append(self.client)

    def _hdl_msg_input(self):
        """
        Get message input from keyboard and put aprs message into the ack_list
        :return:
        """
        in2 = " "
        while in2[0] not in ["Y", "y", "C", "c"]:
            in1 = ""
            while len(in1) > 9 or not re.match(r"([A-Z\d]{4,7})(-\d{1,2})?", in1.upper()):
                in1 = input("To call sign (9 char max): ")
            call_to = in1.upper()
            in1 = ""
            while 1 > len(in1) < 67:
                in1 = input(
                    "Message (67 char max):\r\n" \
                    ".........1.........2.........3.........4.........5.........6.......\r\n"
                )
            message = in1
            in2 = input("Ok to send? (y/n/c): ")
        if in2[0] in ["C", "c"]:
            print("Message send cancelled")
            return
        self.msg_id += 1 % 99
        id_str = str(format(self.msg_id, '02d'))
        aprs_str = f"{self.user.my_call}-{self.user.ssid}>" \
                   f"{self.VERS},TCPIP*::{call_to.ljust(9)}:{message}" \
                   + "{" + id_str + "\r\n"
        if id_str not in self.ack_list:
            self.ack_list[id_str] = aprs_str
            self.ack_list["send"].append(self.MSG_RETRY)
        self._hdl_msg_tx(id_str)

    def _hdl_msg_rx(self, call_to: str, pay_ld: str):
        """
        Process messages received: either for a received message
        an acknowledgment is sent out (ack_c) or a received
        acknowledment is processed (ack_a)
        :param call_to: destination call sign with ssid
        :param pay_ld: payload of package
        :return:
        """
        msg = re.sub(r":[0-9A-Z -]{9}:", "", pay_ld)
        ack_c = re.search(r"{([A-Z0-9}]{2,})", msg)
        ack_a = re.search(r"ack([0-9]{2})", msg)
        if ack_c:  # acknowledge message received: send ack
            logging.info("[MSG ] Message received from %s", call_to)
            self.p_stat["msg_rcvd"] += 1
            seq = ack_c.group(1)
            aprs_str = f"{self.user.my_call}-{self.user.ssid}>" \
                       f"{self.VERS},TCPIP*::{call_to.ljust(9)}:ack{seq}\r\n"
            packet = bytes(aprs_str, "ascii")
            self.queue_list[self.client] = packet
            if self.client not in self.outputs:
                self.outputs.append(self.client)
        elif ack_a:  # received ack for msg sent
            seq = ack_a.group(1)
            if seq in self.ack_list:
                index = list(self.ack_list.keys()).index(seq)
                del self.ack_list["send"][index - 1]
                del self.ack_list[seq]
                self.p_stat["msg_sent"] += 1
                self.p_stat["msg_sack"] += 1
                logging.info("[MSG ] Message %s was acknowledged!", seq)
                self.queue_list[sys.stdout] = \
                    f"[MSG ] {COL.purple}Message {seq} acknowledged!{COL.end}\r\n"

    def packet_parse(self, packet: bytes):
        """
        Parse packets received, check validity, determine data type, and
        whether it should be gated to the internet. Gating is called from here.
        :param packet: bytes with packet received
        :return:
        """
        q_c = re.compile(r",(qA[CIOSRUoX]),")
        q_constr = ""
        if len(packet) < 3 or packet.find(b":") < 0:
            logging.info("[ERR ] packet parse: %s", packet)
            self.queue_list[sys.stdout] = b"[ERR ] parse: " + packet
            return  # disregard
        a_p1 = decode_ascii(packet.split(b":", 1)[0])
        b_p2 = packet.split(b":", 1)[1]
        a_p2 = decode_ascii(b_p2)
        if a_p1[1][0] == "#":  # APRS server comments
            return  # disregard
        routing: str = a_p1[1]
        payload: str = a_p2[1]  # non ascii chars will be shown as\xnn
        data_type = self.get_data_type(payload)
        if q_c.search(routing):
            q_constr = q_c.search(routing).group(1)
        if a_p1[0] > 0:  # invalid routing
            routing = f"{COL.yellow}Invalid routing{COL.end}{routing}"
            logging.warning("[INV ] Invalid routing: %s%s", routing, payload)
            self.p_stat["invalid"] += 1
        elif self.is_routing(routing):  # starts with a valid call sign"
            reason = self.check_routing(routing, payload)
            if re.match(f"{self.user.my_call}-{self.user.ssid}", routing):
                routing = f"{COL.blue}{routing}{COL.end}"  # own packet
                payload = f"{COL.blue}{payload}{COL.end}"
            elif data_type in ["MSG ", "3PRT"]:
                rec = re.match(r":([0-9A-Z -]{9}):", payload)
                if rec:
                    if rec.group(1).strip(" ") == f"{self.user.my_call}-{self.user.ssid}":
                        rx_from = self.get_call_from(routing)
                        self._hdl_msg_rx(rx_from, payload)  # handle received message
                        recipient = COL.purple + rec.group(1) + COL.end
                        payload = recipient + payload[10:]
            if reason == "" and q_constr == "":
                # gate message to the internet
                self._do_gating(routing, b_p2)
                routing = f"{COL.green}{routing}{COL.end}"
                payload = f"{COL.green}{payload}{COL.end}"
            elif reason != "":
                routing = f"{COL.yellow}{reason}{COL.end}: {routing}"
        logging.debug("[%s] %s %s", data_type, routing, a_p2[1])
        packet = bytes(f"[{data_type}] {routing}:{payload}", "utf-8")
        self.queue_list[sys.stdout] = packet
        # print(f"{time.strftime('%H:%M:%S ')}[{data_type}] {routing}:{payload}")


    def _send_my_position(self):
        """
        thread that sends position every BEACON sec to APRS IS
        """
        pos_c = bytes(f"{self.user.my_call}-{self.user.ssid}>{self.VERS},"
                      f"TCPIP*:=/GATAm'8^#JHt {self.BCNTXT}\r\n", "utf-8"
                      )
        threading.Timer(self.BEACON, self._send_my_position).start()
        self.queue_list[self.client] = pos_c  # put into output queue
        if self.client not in self.outputs:
            self.outputs.append(self.client)

    @staticmethod
    def prn_hlp():
        """
        Help function to show the available commands
        :return:
        """
        hlp_txt = "\r\nCommands:\r\n" \
                  f" {COL.bold}help:{COL.end} This help text\r\n" \
                  f" {COL.bold}pos: {COL.end} Send my position\r\n" \
                  f" {COL.bold}msg: {COL.end} Send message\r\n" \
                  f" {COL.bold}que: {COL.end} Show message queue\r\n" \
                  f" {COL.bold}stat:{COL.end} Show statistics\r\n" \
                  f" {COL.bold}exit:{COL.end} Exit program\r\n"
        print(textwrap.indent(hlp_txt, 9 * " "))

    def prn_stat(self):
        """
        Print statistics
        :return:
        """
        time_on = datetime.datetime.now() - self.start_datetime
        pck_tot = self.p_stat['is_rcvd'] + self.p_stat['ser_rcvd'] +self.p_stat['gated']
        print(f"IGate up {time_on.days} days {round(time_on.seconds/3600, 1)} h ")
        print("Packets: {:d} processed, ".format(pck_tot)
              + "{:d} received, ".format(self.p_stat['ser_rcvd'])
              + "{:d} gated, ".format(self.p_stat['gated'])
              + "{:d} not gated, ".format(self.p_stat['not gated'])
              + "{:d} invalid.".format(self.p_stat['invalid'])
              )
        print(
            f"Messages: {self.p_stat['msg_rcvd']} received;"
            f" {self.p_stat['msg_sent']} sent, thereof"
            f" {self.p_stat['msg_sack']} acknowledged."
        )
        n_calls = len(self.p_stat["calls"])
        print(
            textwrap.wrap(
                f"Call signs: {n_calls} unique call signs: "
                + ' '.join([str(call) for call in self.p_stat["calls"]]), WRAP
            )[0]
        )

    def _hdl_kbd(self):
        """
        Handler for keyboard input
        :return: None
        """
        inv_cmd = bytes(f"{COL.red}Invalid keyboard input{COL.end}", "utf-8")
        que = json.dumps(self.ack_list, indent=4, sort_keys=True)

        line = sys.stdin.readline()
        if line.startswith("help"):
            self.prn_hlp()
        elif line.startswith("pos"):
            self._send_my_position()
        elif line.startswith("msg"):
            self._hdl_msg_input()
        elif line.startswith("que"):
            print(que)
        elif line.startswith("stat"):
            self.prn_stat()
        elif "exit" in line:
            self._close_pgm()
        else:
            self.queue_list[sys.stdout] = inv_cmd

    def _hdl_prn(self):
        """
        Handler for formatted stdout (print). Adds timestamp
        and indent output
        :return: None
        """
        if not self.queue_list or sys.stdout not in self.queue_list:
            return
        try:
            b_txt = self.queue_list[sys.stdout]
        except KeyError:
            # todo: check, whether exception is really necessary
            logging.debug("KeyError in hdl_prn %s", self.queue_list)
            return
        text = decode_ascii(b_txt)
        lines = text[1].split("\r\n")
        for line in lines:
            if len(line) > 0:
                t_out = time.strftime("%H:%M:%S ") + t_wrap(line, INDENT)
                sys.stdout.write(t_out)
        del self.queue_list[sys.stdout]  # delete from queue

    def _hdl_timeout(self):
        """
        Reconnect to APRS server in case of timeout. Called every
        retry seconds until internet is back
        :return:
        """
        retry = 120.  # wait 2 min before trying to reconnect
        # todo: needs more extensive testing
        logging.warning("[TOUT] timeout or start login - %s", self.client)
        if is_internet():
            if self._aprs_con():
                self._send_my_position()
                return
        else:
            b_txt = bytes(f"{COL.yellow}No Internet ...{COL.end}", "utf-8")
            self.queue_list[sys.stdout] = b_txt
            threading.Timer(retry, self._hdl_timeout).start()

    def _hdl_aprs_rx(self):
        """
        Handler to read packets from APRS-IS and forward them to stdout
        via the parser.
        :return: None
        """
        try:
            buf = self.client.recv(self.BUF)
            logging.debug("APRS buf: %s", buf)
        except (TimeoutError, OSError) as err:
            self.queue_list[sys.stdout] = \
                bytes(f"{COL.yellow}Error reading from APRS-IS{COL.end}:"
                      f" {err}\r\n", "utf-8")
            self._hdl_timeout()  # try to reconnect
            return
        for packet in buf.splitlines():
            self.packet_parse(packet)
            self.p_stat["is_rcvd"] += 1

    def _hdl_aprs_tx(self):
        """
        Handler for sending data to APRS-IS
        :return: None
        """
        b_to_send = self.queue_list[self.client]
        try:
            self.client.sendall(b_to_send)
        except (TimeoutError, OSError) as err:
            # todo: error handling
            print(f"{COL.yellow}Error writing to APRS-IS"
                  f"{COL.end}: {err}", "utf-8")
            self._hdl_timeout()  # try to reconnect
        logging.info("[TX  ] %s", b_to_send)
        del self.queue_list[self.client]  # delete from queue
        self.outputs.remove(self.client)
        self.packet_parse(b_to_send)

    def _hdl_ser_rx(self):
        """
        Handler for serial input from Yaesu radio
        :return:
        """
        is_ui = re.compile(r" \[.*\] <UI.*>")
        b_p1 = self.ser.read_until()
        if b_p1 == b'\r\n' or len(b_p1) == 0:  # more than \r\n
            return
        logging.debug("Ser1: %s", b_p1)
        a_p1 = decode_ascii(b_p1)  # 1st line routing
        if is_ui.search(a_p1[1]):
            b_p1 = bytes(is_ui.sub("", a_p1[1].strip()), "ascii")
            b_p2 = self.ser.read_until()  # 2nd line payload bytes
            logging.debug("Ser2: %s", b_p2)
        else:  # out of sync, disregard payload
            logging.info("[SER ] out of sync: %s", b_p1)
            return
        buf = b_p1 + b_p2  # complete received packet
        logging.info("[SER ] %s", buf)
        self.p_stat["ser_rcvd"] += 1
        self.packet_parse(buf)

    def _hdl_def_r(self):
        """
        Default Handler (not in use)
        :return: None
        """
        # todo: should be removed later
        print("Default readable: ", self.inputs, self.queue_list)

    def _hdl_def_t(self):
        """
        Default Handler (not in use)
        :param selctd:
        :return:
        """
        # todo: should be removed later
        print("Default writable: ", self.outputs, self.queue_list)

    def _hdl_exc_aprs(self):
        """
        Handler for exceptions
        :return:
        """
        # todo: might be not needed
        print("Exception ...")

    def _close_pgm(self):
        self.prn_stat()
        logging.info(self.p_stat)
        # os._exit is used to exit the program
        # immediately, because threats are running
        os._exit(0)

    def _start_up(self):
        """
        Startup of IGate: opens serial port and internet connection
        Login to APRS server and send bulletin and beacon
        :return: None
        """
        print(
            f"{COL.green}{(str(self.start_datetime).split('.'))[0]} "
            f"{self.user.my_call}-{self.user.ssid} "
            f"IGgate started - Program Version {self.VERS[-3:]} by 9V1KG{COL.end}"
        )
        self.prn_hlp()
        self.dispatch_in[sys.stdin] = self._hdl_kbd  # handle keyboard input
        self.dispatch_out[sys.stdout] = self._hdl_prn  # handle print output
        self.dispatch_exceptions[sys.stdin] = self._hdl_kbd

        self._open_serial()  # open serial
        self._hdl_timeout()  # open socket and connect to aprs server

    def main(self):
        """
        Main program for ygate2
        :return: None
        """
        self._start_up()
        # todo: see, whether exceptions is ever reached
        while self.inputs:
            if not isinstance(self.ser, str):
                self._hdl_ser_rx()  # does not work with select
            readable, writable, exceptional \
                = select.select(self.inputs, self.outputs, [])
            for sel in readable:
                self.dispatch_in.get(sel, self._hdl_def_r)()
            for sel in writable:
                self.dispatch_out.get(sel, self._hdl_def_t)()
            for sel in exceptional:
                self.dispatch_exceptions.get(sel)()
            time.sleep(0.1)


if __name__ == "__main__":
    YGATE = Ygate2()
    YGATE.main()
