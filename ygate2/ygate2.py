"""
    Ygate-n Yaesu igate new version 2

    9V1KG Klaus D Goepel -
    https://klsin.bpmsg.com
    https://github.com/9V1KG/ygate2

    Version 2 first commit 2020-05-25
"""

import sys
import os
import time
from time import strftime, localtime
import datetime
import select
import socket
import threading
import re
import textwrap
import logging
import json
import serial
import aprsutils.aprs_util as aprs
from aprsutils.aprs_util import Color as Col
import kiss.kiss_interface as kiss


class Ygate2:
    """
    Yaesu YGate2 takes packets sent from Yaesu radio via
    serial (data) interface and forwards them to the APRS
    Internet system (APRS-IS)
    """
    CONFIG = {
        "mycall": "DU1KG",
        "ssid": 2,
        "secret": 16892,
        "pos": {
            "lat": (14, 7.09, "N"),
            "lon": (120, 58.07, "E"),
            "alt": (570, "m"),
        },
        "filter": 150,
        "beacon": "Testing Yaesu IGate 2.0 program - 73",
        "status": "IGate is up - RF-IS for FTM-400: https://github.com/9V1KG/Ygate2",
        "serial": ("/dev/tty.usbserial-14110", 9600),
        "aprsis": ("rotate.aprs2.net", 14580),
    }
    BEACON = 1200.0  # beacon every 20 min
    SPECIAL_CALLS = ["USNAP1", "PSAT", "PCSAT", "AISAT", "WXYO", "WXBOT"]
    LOG_FILE = "ygate2.log"

    COL = Col()  # Class of chars for color output

    _BUF = 1024
    _HOURLY = 3600.0
    _MSG_RETRY = 5
    _FORMAT = "ascii"  # APRS uses ASCII
    _VERS = "APZ207"  # Software experimental vers 2.07 (dev #7)

    _ack_list = {"send": []}  # msg_id as str!
    _client = None  # socket for aprs TCP connection
    _ser = None
    _queue_list = {}  # queue to store file no: and bytes to send/receive
    _msg_list = {}  # store messages received and sent
    _inputs = [sys.stdin.fileno()]  # Sockets from which we expect to read
    _outputs = [sys.stdout.fileno()]  # Sockets to which we expect to write
    _dispatch_in = {}  # file no and functions to execute receiving
    _dispatch_out = {}  # file no and functions to execute sending

    def __init__(self):
        logging.basicConfig(  # logging
            filename=self.LOG_FILE,
            level=logging.INFO,
            format='%(asctime)s %(message)s'
        )
        self.p_stat = {  # statistics
            "is_rcvd": 0,  # received from internet
            "ser_rcvd": 0,  # received from the radio
            "gated": 0,  # gated from radio to internet
            "not gated": 0,
            "invalid": 0,
            "msg_sent": 0,  # number of messages sent
            "msg_sack": 0,  # number of messages acknowledged
            "msg_rcvd": 0,  # number of messages received
            "calls": []  # list of unique call signs
        }
        self._user = self.CONFIG["mycall"] + "-" + str(self.CONFIG["ssid"])
        self.kiss = kiss.KissInterface(self._user)
        self.start_datetime = datetime.datetime.now()
        self.msg_id: int = 0
        self.is_rx = True  # receive from Internet is on
        self._aprs_fn = 0  # fileno for aprs socket
        self._ser_fn = 0  # fileno for serial

    def _aprs_con(self) -> bool:
        """
        Connect to APRS-IS server
        :return: True or False depending on the success.
        """
        lgi_str = f"user {self._user} pass {self.CONFIG['secret']} " \
                  f"vers 9V1KG-ygate {self._VERS[-3:]} " \
                  f"filter m/{self.CONFIG['filter']}\r\n"
        flg_str = f"{self.COL.red}" \
                  f"Login not successful. Check call sign and verification code." \
                  f"{self.COL.end}"
        fcn_str = f"{self.COL.yellow}Cannot connect to APRS server{self.COL.end}"

        if self._client is not isinstance(self._client, classmethod):
            logging.info("[ERR ] APRS connection lost: fn: %s", self._aprs_fn)
            if self._aprs_fn != 0:
                if self._aprs_fn in self._inputs:
                    self._inputs.remove(self._aprs_fn)
                del self._dispatch_in[self._aprs_fn]
                del self._dispatch_out[self._aprs_fn]
            self._client = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            self._aprs_fn = self._client.fileno()
            # Update dispatch list with new socket
            self._dispatch_in[self._aprs_fn] = self._hdl_aprs_rx
            self._dispatch_out[self._aprs_fn] = self._hdl_aprs_tx
        try:
            self._client.connect(self.CONFIG["aprsis"])
        except (OSError, TimeoutError) as msg:
            logging.info("[LGIN] aprs_con: OSError, TimeoutError %s", msg)
            print(f"{fcn_str}: {msg}")
            return False
        time.sleep(0.5)
        self._client.sendall(bytes(lgi_str, "utf-8"))  # Login
        resp1 = self._client.recv(self._BUF)  # first response line
        resp2 = self._client.recv(self._BUF)  # second response line
        response = f"{self.COL.green}{resp1[:-2]}{self.COL.end}\r\n" \
                   f"{self.COL.green}{resp2[:-2]}{self.COL.end}\r\n"
        self._queue_list[sys.stdout.fileno()] = bytes(response, "utf-8")
        logging.info("[LGIN] %s %s", resp1, resp2)
        if resp2.find(b"# logresp") >= 0 and resp2.find(b" verified") > 0:
            # put into inputs list once logged in!
            if self.is_rx and self._aprs_fn not in self._inputs:
                logging.info("[INFO] Internet connected to receive (fn: %s)",
                             self._aprs_fn)
                self._inputs.append(self._aprs_fn)
            return True
        if resp1.find(b"# Port full"):
            logging.info("APRS server full")
        print(flg_str)  # login not successful
        return False

    def _kiss_con(self) -> bool:
        """
        Connect to kiss modem (direwolf)
        :return: True when connect was successful
        """
        if self.kiss.kiss_con():  # open kiss interface socket to direwolf
            self._dispatch_in[self.kiss.kiss_fn] = self._hdl_kiss_rx  # handle kiss input
            self._inputs.append(self.kiss.kiss_fn)
            self._dispatch_out[self.kiss.kiss_fn] = self._hdl_kiss_tx
            name = self.kiss.TCPClient.getpeername()
            aprs.print_wrap(
                9 * " " + f"{self.COL.green}Kiss modem connected: {name}{self.COL.end}"
            )
            return True
        print(9 * " " + f"{self.COL.yellow}No kiss modem found{self.COL.end}")
        return False

    def _serial_con(self) -> bool:
        """
        Opens serial port with self.BAUD Bd
        :return: True when serial could be opened
        """
        try:
            self._ser = serial.Serial(
                port=self.CONFIG["serial"][0],
                baudrate=self.CONFIG["serial"][1],
                timeout=1
            )  # timeout necessary no to block rest of pgm
        except (serial.SerialException, serial.SerialTimeoutException) as err:
            # print(" " * 9 + aprs.t_wrap(f"{self.COL.red}Serial interface: Check connection "
            #                            f"and driver name. Error {str(err)}{self.COL.end}", 9)
            #      )
            logging.warning("[WRN ] %s", str(err))
            return False
        self._ser_fn = self._ser.fileno()
        self._dispatch_in[self._ser.fileno()] = self._hdl_ser_rx  # handle kiss input
        self._inputs.append(self._ser.fileno())
        print(" " * 9 + f"Serial port {self._ser.name} opened")
        return True

    def _do_gating(self, packet: dict):
        """
        Forwards received packet to the internet. q construct and own
        call added.
        :param route: routing string
        :param payld: payload
        :return:
        """
        # add ",qAO,mycall-ssid:"
        packet["path"].append("qAO")
        packet["path"].append(self._user)
        p_str = bytes(aprs.packet_prn(packet), "ascii")
        self._queue_list[self._aprs_fn] = p_str  # put into output queue
        if self._aprs_fn not in self._outputs:
            self._outputs.append(self._aprs_fn)
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
        if m_id not in self._ack_list:
            return
        index = list(self._ack_list.keys()).index(m_id)
        aprs_str: str = self._ack_list[m_id]
        retry = self._ack_list["send"][index - 1]
        if retry == 0:  # all retries done
            del self._ack_list["send"][index - 1]
            del self._ack_list[m_id]
            self.p_stat["msg_sent"] += 1
            return
        logging.info("[MSG ] Id %s Retry %i", m_id, retry)
        wait = 60. + (self._MSG_RETRY - retry) * 30
        threading.Timer(wait, self._hdl_msg_tx, (m_id,)).start()
        self._ack_list["send"][index - 1] = retry - 1
        # todo: routing?
        if self.kiss.kiss_fn == 0:
            out_fn = self._aprs_fn  # send via internet server
        else:
            out_fn = self.kiss.kiss_fn  # send via kiss
        self._queue_list[out_fn] = bytes(aprs_str, "ascii")
        if out_fn not in self._outputs:
            self._outputs.append(out_fn)
        self.packet_parse(bytes(aprs_str, "ascii"))

    def _hdl_msg_input(self):
        """
        Get message input from keyboard and put aprs message into the ack_list
        :return:
        """
        call_to = ""
        message = ""
        in2 = " "
        while in2[0] not in ["Y", "y", "C", "c"]:
            in1 = ""
            while 0 > len(in1) > 9 or not re.match(r"([A-Z\d]{4,7})(-\d{1,2})?", in1.upper()):
                in1 = input("To call sign (9 char max): ")
                if in1 == "":
                    break
                call_to = in1.upper()
            in1 = ""
            while 1 > len(in1) < 67:
                in1 = input(
                    "Message (67 char max):\r\n"
                    ".........1.........2.........3.........4.........5.........6.......\r\n"
                )
            message = in1
            in2 = input("Ok to send? (y/n/c): ")
        if in2[0] in ["C", "c"]:
            print("Message send cancelled")
            return
        self.msg_id += 1 % 99
        id_str = str(format(self.msg_id, '02d'))
        routing = f"{self._user}>{self._VERS},"
        routing += "WIDE1-1, WIDE2-1:" \
            if self.kiss.kiss_fn != 0 else "TCPIP*:"
        payload = f":{call_to.ljust(9)}:{message}"
        retry = 1  # no ack expected
        if not call_to.startswith("BLN"):
            payload += "{" + id_str
            retry = self._MSG_RETRY
        self._msg_list[strftime("%Y-%m-%d %H:%M:%S", localtime())] = \
        [self._user, payload.strip()]  # msg list
        if id_str not in self._ack_list:
            self._ack_list[id_str] = routing + payload + "\r\n"
            self._ack_list["send"].append(retry)
            self._hdl_msg_tx(id_str)  # handle message send

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
            self._msg_list[strftime("%Y-%m-%d %H:%M:%S", localtime())] \
                = [call_to, pay_ld]
            seq = ack_c.group(1)
            aprs_str = f"{self._user}>" \
                       f"{self._VERS},TCPIP*::{call_to.ljust(9)}:ack{seq}\r\n"
            packet = bytes(aprs_str, "ascii")
            # todo: direct to "sock_out"
            self._queue_list[self._aprs_fn] = packet
            if self._aprs_fn not in self._outputs:
                self._outputs.append(self._aprs_fn)
        elif ack_a:  # received ack for msg sent
            seq = ack_a.group(1)
            if seq in self._ack_list:
                index = list(self._ack_list.keys()).index(seq)
                del self._ack_list["send"][index - 1]
                del self._ack_list[seq]
                self.p_stat["msg_sent"] += 1
                self.p_stat["msg_sack"] += 1
                self._msg_list[strftime("%Y-%m-%d %H:%M:%S", localtime())] = \
                    ["", f"{seq} acknowledged"]
                logging.info("[MSG ] Message %s was acknowledged!", seq)
                self._queue_list[sys.stdout.fileno()] = \
                    f"[MSG ] {self.COL.purple}Message {seq} acknowledged!{self.COL.end}\r\n"

    def _send_my_position(self):
        """
        thread that sends position every BEACON sec to APRS IS
        """
        pos_c = aprs.compress_position(self.CONFIG["pos"]["lat"],
                                       self.CONFIG["pos"]["lon"],
                                       self.CONFIG["pos"]["alt"])
        position_string = f"{self._user}" \
                          f">{self._VERS},TCPIP*:={pos_c}{self.CONFIG['beacon']}\n"
        threading.Timer(self.BEACON, self._send_my_position).start()
        self._queue_list[self._aprs_fn] = bytes(position_string, "ascii")
        # send t APRS-IS
        if self._aprs_fn not in self._outputs:
            self._outputs.append(self._aprs_fn)
        self.packet_parse(bytes(position_string, "ascii"))

    def packet_parse(self, packet: bytes):
        """
        Parse packets received, check validity, determine data type, and
        whether it should be gated to the internet. Gating is called from here.
        Handle messages received to own call
        :param packet: bytes with packet received
        :return:
        """
        if packet == {}:
            logging.info("packet_parse: Empty packet")
            return
        p_dec = aprs.packet_parse(packet)
        _, payload = aprs.decode_ascii(p_dec["payload"])
        data_type = aprs.get_data_type(p_dec["dta_id"])
        aprs_str = aprs.packet_prn(p_dec)
        own = False
        if p_dec["payload"] == "":
            logging.debug("packet parse: empty payload")
            return
        if p_dec["source"] == self._user:
            own = True  # own packet, print in blue
            aprs_str = aprs.packet_prn(p_dec, self.COL.blue)
        else:  # put into list of unique call signs
            # todo take out ssid
            if p_dec["source"] not in self.p_stat["calls"]:
                self.p_stat["calls"].append(p_dec["source"])
        if data_type in ["MSG ", "3PRT"]:
            rec = re.match(r":([0-9A-Z -]{9}):", payload)
            if rec: # check for own call and handle received message
                if rec.group(1).strip(" ") == f"{self._user}":
                    self._hdl_msg_rx(p_dec["source"], payload)
                    aprs_str = aprs.packet_prn(p_dec, self.COL.purple)
        reason = aprs.check_routing(p_dec)
        if reason == "" and p_dec["q_constr"] == "" and not own:
            # gate message to the internet
            self._do_gating(p_dec)
            aprs_str = aprs.packet_prn(p_dec, self.COL.green)
        if reason != "":
            p_dec["info"] = reason
            self.p_stat["not gated"] += 1
            aprs_str = aprs.packet_prn(p_dec, self.COL.yellow)
        logging.debug("[%s] %s", data_type, aprs_str)
        pck = bytes(f"[{data_type}] {aprs_str}", "utf-8")
        self._queue_list[sys.stdout.fileno()] = pck
        if data_type == "MICE":  # decode MIC_E packets
            self._queue_list[sys.stdout.fileno()] \
               += b"\r\n" + bytes(7 * " " + aprs.mic_e_decode(p_dec), "utf-8")

    def prn_hlp(self):
        """
        Help function to show the available commands
        :return:
        """
        hlp_txt = "\r\nCommands:\r\n" \
                  f" {self.COL.bold}help:{self.COL.end} This help text\r\n" \
                  f" {self.COL.bold}kiss:{self.COL.end} Connect Kiss modem\r\n" \
                  f" {self.COL.bold}isrx:{self.COL.end} Toggle internet receive on/off\r\n" \
                  f" {self.COL.bold}pos: {self.COL.end} Send my position\r\n" \
                  f" {self.COL.bold}msg: {self.COL.end} Send message\r\n" \
                  f" {self.COL.bold}que: {self.COL.end} Show message queue\r\n" \
                  f" {self.COL.bold}stat:{self.COL.end} Show statistics\r\n" \
                  f" {self.COL.bold}io:  {self.COL.end} Show status of I/O\r\n" \
                  f" {self.COL.bold}exit:{self.COL.end} Exit program\r\n"
        print(textwrap.indent(hlp_txt, 9 * " "))

    def prn_stat(self):
        """
        Print statistics
        :return:
        """
        time_on = datetime.datetime.now() - self.start_datetime
        pck_tot = self.p_stat['is_rcvd'] + self.p_stat['ser_rcvd'] + self.p_stat['gated']
        print(f"IGate up {time_on.days} days {round(time_on.seconds / 3600, 1)} h ")
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
                + ' '.join([str(call) for call in self.p_stat["calls"]]), aprs.WRAP
            )[0]
        )

    def prn_io(self):
        """
        Print IO status of interfaces
        :return:
        """
        print(9 * " " +
              f"I/O: APRS-IS: {self._red_green(self._aprs_fn)}"
              f" APRS-IS RX: {self._red_green(self.is_rx)}"
              f" Serial: {self._red_green(self._ser_fn)}"
              f" KISS: {self._red_green(self.kiss.kiss_fn)}"
              )

    def _red_green(self, var) -> str:
        """
        ON (green) for var true, OFF (red) otherwise
        :param var: bool or int
        :return:
        """
        var = int(var)
        p_var = self.COL.red + "OFF" if var == 0 else self.COL.green + "ON"
        p_var += self.COL.end
        return p_var

    def _tgl_isrx(self):
        """
        Toggle between receiving from APRS server on/off
        :return:
        """
        sw_prn = self._red_green(self.is_rx)
        prmpt = f"APRS-IS rx is {sw_prn}, switch off (y/n)?"
        if not input(prmpt).upper().startswith("Y"):
            return
        self.is_rx = not self.is_rx
        if self.is_rx:
            self._client.recv(self._BUF)  # make buffer empty
            self._inputs.append(self._aprs_fn)
        else:
            if self._aprs_fn in self._queue_list:
                del self._queue_list[self._aprs_fn]
            self._inputs.remove(self._aprs_fn)
        logging.info("Internet receive is %s", self.is_rx)
        # p_prn = f"[INFO] Internet receive is switched {self.red_green(self.is_rx)}."
        self.prn_io()
        if self.kiss.kiss_fn == 0 and self._ser_fn == 0 and not self.is_rx:
            self._queue_list[sys.stdout.fileno()] \
               = bytes(f"\r\n{self.COL.red}       No packets can be received, "
                        f"no radio connected{self.COL.end}", "utf-8")

    def _hdl_kbd(self):
        """
        Handler for keyboard input
        :return: None
        """
        inv_cmd = bytes(f"{self.COL.red}Invalid keyboard input{self.COL.end}", "utf-8")

        line = sys.stdin.readline()
        if line.startswith("help"):
            self.prn_hlp()
        elif line.startswith("kiss"):
            if self.kiss.kiss_fn == 0:
                self._kiss_con()
            else:
                print(9 * " " \
                      + f"{self.COL.yellow}Kiss modem already connected{self.COL.end}")
        elif line.startswith("isrx"):
            self._tgl_isrx()
        elif line.startswith("pos"):
            self._send_my_position()
        elif line.startswith("msg"):
            self._hdl_msg_input()
        elif line.startswith("que"):
            # todo: function with structured printout
            print(json.dumps(self._msg_list, indent=4))
            print(json.dumps(self._ack_list, indent=4, sort_keys=True))
        elif line.startswith("stat"):
            self.prn_stat()
        elif line.startswith("io"):
            self.prn_io()
        elif line.startswith("exit"):
            self._close_pgm()
        else:
            self._queue_list[sys.stdout.fileno()] = inv_cmd

    def _hdl_prn(self):
        """
        Handler for formatted stdout (print). Adds timestamp
        and indent output
        :return: None
        """
        if not self._queue_list or sys.stdout.fileno() not in self._queue_list:
            return
        try:
            b_txt = self._queue_list[sys.stdout.fileno()]
        except KeyError:
            # todo: check, whether exception is really necessary
            logging.debug("KeyError in hdl_prn %s", self._queue_list)
            return
        text = aprs.decode_ascii(b_txt)
        lines = text[1].split("\r\n")
        for line in lines:
            if len(line) > 0:
                t_out = time.strftime("%H:%M:%S ") + aprs.t_wrap(line, aprs.INDENT)
                sys.stdout.write(t_out)
        del self._queue_list[sys.stdout.fileno()]  # delete from queue

    def _hdl_timeout(self):
        """
        Reconnect to APRS server in case of timeout. Called every
        retry seconds until internet is back
        :return:
        """
        retry = 120.  # wait 2 min before trying to reconnect
        logging.warning("[TOUT] timeout or start login - fn: %s", self._aprs_fn)
        # todo remove fn
        if aprs.is_internet():
            if self._aprs_con():
                self._send_my_position()
                return
        else:
            b_txt = bytes(f"{self.COL.yellow}Trying to reconnect ...{self.COL.end}", "utf-8")
            self._queue_list[sys.stdout.fileno()] = b_txt
            threading.Timer(retry, self._hdl_timeout).start()

    def _hdl_aprs_rx(self):
        """
        Handler to read packets from APRS-IS and forward them to stdout
        via the parser.
        :return: None
        """
        try:
            buf = self._client.recv(self._BUF)
            logging.debug("APRS buf: %s", buf)
        except (TimeoutError, OSError) as err:
            self._queue_list[sys.stdout.fileno()] = \
                bytes(f"{self.COL.yellow}Error reading from APRS-IS{self.COL.end}:"
                      f" {err}\r\n", "utf-8")
            self._hdl_timeout()  # try to reconnect
            return
        if buf.startswith(b"#"):  # disregard aprs-is comments
            return
        for packet in buf.splitlines():
            self.packet_parse(packet)
            self.p_stat["is_rcvd"] += 1

    def _hdl_aprs_tx(self):
        """
        Handler for sending data to APRS-IS
        :return: None
        """
        b_to_send = self._queue_list[self._aprs_fn]
        try:
            self._client.sendall(b_to_send)
        except (TimeoutError, BrokenPipeError, OSError) as err:
            # todo: error handling
            print(f"{self.COL.yellow}Error writing to APRS-IS"
                  f"{self.COL.end}: {err}", "utf-8")
            self._hdl_timeout()  # try to reconnect
        logging.info("[TX  ] %s", b_to_send)
        del self._queue_list[self._aprs_fn]  # delete from queue
        self._outputs.remove(self._aprs_fn)

    def _hdl_ser_rx(self):
        """
        Handler for serial input from Yaesu radio
        :return:
        """
        is_ui = re.compile(r" \[.*\] <UI.*>")
        b_p1 = self._ser.read_until()
        if b_p1 == b'\r\n' or len(b_p1) == 0:  # \r\n
            return
        logging.debug("Ser1: %s", b_p1)
        a_p1 = aprs.decode_ascii(b_p1)  # 1st line routing
        if is_ui.search(a_p1[1]):
            b_p1 = bytes(is_ui.sub("", a_p1[1].strip()), "ascii")
            b_p2 = self._ser.read_until()  # 2nd line payload bytes
            logging.debug("Ser2: %s", b_p2)
        else:  # out of sync, disregard payload
            logging.info("[SER ] out of sync: %s", b_p1)
            return
        buf = b_p1 + b_p2  # complete received packet
        logging.info("[SER ] %s", buf)
        self.p_stat["ser_rcvd"] += 1
        self.packet_parse(buf)

    def _hdl_kiss_tx(self):
        """
        Coding of message frame and sending to Kiss modem
        :return:
        """
        b_to_send = self._queue_list[self.kiss.kiss_fn]
        a_msg = b_to_send.decode("ascii")
        _, a_msg = a_msg.split(":", 1)
        frame = self.kiss.encode_msg_frame(call_to=a_msg[1:9].strip(" "), message=a_msg[11:])
        self.kiss.kiss_cmd(self.kiss.KISS_PORT, self.kiss.KISS_DATA, frame)
        logging.info("[KISS] %s", b_to_send)
        del self._queue_list[self.kiss.kiss_fn]  # delete from queue
        self._outputs.remove(self.kiss.kiss_fn)
        self.packet_parse(b_to_send)

    def _hdl_kiss_rx(self):
        """
        Receiving and parsing packets from Kiss modem
        :return:
        """
        packet = self.kiss.hdl_kiss_rx()
        if packet == b"":
            # connection lost
            self._inputs.remove(self.kiss.kiss_fn)
            self.kiss.TCPClient.close()
            self.kiss.kiss_fn = 0
            logging.info("[WRN ] Kiss modem disconnected")
            self._queue_list[sys.stdout.fileno()] = \
                bytes(f"[WRN ] {self.COL.yellow}Kiss modem disconnected{self.COL.end}", "utf-8")
            return
        logging.info("[KISS] %s", packet)
        self.packet_parse(packet)

    def _close_pgm(self):
        """
        CLosing the program with exit, displaying statistics
        :return:
        """
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
            f"{self.COL.green}{(str(self.start_datetime).split('.'))[0]} "
            f"{self._user} "
            f"IGgate started - Program Version {self._VERS[-3:]} "
            f"by 9V1KG{self.COL.end}"
        )
        issw = f"{self.COL.green}ON{self.COL.end}" \
            if self.is_rx else f"{self.COL.red}OFF{self.COL.end}"
        print(" " * 9 + f"Receive packets from APRS-IS is {issw}, toggle with \"isrx\"")

        pos_c = aprs.compress_position(self.CONFIG["pos"]["lat"],
                                       self.CONFIG["pos"]["lon"],
                                       self.CONFIG["pos"]["alt"])
        pos_f = aprs.format_position(self.CONFIG["pos"]["lat"], self.CONFIG["pos"]["lon"])
        print(" " * 9 + f"Formatted  Position: {pos_f}")
        print(" " * 9 + f"Compressed Position: {pos_c}")
        logging.info("Ygate program started, version %s", self._VERS)

        self.prn_hlp()
        self._dispatch_in[sys.stdin.fileno()] = self._hdl_kbd  # handle keyboard input
        self._dispatch_out[sys.stdout.fileno()] = self._hdl_prn  # handle print output

        self._serial_con()  # open serial
        self._kiss_con()  # open kiss modem
        self._hdl_timeout()  # open socket and connect to aprs server
        self.prn_io()

    def main(self):
        """
        Main program for ygate2
        :return: None
        """
        self._start_up()
        while self._inputs:
            readable, writable, _ \
                = select.select(self._inputs, self._outputs, [])
            for sel in readable:
                self._dispatch_in.get(sel)()
            for sel in writable:
                self._dispatch_out.get(sel)()
            time.sleep(0.2)


if __name__ == "__main__":
    YGATE = Ygate2()
    YGATE.main()
