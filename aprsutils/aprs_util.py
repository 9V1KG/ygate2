"""
Module with utilities and functions for APRS decoding/encoding
Author: Klaus D Goepel, 9V1KG
"""
import textwrap
import re
import math
import logging
import requests

WRAP = 120
INDENT = 16

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

# Message types for MIC-E encoded frames
MSG_TYP = {"std": 0, "cst": 1}
MSG_ID = {
    0: ["Emergency", "Emergency,"],
    1: ["Priority", "Custom-6"],
    2: ["Special", "Custom-5"],
    3: ["Committed", "Custom-4"],
    4: ["Returning", "Custom-3"],
    5: ["In Service", "Custom-2"],
    6: ["En Route", "Custom-1"],
    7: ["Off Duty", "Custom-0"],
}


class Color:
    """
    Class color for colored terminal output
    """
    def __init__(self):
        self.red = "\033[1;31;48m"
        self.green = "\033[1;32;48m"
        self.yellow = "\033[1;33;48m"
        self.blue = "\033[1;34;48m"
        self.purple = "\033[1;35;48m"
        self.cyan = "\033[1;36;48m"
        self.bold = "\033[1;37;48m"
        self.end = "\033[1;37;0m"


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


def b91_encode(v_int: int) -> str:
    """
    Calculates an ASCII string base 91 from r
    Max: 91 ** 4 = 68 574 961
    :param v_int: scaled position latitude or longitude
    :return: character string
    """
    l_str = ""
    for i in range(0, 5):
        dvr = 91 ** (4 - i)
        l_str += chr(int(v_int / dvr) + 33)
        v_int = v_int % dvr
    return l_str.lstrip("!")


def b91_decode(l_str: str) -> int:
    """
    Decodes ASCII string base 91 to number
    :param l_str: base 91 encoded ASCII string
    :return: r result
    """
    l_len = len(l_str) - 1
    v_int = 0
    for i, l_chr in enumerate(l_str):
        v_int += (ord(l_chr) - 33) * 91 ** (l_len - i)
    return v_int


def format_position(lat: tuple, lon: tuple) -> str:
    """
    # Formatted uncompressed APRS Position String
    :param lon: Tuple of Degree, Decimal-Minutes, "N or S"
    :param lat: Tuple of Degree, Decimal-Minutes , "E or W"
    :return: Aprs formatted string
    """
    symbol = "/#"  # Gateway symbol
    lat = "{:02d}".format(lat[0]) + "{:05.2f}".format(lat[1]) + lat[2]
    lon = "{:03d}".format(lon[0]) + "{:05.2f}".format(lon[1]) + lon[2]
    f_pos = f"{lat}{symbol[0]}{lon}{symbol[1]}"
    if re.match(  # check validity of position
            r"[0-8]\d[0-5]\d\.\d\d[N,S][/,\\][0,1][0-7]\d[0-5]\d\.\d{2}[E,W].",
            f_pos
    ):
        return f_pos
    return f"Invalid position input {lat}, {lon}."


def compress_position(lat: tuple, lon: tuple, alt: tuple = (0.0, "m")) -> str:
    """
    # Calculate compressed position info as string
    # uses b91(r)
    :param lon: Tuple of Degree, Decimal-Minutes , "E or W"
    :param lat: Tuple of Degree, Decimal-Minutes, "N or S"
    :param alt: Tuple of altitude, unit "m' or "ft"
    :return: APRS compressed position string
    """
    symbol = "/#"  # Gateway symbol
    lstr = symbol[0]  # symbol table id

    lat_dec = -(lat[0] + lat[1]/60.) if "S" in lat[2] else (lat[0] + lat[1]/60.)
    lon_dec = -(lon[0] + lon[1]/60.) if "W" in lat[2] else (lon[0] + lon[1]/60.)
    v_int = int(380926 * (90.0 - lat_dec))
    lstr += b91_encode(v_int)  # Compressed Latitude XXXX
    v_int = int(190463 * (180.0 + lon_dec))
    lstr += b91_encode(v_int)  # Compressed Longitude YYYY

    lstr += symbol[1]  # station symbol

    if alt[0] == 0.:
        lstr += "   "  # no altitude data
    else:  # csT bytes
        h_ft = alt[0]/0.3048 if "m" in alt[1] else alt[0]
        a_pot = int(math.log(h_ft) / math.log(1.002))
        lstr += chr(33 + int(a_pot / 91)) + chr(33 + int(a_pot % 91))
        lstr += chr(33 + int("00110010", 2) + 33)  # comp type altitude
    return lstr


def _cnv_ch(o_chr: chr) -> chr:
    """
    Character decoding for MIC-E destination field
    used in mic_e_decoding
    :param o_chr: original char
    :return: modified char
    """
    if o_chr in ["K", "L", "Z"]:  # ambiguity
        return chr(48)
    if ord(o_chr) > 79:
        return chr(ord(o_chr) - 32)
    if ord(o_chr) > 64:
        return chr(ord(o_chr) - 17)
    return o_chr


def prn_mice(mice_dec: dict) -> str:
    """
    Convert MIC-E dict into printable one line string
    :param mice_dec: decoded mic_e dictionary
    :return: string for printing
    """
    mice_d_str = \
        f"Pos: {mice_dec['latitude']['deg']} " \
        f"{mice_dec['latitude']['min']}'{mice_dec['latitude']['dir']}, " \
        f"{mice_dec['longitude']['deg']} " \
        f"{mice_dec['longitude']['min']}'{mice_dec['longitude']['dir']}, " \
        f"{mice_dec['info']}, "
    if mice_dec['ambiguity'] > 0:
        mice_d_str += f"Ambgty: {mice_dec['ambiguity']} digits, "
    if mice_dec['speed'] > 0:
        mice_d_str += f"Speed: {mice_dec['speed']} knots, "
    if mice_dec['course'] > 0:
        mice_d_str += f"Course: {mice_dec['course']} deg, "
    if mice_dec['altitude'] > 0:
        mice_d_str += f"Alt: {mice_dec['altitude']} m, "
    # decoded += f"Status: {info}"
    return mice_d_str


def mic_e_decode(route: str, m_i: bytes) -> str:
    """
    Decodes APRS MIC-E encoded data
    :param route: routing field
    :param m_i: payload bytes
    :return: str with decoded information or empty
    """
    decode = {
        "symbol": "",
        "latitude": {"deg": 0, "min": 0.0, "dir": ""},
        "longitude": {"deg": 0, "min": 0.0, "dir": ""},
        "info": "",
        "altitude": 0,
        "ambiguity": 0,
        "speed": 0,
        "course": 0,
        "msg": ""
    }
    # Check input
    if len(m_i) == 0 or chr(m_i[0]) not in ["'", "`"]:
        return ""
    m_d = re.search(r">([A-Z,\d]{6,7}),", route)  # extract destination
    if not m_d:
        return ""
    m_d = m_d.group(1)
    # Check validity of input parameters
    if not re.search(r"[0-9A-Z]{3}[0-9L-Z]{3,4}$", m_d):
        return ""
    if not re.match(
            r"[\x1c\x1d`'][&-~,\x7f][&-a][\x1c-~,\x7f]{5,}", m_i.decode("ascii")
    ):
        return ""
    # Message type first three bytes destination field
    msg_t: str = "std"
    mbits: int = 0  # message bits (0 - 7)
    for i in range(0, 3):
        mbits += (4 >> i) if re.match(r"[A-K,P-Z]", m_d[i]) else 0
    # print("Message bits: {:03b}".format(mbits))
    if re.search(r"[A-K]", m_d[0:3]):
        msg_t = "cst"  # custom
    decode["info"] = MSG_ID[mbits][MSG_TYP[msg_t]]

    # Lat N/S, Lon E/W and Lon Offset byte 1 to 6
    decode["latitude"]["dir"] = "S" if re.search(r"[0-L]", m_d[3]) else "N"
    lon_o = 0 if re.search(r"[0-L]", m_d[4]) else 100
    decode["longitude"]["dir"] = "E" if re.search(r"[0-L]", m_d[5]) else "W"
    decode["ambiguity"] = (len(re.findall(r"[KLZ]", m_d)))
    # Latitude deg and min
    lat = "".join([_cnv_ch(ch) for ch in list(m_d)])
    decode["latitude"]["deg"] = int(lat[0:2])
    decode["latitude"]["min"] = round(int(lat[2:4]) + int(lat[-2:]) / 100, 2)

    # MIC-E Information field
    # Longitude deg and min byte 2 to 4 info field
    decode["longitude"]["deg"] = m_i[1] - 28 if lon_o == 0 else m_i[1] + 72
    decode["longitude"]["deg"] = decode["longitude"]["deg"] - 80 \
        if 189 >= decode["longitude"]["deg"] >= 180 else decode["longitude"]["deg"]
    decode["longitude"]["deg"] = decode["longitude"]["deg"] - 190 \
        if 199 >= decode["longitude"]["deg"] >= 190 else decode["longitude"]["deg"]
    decode["longitude"]["min"] = m_i[2] - 88 if m_i[2] - 28 >= 60 else m_i[2] - 28
    decode["longitude"]["min"] = round(decode["longitude"]["min"] + (m_i[3] - 28) / 100, 2)

    # Speed and Course bytes 5 to 7 info field
    decode["speed"] = (m_i[4] - 28)
    decode["speed"] = (decode["speed"] - 80) * 10 \
        if decode["speed"] >= 80 else decode["speed"] * 10 + int((m_i[5] - 28) / 10)
    decode["speed"] = decode["speed"] - 800 \
        if decode["speed"] >= 800 else decode["speed"]
    decode["course"] = 100 * ((m_i[5] - 28) % 10) + m_i[6] - 28
    decode["course"] = decode["course"] - 400 \
        if decode["course"] >= 400 else decode["course"]

    # Symbol bytes 8 to 9 info field
    decode["symbol"] = chr(m_i[7]) + chr(m_i[8])

    # Check for altitude or telemetry
    if len(m_i) > 9:
        decode["msg"] = decode_ascii(m_i[9:])[1]
        # Check for altitude
        m_alt = re.search(r".{3}}", decode["info"])
        if m_alt:
            decode["altitude"] = b91_decode(m_alt.group()[:3]) - 10000
        if m_i[9] in [b"'", b"`", b'\x1d']:
            # todo decode telemetry data
            # "'" 5 HEX, "`" 2 HEX "\x1d" 5 binary
            # info = "Telemetry data"
            pass
    return prn_mice(decode)


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


def print_wrap(text: str):
    """
    Prints text wrapped and indented
    :param text: input string
    :return:
    """
    lines = textwrap.wrap(text, WRAP)
    print(lines.pop(0))
    for line in lines:
        print(textwrap.indent(line, 16 * " "))


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
            f"\033[1;31;48mInternet connection failed: "
            f"{h_err.response.status_code}\033[1;37;0m"
        )
        logging.warning("is_internet: %s", h_err.response.status_code)
        return False
    except requests.exceptions.ConnectionError as c_err:
        print({c_err})
        logging.warning("is_internet: %s", c_err)
        return False
