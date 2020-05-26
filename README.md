# Yaesu APRS IGate 2.0

Ygate2 is an APRS Internet gate working with Yaesu radios.
This version is an improved version based on my previous first version Igate-n with
additional features. More features to follow.
(c) 9V1KG

The script will turn your Yaesu radio (FT1D, FTM-100, FTM-400) into a receive-only
APRS IGate. All APRS packet traffic received by your radio will be forwarded to the 
Internet (APRS-IS Servers) for further routing. Just connect the Yaesu supplied 
USB cable from your radio to the computer and run the script under Python 3.

The script is still experimental under testing on MacOS and Raspberry Pi 3B+. 
It should run on Windows too.

## Features
- Runs under Python 3 (tested with 3.7 and 3.8)
- Checks and recovers from lost network/internet connection
- Interactive terminal input during runtime
- NEW: allows to send and receive messages via APRS-IS
- Beacon of your position and altitude in compressed format
- Statistics showing up-time, processed packets and unique call signs
- Checks packet payload decoding and highlight invalid bytes
- Displays APRS data type POS, MSG, MICE, WX etc.
- Colored terminal text output
- All output data logged into a log file

## User Settings
Please modify the following parameter in `ygate2.py` according 
to your requirements:
### User settings

     parameter to set:
     self.user = User(
            my_call="MYCALL",
            ssid=10,
            secret=00000,
            pos=((14, 7.09, "N"), (120, 58.07, "E"), (570, "m"))
        )

 - `my_call=`:   your call sign, e.g. DU1KG
 - `ssid=`:      ssid for the gateway (default 10)
 - `secret=`:    your APRS 5-digit pass code
 - `pos=` (Latitude, Longitude, Altitude):
 - Latitude and longitude in the format
 `(degrees, minutes as decimal number, N/S/E/W)`. 
Altitude in meter `"m"` or feet `"ft"`, e.g. `(0.,"m")` if none
### Constants
     
    RANGE:  Filter range in km (default 150) 
    SERIAL: Serial driver (default "/dev/ttyUSB0")

## Radio Setup FTM-400
    Setup -> APRS -> (5) APRS Modem -> ON
    Setup -> DATA -> (1) COM PORT SETTINGS
        SPEED     -> 9600 bps
        OUTPUT    -> PACKET
        WP FORMAT -> NMEA 9
    Setup -> DATA -> (3) DATA SPEED
        APRS 1200 bps
        DATA 9600 bps

## Install and Run

For a simple installation as python script, copy the file `ygaten.py` into your directory 
and make it executable.
Modify the parameter as explained above. Import `pySerial` and `requests` with:

    pip install pySerial
    pip install requests

Start the program from the command line window in your directory with: 

    python3 ygate2.py

Stop the program with `exit`.
### Install as Python module
    git clone https://github.com/9V1KG/ygate2.git
    cd ygate2
    # create and activate virtual environment
    python3 -m venv venv
    source venv/bin/activate
    python setup.py install
    # python setup.py install --user (Raspi)
    # run Ygate2
    python3 -m ygate2

## Runtime Commands

    help: This help text
    isrx: Toggle internet receive on/off
    pos:  Send my position
    msg:  Send message
    que:  Show message queue
    stat: Show statistics
    exit: Exit program


