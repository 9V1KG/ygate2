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
- NEW: kiss interface to direwolf 
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

     Parameter to set:
        "mycall": "MYCALL",
        "ssid": 10,
        "secret": 00000,
        "pos": {
            "lat": (14, 7.09, "N"),
            "lon": (120, 58.07, "E"),
            "alt": (0, "m"),
        },
        "filter": 150,  # range in km
        "beacon": "Testing Yaesu IGate 2.0 program - 73",
        "status": "IGate is up - RF-IS for FTM-400: https://github.com/9V1KG/Ygate2",
        "serial": ("/dev/tty.usbserial-14110", 9600),
        "aprsis": ("rotate.aprs2.net", 14580),

 - `mycall=`:   your call sign, e.g. DU1KG
 - `ssid=`:      ssid for the gateway (default 10)
 - `secret=`:    your APRS 5-digit pass code
 - `pos=` (Latitude, Longitude, Altitude):
 - Latitude and longitude in the format
 `(degrees, minutes as decimal number, N/S/E/W)`.
 Altitude in meter `"m"` or feet `"ft"`, e.g. `(0.,"m")` if none
 - `filter` Filter range to receive from APRS-IS in km 
 - `serial`: Serial driver and baud ("/dev/ttyUSB0")
 - `aprsis`: APRS server address
 
     
    

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

Modify the parameter as explained above.
Start the program from the command line window in your directory with: 

    cd ygate2
    python3 -m ygate2

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
    kiss: Connect Kiss modem
    isrx: Toggle internet receive on/off
    pos:  Send my position
    msg:  Send message
    que:  Show message queue
    stat: Show statistics
    exit: Exit program


