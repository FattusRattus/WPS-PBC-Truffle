# WPS-PBX-Truffle
Wifi WPS PBX PSK Capture

Description
----
This script is based on ideas from several scripts, notably wpsspy.py from https://github.com/devttys0/wps/tree/master/wpstools

To run it: ./wps_pbc-truffle.py -i wlan1

It will create several files when running:

wps-pbc.conf - temp wpa_supplicant config file that will capture the WPA PSK
wpa-pot.txt - pot file for all captured WPA PSKs
wps-pbc.bak - last captured wpa_supplicant config file
dummy.exit - internally used file for shutting down backgound tasks


Requirements
----
It requires the Scapy Python module and Aircrack suite. It runs best from Kali, but on a Raspberry Pi 3 it does not like the internal Wifi - use an external one.

