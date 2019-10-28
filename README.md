# WPS-PBC-Truffle
Wifi WPS PBC PSK Capture

Description
----
This is a PoC script that sniffs WiFi whilst hopping channels, if it detects a WiFi router that has been put into WPS PBC pairing mode (i.e. the WPS Push Button has been pressed), it attempts to hijack the pairing and get the WPA password.

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

