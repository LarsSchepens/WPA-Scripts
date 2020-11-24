import os, sys

#This script implements a standard wordlist attack 

wordlist = input("Enter your wordlist: ")
cap = input("Enter your .cap file: ")

cmd = "aircrack-ng %s -w %s" %(cap, wordlist)
os.system(cmd)
