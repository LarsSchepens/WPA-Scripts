
from scapy.all import *
from pbkdf2 import PBKDF2
import hmac
from hashlib import pbkdf2_hmac, sha1, md5
from binascii import a2b_hex, b2a_hex

#Put the .cap file you want to analyse here
cap = "/home/kali/Documents/groep2-13.cap"
packet_file = rdpcap(cap)

ssid = "groep2 "
password = "uncrackable"


# Create the PMK using the pbkdf2 function
PMK = pbkdf2_hmac('sha1', password.encode('ascii'), ssid.encode('ascii'), 4096, 32).hex()

authenticator_macs = []
supplicant_macs = []
eapol = []
# Filter all the handshake packets
for pkt in packet_file:
	if pkt.haslayer(EAPOL):
		eapol.append((pkt.load).hex())
		authenticator_macs.append(pkt.addr1)
		supplicant_macs.append(pkt.addr2)
	

# There is a chance a handshake packet will be sent twice, this while loop removes these duplicates
i = 1
while i < len(eapol):
	if eapol[i][26:90] == eapol[i-1][26:90]:
		del eapol[i]
	else:
		i += 1

#Manually select 1 handshake
handshake1 = eapol[:4]

nonces = []
key_ivs = []
rsc = []
key_ids = []
MICs = []
key_datas = []

for pkt in handshake1:
	nonces.append(pkt[26:90])
	key_ivs.append(pkt[90:122])
	rsc.append(pkt[122:138])
	key_ids.append(pkt[138:154])
	MICs.append(pkt[154:186])
	key_datas.append(pkt[190:])



def PRF(PMK, A, B):
	"""
	Pseudo-random function for the generation of the PTK
	PMK: The Pairwise Master Key
	A: b'Pairwise key expansion'
	B: Concatination of the Amac, Smac, Anonce and Snonce
	"""
	#Number of bytes in the PTK
	nByte = 64
	i = 0
	R = b''
	#Each iteration produces 160-bit value and 512 bits are required
	while(i <= ((nByte * 8 + 159) / 160)):
		hmacsha1 = hmac.new(a2b_hex(PMK), A + chr(0x00).encode() + B + chr(i).encode(), sha1)
		R = R + hmacsha1.digest()
		i += 1
	return R[:nByte]


def make_B(Anonce, Snonce, Amac, Smac):
	B = min(Amac, Smac) + max(Amac, Smac) + min(Anonce, Snonce) + max(Anonce, Snonce)
	
	return B


def format_mac(mac):
	new_mac = mac.replace(":", "")
	return new_mac


Anonce = a2b_hex(nonces[0])
Snonce = a2b_hex(nonces[1])

Amac = authenticator_macs[0]
Smac = supplicant_macs[0]

Amac = a2b_hex(format_mac(Amac))
Smac = a2b_hex(format_mac(Smac))


A = b'Pairwise key expansion'
B = make_B(Anonce, Snonce, Amac, Smac)

PTK = PRF(PMK, A, B).hex()

print("PMK : ")
print(PMK)

print("PTK : ")
print(PTK)










