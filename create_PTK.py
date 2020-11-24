from scapy.all import *
from pbkdf2 import PBKDF2
import hmac
from hashlib import pbkdf2_hmac, sha1, md5

cap = "/home/kali/Documents/groep2-07.cap"
packet_file = rdpcap(cap)

ssid = "groep2"
password = "uncrackable"
PMK = PBKDF2(password, ssid, 4096).read(32).hex()


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

Anonce = nonces[0]
Snonce = nonces[1]
Amac = authenticator_macs[0]
Smac = supplicant_macs[0]

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
		hmacsha1 = hmac.new(PMK.encode(), A + chr(0x00).encode() + B + chr(i).encode(), sha1)
		R = R + hmacsha1.digest()
		i += 1
	return R[:nByte]


def make_B(Anonce, Snonce, Amac, Smac):
	B = min(Amac, Smac) + max(Amac, Smac) + min(Anonce, Snonce) + max(Anonce, Snonce)
	return B.encode()


def format_mac(mac):
	new_mac = mac.replace(":", "")
	return new_mac

B = make_B(Anonce, Snonce, Amac, Smac)

Amac = format_mac(Amac).encode()
Smac = format_mac(Smac).encode()
A = b'Pairwise key expansion'

PTK = PRF(PMK, A, B).hex()


print("PTK : ")
print(PTK)






