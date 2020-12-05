# This script will decrypt .cap files which are encrypted with AES (in counter mode)

from scapy.all import *

def galoisMult(a, b):
    """
    Function that provides the galois multiplication of 2 integers. The output is an integer in base 10.
    """
    p = 0
    hiBitSet = 0
    for i in range(8):
        if b & 1 == 1:
            p ^= a
        hiBitSet = a & 0x80
        a <<= 1
        if hiBitSet == 0x80:
            a ^= 0x1b
        b >>= 1
    return p % 256

Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
)
Sbox_inv = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
)

np_matrix = ['0x02030101','0x01020301','0x01010203','0x03010102']
inv_np_matrix = ['0x0e0b0d09','0x090e0b0d','0x0d090e0b','0x0b0d090e']

def padded_hex(i, l):
    """
    Return an hexadecimal number with given length l. If the number has a length < l, leading zeroes will be added.
    """
    given_int = i
    given_len = l

    hex_result = hex(given_int)[2:]
    num_hex_chars = len(hex_result)
    extra_zeros = '0' * (given_len - num_hex_chars)

    return ('0x' + hex_result if num_hex_chars == given_len else
            hex(i) if num_hex_chars > given_len else
            '0x' + extra_zeros + hex_result if num_hex_chars < given_len else
            None)

def SubWord(word, box):
    """
    Returns the substition of a word given a specific substitution box.
    """
    hexlist = []
    output = ''
    for i in range(1, 5):
        hexlist.append(padded_hex(box[int(word[2 * i], 16) * 16 + int(word[2 * i + 1], 16)], 2))
    for j in hexlist:
        output += j[2:]
    return '0x' + output

def RotWord(word):
    """
    Returns the word after the first byte is moved backwards.
    """
    a = int(word, 16) * 0x100
    b = int(word, 16) // 0x1000000
    word = a + b - b * 0x100000000
    return padded_hex(word, 8)

def MakeRcon(nb):
    Rcon = []
    for i in range(nb):
        if i == 0:
            Rcon.append("0x01000000")
        elif i > 0 and int(Rcon[i-1], 16) < int('80000000', 16):
            Rcon.append(padded_hex(2* int(Rcon[i-1],16), 8))
        elif i > 0 and int(Rcon[i-1], 16) >= int('80000000', 16):
            Rcon.append(padded_hex((2*int(Rcon[i-1], 16))^int('11b000000', 16),8))
    return Rcon

def KeyExpansion(key, nb):
    """
    Gives the key expansion for a given key, for the AES algorithm.
    """
    Rcon = MakeRcon(10)
    k = MakeMatrix(key, nb)
    w = []
    for i in range((nb+7)*4):
        if i < nb:
            w.append(k[i])
        elif i >= nb and i % nb == 0:
            w.append(padded_hex((int(SubWord(RotWord(w[i-1]), Sbox), 16) ^ int(Rcon[(i // nb)-1],16) ^ int(w[i-nb], 16)), 8))
        elif (i >= nb) and (nb > 6) and i % nb == 4:
            w.append(padded_hex((int(SubWord(w[i-1], Sbox), 16) ^ int(w[i-nb], 16)), 8))
        else:
            w.append(padded_hex(int(w[i - 1], 16) ^ int(w[i - nb], 16), 8))
    return w

def AddRoundKey(state, key, nb):
    """
    Returns the xor of a state with a specific round of the expanded key.
    """
    output = []
    roundkey = key[nb * 4:(nb + 1) * 4]
    for i in range(4):
        output.append(padded_hex(int(state[i], 16) ^ int(roundkey[i], 16), 8))
    return output

def SubBytes(state, Sbox):
    """
    Returns the substitution of a state with a given substitution box.
    """
    output = []
    for i in state:
        output.append(SubWord(i, Sbox))
    return output

def ShiftRows(state):
    """
    Shifts over the rows of a state.
    """
    output = ['0x' for x in range(4)]
    for i in range(4):
        for j in range(4):
            index_state = i+j
            if index_state >= 4:
                index_state -= 4
            output[i] += state[index_state][2*j+2:2*(j+1)+2]
    return output

def InvShiftRows(state):
    """
    Shifts the rows back to its original state.
    """
    for i in range(3):
        state = ShiftRows(state)
    return state

def MixColumns(state, matrix):
    """
    Mixes the columns of a state by left multiplying it by a given matrix. The multiplication must be a galois multiplication.
    """
    output = ['0x' for x in range(4)]
    for i in range(4):
        for j in range(4):
            b = '0x00'
            for n in range(1,5):
                a = padded_hex(galoisMult(int(matrix[j][n*2:(n+1)*2],16),int(state[i][n*2:(n+1)*2],16)),2)
                b = padded_hex(int(b,16) ^ int(a, 16),2)
            output[i] += b[-2:]
    return output

def MakePlain(state):
    """
    Returns the plaintext of a state.
    """
    output = ''
    for i in state:
        output += i[2:]
    return output

def MakeMatrix(plain, nb):
    """
    Converts te plaintext into a vector.
    """
    w = []
    for i in range(nb):
        c = ""
        for j in range(8):
            c += plain[8*i + j]
            d = int(c,16)
        w.append('0x' + c)
    return w

def AESEncryption(key, plain):
    # Step 1 expand the 128 bit key
    nb = len(key) // 8
    expanded_key = KeyExpansion(key, nb)
    # Step 2 initial round key addition
    state = MakeMatrix(plain, 4)
    state = AddRoundKey(state, expanded_key, 0)
    # Step 3 9 rounds of SubBytes, Shiftrows, MixColumns and AddRoundKey
    for i in range(1, nb + 6):
        state = SubBytes(state, Sbox)
        state = ShiftRows(state)
        state = MixColumns(state, np_matrix)
        state = AddRoundKey(state, expanded_key, i)
    # Step 4 Final round
    state = SubBytes(state, Sbox)
    state = ShiftRows(state)
    output = AddRoundKey(state, expanded_key, nb + 6)
    return MakePlain(output)

def AESDecryption(key, encrypted_text):
    nb = len(key) // 8
    expanded_key = KeyExpansion(key, nb)
    state = MakeMatrix(encrypted_text, 4)
    state = AddRoundKey(state, expanded_key, nb + 6)
    state = InvShiftRows(state)
    state = SubBytes(state, Sbox_inv)
    for i in range(1, nb + 6):
        state = AddRoundKey(state, expanded_key, nb + 6-i)
        state = MixColumns(state,inv_np_matrix)
        state = InvShiftRows(state)
        state = SubBytes(state, Sbox_inv)
    state = AddRoundKey(state, expanded_key, 0)
    return MakePlain(state)



def HexToAscii(plain):
	output = []
	for i in range(len(plain)//2):
		output.append(chr(int(plain[i*2:i*2+2], 16)))
	output = ''.join(output)
	return output

def format_mac(mac):
	new_mac = mac.replace(":", "")
	return new_mac

def MakeIv(pkt):
	#print(pkt.getlayer(Dot11CCMP).PN5)
	iv = padded_hex(pkt.getlayer(Dot11CCMP).PN5, 2)[2:] + padded_hex(pkt.getlayer(Dot11CCMP).PN4, 2)[2:] + padded_hex(pkt.getlayer(Dot11CCMP).PN3, 2)[2:] + padded_hex(pkt.getlayer(Dot11CCMP).PN2, 2)[2:] + padded_hex(pkt.getlayer(Dot11CCMP).PN1, 2)[2:] + padded_hex(pkt.getlayer(Dot11CCMP).PN0, 2)[2:] 	
	iv = padded_hex(int(iv, 16), 12)
	return iv

def MakeNonce(pkt):
	PN = MakeIv(pkt)
	Smac = format_mac(pkt.addr2)
	priority = '00'
	nonce = str(priority) + str(Smac) + str(PN[2:])      
	return nonce

def AES_CTR(plain, key, nonce, iv, one = 1):
    n = len(plain)//32
    rest = len(plain)%32
    cipher = []
    flag = '01'
    ctrblk = flag + nonce + padded_hex(one, 4)[2:]
    
    for i in range(n):
        temp = padded_hex(int(plain[i*32: (i+1)*32], 16) ^ int(AESEncryption(key, ctrblk), 16), 32)
        cipher.append(temp[2:])
        ctrblk = padded_hex(int(ctrblk, 16) + 1, 32)[2:]
    if rest != 0:
        temp = padded_hex(int(plain[n * 32: (n + 1) * 32], 16) ^ int(AESEncryption(key, ctrblk), 16), 32)[2:2+rest]
        cipher.append(temp)
    return cipher
		

def Decrypt(ptk, packets):
	for nb in range(len(packets)):
		pkt = packets[nb]
		if pkt.getlayer(Dot11CCMP) is not None and pkt.getlayer(Dot11).addr1 == '08:be:ac:03:dc:2e':
			data = pkt.getlayer(Dot11CCMP).data.hex()
			iv = MakeIv(pkt)
			nonce = MakeNonce(pkt)
			decrypted_data = AES_CTR(data, ptk, nonce, iv)
			decrypted_data = ''.join(decrypted_data)
			print(HexToAscii(decrypted_data))

# Put the .cap file you want to decrypt here
packets = rdpcap("groep2-13.cap")

# Put the PTK derived from the create_PTK script here
ptk = '461d6eaecb54c8edd2466fc5b25a9cf3b18c01679e4f9516c29f14e28c52d31b9d0ddd2a442821573938333dd9efc89a68e3a4af7cee32e6380f5850ca005eb4'

Decrypt(ptk[64:64 + 32], packets)

