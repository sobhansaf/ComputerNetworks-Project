import socket
from struct import *



def isiterable(item):
    # checks if the item is iterbale
    try:
        iter(item)
    except TypeError:
        return False
    else:
        return True



def retrive_mac(arr):
    # takes an array of size 6 each 1B values. breaking each one into two 4 bits
    # e.g: 160 (0001 1010) -> 1a
    assert(isiterable(arr) and len(arr) == 6)
    
    # making a dictionary of numbers to their hex -> {1:'1', ... , 15:'f'}
    d = {i: f'{i}' for i in range(10)}
    for i in range(10, 16):
        d[i] = chr(ord('a') + i - 10)
    
    res = str()
    for item in arr:
        if item > 255:
            raise ValueError('Items of arr should be at most 1 Byte')
        res += f'{d[item // 16]}{d[item % 16]}:'
    
    # res has an additional ":" at end
    return res[:-1]
    


def ether(data):
    # gets a packet as input and returns src MAC, dst MAC, protocl number
    
    # 1. src and dst mac
    # a list of length 12 (6 for src and 6 for dst). each item is a 1B of mac (should be 4 bits to display)
    # eg -> mac 1a:2b:... => [160, 352, ...]
    dst_src_mac = unpack("!6B 6B", data[:12])
    print(dst_src_mac)
    input('Here')
    assert(isiterable(dst_src_mac) and len(dst_src_mac) == 12)

    dst_mac = retrive_mac(dst_src_mac[:6])
    src_mac = retrive_mac(dst_src_mac[6:])

    # TODO : 2. protocol number

    return (dst_mac, src_mac, data[14:])



# a socket for packets recieved
conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
raw_data, addr = conn.recvfrom(65535)

dst, src, data = ether(raw_data)
print(src, dst, sep="\n")

