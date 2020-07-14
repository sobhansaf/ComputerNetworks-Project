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



def retrive_mac(mac):
    # takes a the mac address in bytes format. returns a string which represents the mac address.
    # e.g: \x02\x10... -> 02:10:...
    assert(type(mac) is bytes)
    
    # making a dict to use to map numbers in dec format to alphabetic or numeric in hex
    d = {i: f'{i}' for i in range(10)}
    for i in range(10, 16):
        d[i] = chr(ord('a') + i - 10)

    # making a list of converted hex to decimal values in string format. e.g \x02\x10... -> ["02", "10", ...]
    res = list()
    for item in mac:
        # item is 1 byte in size. break it into two decimal of 4 bits. e.g \x10 -> 160 -> "10"
        if item // 16 > 16:
            raise ValueError('There is a problem with input')
        res.append(str(d[item // 16]) + str(d[item % 16]))
    return ":".join(res)


def ether(data):
    # gets a packet as input and returns src MAC, dst MAC, protocl number
    
    assert (isiterable(data) and len(data) >= 4)

    # 1. src and dst mac
    # first 12 bytes of packet is src and dst add.
    dst_src_mac = unpack("!6s 6s", data[:12]) # tuple of size 2. they are dst and src mac respectively in bytes format.

    # making src and dst mac in human readable format. eg:\x10\x02 -> 10:02
    dst_mac = retrive_mac(dst_src_mac[0])
    src_mac = retrive_mac(dst_src_mac[1])

    # 2. protocol number
    proto_num = unpack('!H', data[12:14])[0]

    return ({"Destination MAC": dst_mac, "Source MAc": src_mac, "Ethertype": proto_num}, data[14:])



# a socket for packets recieved
conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

raw_data, addr = conn.recvfrom(65535)


ether_headers, data = ether(raw_data)

print(ether_headers, sep="\n")

