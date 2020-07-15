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


def ip(data):
    # teakes a segment and returns its header values and seperates its ip headers.
    ip_headers = list(unpack('!BBHHHBBHBBBBBBBB', data[:20])) # returns a tuple of different parts of ip header

    for i in range(8, len(ip_headers)):  # in order to join IPs with '.' they need to be in string format
        ip_headers[i] = str(ip_headers[i])

    ip_fields = {
        'Version': ip_headers[0] // 16, # first byte consists of version and header length each 4 bits
        'Header length': (ip_headers[0] % 16) * 4,
        'TOS': ip_headers[1],
        'Total length': ip_headers[2],
        'Identifier': ip_headers[3],
        'Don\'t fragment': ip_headers[4] // (2 ** 14), # first bit of flags is always 0(reserved). second bit.
        'More fragments': (ip_headers[4] // 13) & 1, # third bit of flags.
        'Fragment offset': ip_headers[4] % (2 ** 13), # last 13 bits of flags.
        'TTL': ip_headers[5],
        'Protocol number': ip_headers[6],
        'Header checksum': ip_headers[7],
        'Source IP address': '.'.join(ip_headers[8:12]), # merging bytes of src and dst ip
        'Destination IP address': '.'.join(ip_headers[12:])
    }

    header_len = ip_fields['Header length']
    if (header_len > 20):  # IP header has options
        try:
            ip_fields['Options'] = unpack(f'!{header_len - 20}s', data[20: header_len])
        except:
            print(header_len)
            print(len(data))
            print(len(data[20:header_len]))
            input()

    return(ip_fields, data[header_len:])


def icmp(data):
    # decapsulates ICMP packet
    type_, code, ch_sum = unpack('!BBH', data[:4])
    icmp_fields = {
        'Type': type_,
        'Code': code,
        'Checksum': ch_sum,
        'Rest of header': repr(data[4:]) 
    }
    
    return icmp_fields


def arp(data):
    # decapsulates ARP packets.
    hw_type, proto_type, hw_add_len, proto_add_len, opcode = unpack('!HHBBH', data[:8])
    current = 8  # a pointer to byte number of data we are cuurently reading
    
    src_hw = unpack(f'!{hw_add_len}s', data[current : current + hw_add_len])[0]  # returns its src hw address in bytes format
    current += hw_add_len
    
    src_proto_add = unpack(f'!{proto_add_len}B', data[current : current + proto_add_len]) # returns a tupel of ip. e.g(192, 168, ...)
    current += proto_add_len


    dst_hw = unpack(f'!{hw_add_len}s', data[current : current + hw_add_len])[0]
    current += hw_add_len
    
    dst_proto_add = unpack(f'!{proto_add_len}B', data[current : current + proto_add_len])
    current += proto_add_len

    arp_fields = {
        'Hardware type': hw_type,
        'Protocol type': proto_type,
        'Hardware address length': hw_add_len,
        'Protocol address length': proto_add_len,
        'Opcode': opcode,
        'Source hardware address': retrive_mac(src_hw),
        'Source protocol address': '.'.join(map(str, src_proto_add)),
        'Destination hardware address': retrive_mac(dst_hw),
        'Destination protocol address': '.'.join(map(str, dst_proto_add))
    }

    if current < len(data):
        arp_fields['Data'] = repr(data[current])

    return arp_fields



# a socket for packets recieved
conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

while True:
    raw_data, addr = conn.recvfrom(65535)

    ether_headers, data = ether(raw_data)

    if ether_headers['Ethertype'] == 2054: # arp
        arp_head = arp(data)
        print(arp_head)


