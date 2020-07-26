import socket
from packetExtraction import *

def make_protocol_str(headers, protocol_name):
    if headers is None:  # sometimes output of http heaer is None:
        return None
    res = ''
    res += '{:=^30}'.format(protocol_name) + '\n'
    for item in headers:
        res += f'{item} ==> {headers[item]}' + '\n'
    return res


def pcap_header(packet):
    # creates a pcket header for pcap file

    import datetime
    now = datetime.datetime.utcnow()
    
    return pack('<LLLL',
                now.second,
                now.microsecond,
                len(packet),
                len(packet)
    )
    

# a socket for packets recieved
conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

# making pcap file
pcap_file_name = 'file.pcap'
with open(pcap_file_name, 'wb') as f:
    # writing global header of pcap file
    f.write(pack('<LHHLLLL', 
            2712847316,  # magic number
            2,           # version major 
            4,           # version minor
            0,           # thiszone
            0,           # accuracy of time stamps
            262144,      # maxlength of captured pack
            1            # type of datalink
        )
    )


while True:
    raw_data, addr = conn.recvfrom(65535)

    headers = extract(raw_data)

    if headers == None:  # unsupported protocol
        continue

    string = ''
    string += make_protocol_str(headers['Ethernet'], 'Ethernet')

    if 'ARP' in headers:
        string += make_protocol_str(headers['ARP'], 'ARP')
        print(string + ('-' * 30) + '\n')

        with open(pcap_file_name, 'ab') as f:
            f.write(pcap_header(raw_data) + raw_data)  # storing packet in pcap file
        continue
    
    string += make_protocol_str(headers['IP'], 'IP')

    if 'ICMP' in headers:
        string += make_protocol_str(headers['ICMP'], 'ICMP')
        print(string + ('-' * 30) + '\n')

        with open(pcap_file_name, 'ab') as f:
            f.write(pcap_header(raw_data) + raw_data)  # storing packet in pcap file
        continue

    elif 'TCP' in headers:
        string += make_protocol_str(headers['TCP'], 'TCP')

    else:
        string += make_protocol_str(headers['UDP'], 'UDP')

    if 'HTTP' in headers:
        string += make_protocol_str(headers['HTTP'], 'HTTP')
    else:
        string += make_protocol_str(headers['DNS'], 'DNS')
    
    print(string)
    print('-' * 30, '\n')

    with open(pcap_file_name, 'ab') as f:
        f.write(pcap_header(raw_data) + raw_data)  # storing packet in pcap file

