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
    

# a socket for packets recieved
conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))


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
        continue
    
    string += make_protocol_str(headers['IP'], 'IP')

    if 'ICMP' in headers:
        string += make_protocol_str(headers['ICMP'], 'ICMP')
        print(string + ('-' * 30) + '\n')
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

