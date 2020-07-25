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

# supported protocols
layer_two_porotocols = {2048: ip, 2054: arp}
layer_three_protocols = {6: tcp, 17: udp, 1: icmp}
layer_four_protocols = {80: http, 53: dns}


while True:
    raw_data, addr = conn.recvfrom(65535)

    string = ''

    ether_headers, data = ether(raw_data)  

    if ether_headers['Ethertype'] not in layer_two_porotocols:
        continue


    string += make_protocol_str(ether_headers, 'Ethernet')

    layer_two_headers, data = layer_two_porotocols[ether_headers['Ethertype']](data)
    
    string += make_protocol_str(layer_two_headers, layer_two_porotocols[ether_headers['Ethertype']].__name__.upper())

    if data is None: # arp
        print('-' * 50)
        print(string)
        print('-' * 50)
        continue

    if layer_two_headers['Protocol number'] not in layer_three_protocols \
        or layer_two_headers['Source IP address'].startswith('127'):
        # first condition -> unsupported protocol
        # second condition -> loopback
        continue


    layer_three_headers, data = layer_three_protocols[layer_two_headers['Protocol number']](data)

    string += make_protocol_str(layer_three_headers, layer_three_protocols[layer_two_headers['Protocol number']].__name__.upper())

    if data is None:  # icmp
        print('-' * 50, string, '-' * 50, sep='\n')
        continue

    if layer_three_headers['Source port number'] in layer_four_protocols:
        layer_four_headers = layer_four_protocols[layer_three_headers['Source port number']](data)
        string += make_protocol_str(layer_four_headers, layer_four_protocols[layer_three_headers['Source port number']].__name__.upper())

    elif layer_three_headers['Destination port number'] in layer_four_protocols:
        layer_four_headers = layer_four_protocols[layer_three_headers['Destination port number']](data)
        string += make_protocol_str(layer_four_headers, layer_four_protocols[layer_three_headers['Destination port number']].__name__.upper())
    
    else:
        continue


    print('-' * 50, string, '-' * 50, sep='\n')



