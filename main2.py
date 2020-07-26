from packets import *
import socket
import time
from packetExtraction import *
import sys
from timeit import default_timer as timer

def extract_packet_from_IP(packet):
    # gets a TCP packet that starts from IP layer (Ether headers seperated) and returns headers of tcp and ip layer
    headers = dict()
    head, data = ip(packet)
    if head['Protocol number'] != tcp_prot:  # it's not a tcp packet
        return
    headers['IP'] = head
    head, data = tcp(data)
    headers['TCP'] = head

    return headers


def connect_scan():
    pass

def syn_scan(dst, ports, delay, iface, sport=20):
    if type(ports) == tuple:
        ports = [i for i in range(min(ports[0], ports[1]), max(ports[0], ports[1]))]

    print('*' * 30)
    print('Starting SYN scan'.center(30))

    dst = socket.gethostbyname(dst)

    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    open_ports = list()

    for port in ports:
        status = True
        packet_to_send = TCPpacket(dst, port, iface, sport, 'S').make()
        s.sendto(packet_to_send, (dst, 0))
        s.settimeout(delay)

        # in order to keep track of how much to wait for an appropriate answer, start and end is used 
        # between sending a packet and recieving an answer. if time interval got bigger than delay parameter
        # then stops waiting for the answer and sends the next packet
        start = time.time() 
        end = time.time()

        while end - start < delay + 0.1:  # 0.1 is added because of additional calculations (of course 0.1 is also too much for calculations!)
            try:
                packet, addr = s.recvfrom(1024)
            except socket.timeout:
                break
            headers = extract_packet_from_IP(packet)
            end = time.time()
            if headers is None:
                continue
            if addr[0] == dst and headers['TCP']['SYN'] == 1 and headers['TCP']['ACK'] == 1:
                open_ports.append(port)
                status = False
                print('!', end='', flush=True)
                break

        if status:
            print('.', end='', flush=True)

    print('\n')

    print('Port numbers', *open_ports, 'sent back SYN/ACK tcp packets!\n\n')
    print('*' * 30)
                

def ack_scan():
    pass

def fin_scan():
    pass

def win_scan():
    pass


options = sys.argv[1:]

# dst is a string, scan is a function, ports is a tuple for range of ports and a list for single ports, delay is an int
# iface is a string

# default values
dst = '127.0.0.1'
scan = connect_scan
ports = (1, 100)
delay = 1
iface = None


for option in options:  # expected option format: "<sth>=<sth>"
    option = option.strip().split('=')
    option[0] = option[0].lower()
    if len(option) != 2 or option[0] not in ('mode', 'dst', 'ports', 'delay', 'iface'):
        # there is no value. e.g -> mode , mode=
        # Or more than one values. e.g -> mode=cports=100 , ports=1-100=150
        # unknown arguments -> tcpport=80
        print(f'Unknown "{"=".join(option)}"')
        continue

    option[1] = option[1].lower()

    if option[0] == 'mode':
        if option[1] == 'c':
            scan = connect_scan
            print('---Connect scan---')
        elif option[1] == 's':
            scan = syn_scan
            print('---SYN scan---')
        elif option[1] == 'f':
            scan = fin_scan
            print('---FIN scan---')
        elif option[1] == 'w':
            scan = win_scan
            print('---Window scan---')
        elif option[1] == 'a':
            scan = ack_scan
            print('---ACK scan---')
        else:
            print(f'Scan mode not found: {option[1]}')
    elif option[0] == 'ports':
        if re.match(r'^(\d+,)*\d*$', option[1]):  # single port. e.g "15,17,10,4"
            # in single ports -> ports are in a list
            ports = list(map(int, option[1].split(',')))
            print('---Ports:', ports, '---')
        elif re.match(r'^\d+\-\d+$', option[1]):  # a range of ports. e.g "100-150" or maybe "30-10"
            # range of ports -> start and end port are first and second item of a tuple
            first, second = tuple(map(int, option[1].split('-')))
            ports = (min(first, second), max(first, second))
            print('---Range of ports:', ports, '---')
        else:
            print(f'Wrong ports input: "{option[1]}"')
    elif option[0] == 'delay':
        if re.match(r'^\d+\.?\d*$', option[1]):
            delay = float(option[1])
            print(f'---Delay: {delay}---')
        else:
            print(f'Wrong delay input: {option[1]}')
    elif option[0] == 'dst':
        dst = option[1]
        print(f'---Target: {dst}---')
    elif option[0] == 'iface':
        iface = option[1]
        print(f'---interface set to {iface}---')

if iface is None:
    raise AttributeError('Interface name must be specified')


scan(dst, ports, delay, iface)




