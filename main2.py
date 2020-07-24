from scapy.all import *
import sys
import re

# options are in form of "dst=<destination> mode=<mode> ports=<ports> delay=<delay>"  (order not matters, case insensitive)
# mode specifies scan mode -> c (connect scan) , a (ACK scan) , s (SYN scan) , f (FIN scan) , w (window scan)
# ports -> <a>-<b> for range of ports and <a>,<b> for single ports
# delay -> time to wait for each response to a packet


def send_tcp_packet(dest, ports, flags, delay, retry):
    # gets dst address and ports(tuple for range or list for single ports or an int) and flags is a string like "SA" for syn/ack
    # sends tcp packet with specified arguments and returns every packet that receieved an answer.
    # it returns a list of tuples. each tuple has two elements, first is the request we sent and second is its reponse

    return sr(IP(dst=dest)/TCP(dport=ports, flags=flags), retry=retry, timeout=delay, verbose=0)


def connect_scan():
    pass

def ack_scan(dest, ports, delay, retry=1):
    print('Start scanning target with ACK scan'.center(50, '='))

    packets = send_tcp_packet(dest, ports, 'A', delay, retry)[0]
    # variable packets is a list of tuples of request and responses
    # it only contains requests which have responses. first element of each tuple in this list is request
    # and second one is reponse to first element request 

    print(f'---Found {len(packets)} responses!---')

    for packet in packets:
        if packet[1].haslayer(TCP) and packet[1].getlayer(TCP).flags == 0x4:
            print(f'Port number {packet[1].getlayer(TCP).sport} is unfiltered!')
    print('=' * 50)
    print()


def syn_scan(dest, ports, delay, retry=1):
    print('Start scanning target with SYN scan'.center(50, '='))

    packets = send_tcp_packet(dest, ports, 'S', delay, retry)[0]
    # variable packets is a list of tuples of request and responses
    # it only contains requests which have responses. first element of each tuple in this list is request
    # and second one is reponse to first element request 

    print(f'---Found {len(packets)} responses!---')

    for packet in packets:
        if packet[1].getlayer(TCP).flags == 0x12:   # SYN and ACK bit
            print(f'Port number {packet[1].getlayer(TCP).sport} sent an SYN/ACK packet!')

    print('=' * 50)
    print()


def fin_scan(dest, ports, delay, retry=1):
    print('Start scanning target with FIN scan'.center(50, '='))
    packets = send_tcp_packet(dest, ports, 'F', delay, retry)[1]
    # variable packet is a list of all unanswered packets.
    # When sending a fin packet if there was no answere maybe (or maybe not) that port is open

    print(f'---{len(packets)} unanswered requests!---')

    for packet in packets:
        print(f'Port number {packet.getlayer(TCP).dport} may be open!')
    
    print('=' * 50)
    print()

def win_scan():
    pass


options = sys.argv[1:]

# dst is a string, scan is a function, ports is a tuple for range of ports and a list for single ports, delay is an int
# default values
dst = '127.0.0.1'
scan = connect_scan
ports = (1, 100)
delay = 1

print('*' * 50)


for option in options:  # expected option format: "<sth>=<sth>"
    option = option.strip().split('=')
    option[0] = option[0].lower()
    if len(option) != 2 or option[0] not in ('mode', 'dst', 'ports', 'delay'):
        # there is no value. e.g -> mode , mode=
        # Or more than one values. e.g -> mode=cports=100 , ports=1-100=150
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

print('*' * 50)

scan(dst, ports, delay)








