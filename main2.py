from packets import *
import socket


print('*' * 50)

def connect_scan():
    pass

def syn_scan():
    pass

def ack_scan():
    pass

def fin_scan():
    pass

def win_scan():
    pass


options = sys.argv[1:]

# dst is a string, scan is a function, ports is a tuple for range of ports and a list for single ports, delay is an int
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







