from arp import Arp
import optparse
import re
from checkValues import *
import socket


def get_inputs():
    import netifaces

    parser = optparse.OptionParser()
    parser.add_option('-s', '--source', help='Source IP address', dest='sip')
    parser.add_option('-m', '--mac', help='Source MAC address', dest='mac')
    parser.add_option('-i', '--iface', help='Interface name (required)', dest='iface')
    parser.add_option('-r', '--range', help='Range of IP to scan(e.g: 192.168.1.1/24)', dest='range')
    parser.add_option('-n', '--number', help='number of interface (default=1)', dest='n', default='1')
    
    options, args = parser.parse_args()

    if options.iface is None:
        print('[-] Interface name is required.')
        exit(1)
    elif not check_iface(options.iface):  # checks if there is such iface name
        print('[-] Wrong interface name.')
        exit(1)
    else:
        iface = options.iface

    if options.range is None:
        print('[-] Range of IPs to scan should be specified!')
        exit(1)
    elif not check_ip_range(options.range):   # checking the FORMAT of ip range. -> CORRECT: 192.168.0.0/24 , WRONG: 192.168.0/24, 
        print('[-] Wrong range of IPs.')
        exit(1)
    else:
        mask = options.range[options.range.find('/') + 1:]
        rip = options.range[:options.range.find('/')]

    if options.mac is None:
        mac = netifaces.ifaddresses(iface)[netifaces.AF_LINK][int(options.n) - 1]['addr']  # number of nic is given from input. default is 1
    else:  # source MAC address is specified
        if check_mac(options.mac):  
            mac = options.mac
        else:
            print('[-] Wrong MAC address')
            exit(1)

    if options.sip is None:
        sip = netifaces.ifaddresses(options.iface)[netifaces.AF_INET][int(options.n) - 1]['addr']  # number of nic is given from input. default is 1
    elif not check_ip(options.sip):
        print('[-] Wrong source of IPs.')
        exit(1)
    else:
        sip = options.sip

    return iface, mac, rip, mask, sip

def make_ip_integer(ip):
    # gets an ip like "192.168.1.1". it is 4 bytes or 32bit. returns an integer as its corresponding unsigned integer
    assert (re.match(r'(\d{1,3}\.){3}\d{1,3}', ip))
    numbers = tuple(reversed(tuple(map(int, ip.split('.')))))
    res = 0

    # ip can be thought of a number in base of 256. so to make it to a decimal integer we can use a loop
    # numbers of ip has been reversed.
    for i in range(len(numbers)):
        res += 256 ** i * numbers[i]
    
    return res

def make_integer_ip(ip_integer):
    # gets an integer. this integer is assumed to be 4 bytes. this function breaks this integer to 4 bytes each of seze 1B.
    # and makes an ip according to that
    assert(type(ip_integer) == int)
    
    res = ''
    for i in range(4):
        res += str(ip_integer // (256 ** (3 - i)))
        ip_integer = ip_integer % (256 ** (3 - i))
        res += '.'
    res = res[:-1]  # in the above for loop there will be an additional "." at the end of string.
    return res


def get_range(ip, mask):
    # ip is a string. -> "192.168.1.1". mask is an integer between 0, 32
    # gets the net id(ip) as a string and mask.
    # returns two integers. first one the start ip and second is last ip
    # each integer is the converted version of 32 bit ip. e.g: 192.168.1.1 -> 11000000.10100100.00000001.00000001 -> 3232235777
    assert (type(mask) == int and type(ip) == str)
    
    if mask > 32 or mask < 0:
        print('[-] Wrong mask!')
        exit(1)
    
    start = (make_ip_integer(ip) // (2 ** (32 - mask))) * (2 ** (32 - mask))
    end = start + 2 ** (32 - mask) - 1

    return start, end

def send_raw_packet(packet, iface):
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
    s.bind((iface, 0))
    s.sendall(packet)

if __name__ == '__main__':
    iface, mac, rip, mask, sip = get_inputs()
    start, end = get_range(rip, int(mask))

    # creating packet for first ip in the given range
    # later we use the same object for other ips with changing its dip then we call its make method
    arp = Arp(sip, make_integer_ip(start), mac)

    for ip in range(start, end + 1):
        arp.update_values({'dip': make_integer_ip(ip)})
        packet = arp.make()
        send_raw_packet(packet, iface)







