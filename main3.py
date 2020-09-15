from arp import Arp
import optparse
import re

def get_inputs():
    import netifaces

    parser = optparse.OptionParser()
    parser.add_option('-m', '--mac', help='Source MAC address (one of source mac and interface name is required. mac has more priority)', dest='mac')
    parser.add_option('-i', '--iface', help='Interface name (one of source mac and interface name is required. mac has more priority)', dest='iface')
    parser.add_option('-r', '--range', help='Range of IP to scan(e.g: 192.168.1.1/24)', dest='range')
    
    options, args = parser.parse_args()
    if options.range is None:  # checking the FORMAT of ip range. -> CORRECT: 192.168.0.0/24 , WRONG: 192.168.0/24, 
        print('[-] Range of IPs to scan should be specified!')
    elif not re.match(r'(\d{1,3}\.){3}\d{1,3}\/\d{1,2}', options.range):
        print('[-] Wrong range of IPs.')
        exit(1)
    else:
        mask = options.range[options.range.find('/') + 1:]
        ip = options.range[:options.range.find('/')]
    if options.mac is None and options.iface is None:
        print('[-] At lease one of mac address or interface name should be specified')
        exit(1)
    elif options.mac is None:
        mac = netifaces.ifaddresses(options.iface)[netifaces.AF_LINK][0]['addr']

    return mac, ip, mask

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




print(make_integer_ip(3232235777))