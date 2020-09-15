from arp import Arp
import optparse

def get_inputs():
    import netifaces
    import re

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

def get_range(ip, mask):
    # gets the net id(ip) as a string and mask.
    # returns two integers. first one the start ip and second is last ip
    # each integer is the converted version of 32 bit ip. e.g
    pass

get_inputs()


