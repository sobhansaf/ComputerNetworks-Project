import re

def check_ip(ip):
    # gets an IP and validates it.
    if type(ip) != str or not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', ip):
        return False

    numbers = ip.split('.')
    for num in numbers:
        if int(num) > 255:
            return False
    return True

def check_mac(mac):
    # gets a string as MAC address. validates it.
    if type(mac) != str or not re.match(r'^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$'):
        return False

def check_ip_range(rip):
    # gets an IP range (i.e it has a '/' for mask) and validates it
    if type(rip) != str or not re.match(r'^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$', rip):
        return False
    
    ip = rip[:rip.find('/')]
    return check_ip(ip)



