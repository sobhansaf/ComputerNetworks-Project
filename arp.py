import struct
import re

class Arp:
    """
    Creates IPv4 ARP packets. The hardware size and protocol size is fixed to 6 and 4 respectivly.

    params:
        sip(string): source IPv4 address
        dip(string): destination IPv4 address
        smac(string): source MAC address (48 bits)
        dmac(string): destination MAC address (48 bits)
    """
    __arp_ether_type = 0x0806

    def __init__(self, sip, dip, smac, dmac='00:00:00:00:00:00'):
        if type(sip) != str or type(dip) != str or type(smac) != str or type(dmac) != str:  # checking all of the inputs are string
            raise TypeError('smac, dmac, sip and dip should be strings.')
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', sip) or not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', dip):  # checking the format of IP address
            raise ValueError('Unsupported IP format!')
        if not re.match(r'^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$', smac) or not re.match(r'^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$', dmac):  # checking the format of mac address.
            raise ValueError('Unsupported MAC address format!')
        
        sip = tuple(sip.split('.'))
        dip = tuple(dip.split('.'))
        smac = tuple(smac.split(':'))
        dmac = tuple(dmac.split(':'))

        # checking the values of ip. they shouldn't be more than 255 or less than 0
        for items in [sip_list, dip]:
            for item in items:
                if int(item) > 255 or int(item) < 0:
                    raise ValueError('Wrong IP address!')

        self.sip = sip
        self.dip = dip
        self.smac = smac
        self.dmac = dmac


