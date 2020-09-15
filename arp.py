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

    @staticmethod
    def _make_mac_from_str(mac):
        # gets the mac address in form of string (e.g 08:a4:...) and returns a list of 6 integers representing each byte (e.g [8, 164,...])
        assert(re.match(r'^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$', mac))
        
        # mapping letters to their corresponding numbers. e.g : 'a': 10 , 'f': 15
        d = {str(i): i for i in range(10)}
        d.update({chr(ord('a') + i): 10 + i for i in range(7)})

        mac = mac.split(':')
        res = list()
        for item in mac:
            # it has been checked in the assertion that each item has exatcly 2 letters and each letter is either number or a-f or A-F
            res.append(d[item[0].lower()] * 16 + d[item[1].lower()])
        return res



