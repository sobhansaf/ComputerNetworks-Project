import struct
import re
import socket

class Arp:
    """
    Creates IPv4 ARP packets. The hardware size and protocol size is fixed to 6 and 4 respectivly.

    params:
        sip(string): source IPv4 address
        dip(string): destination IPv4 address
        smac(string): source MAC address (48 bits)
        dmac(string): destination MAC address (48 bits)
    """
    __ether_type = 2054  # arp (Ethernet header)
    __hw_type = 1  # Ethernet (arp header)
    __protocol_type = 2048  # IPv4 (arp header)
    __hw_size = 6  # mac size (arp header)
    __protocol_size = 4  # ip size (arp header)

    def __init__(self, sip, dip, smac, dmac='ff:ff:ff:ff:ff:ff', opcode=1):
        if type(sip) != str or type(dip) != str or type(smac) != str or type(dmac) != str:  # checking all of the inputs are string
            raise TypeError('smac, dmac, sip and dip should be strings.')
        if not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', sip) or not re.match(r'^(\d{1,3}\.){3}\d{1,3}$', dip):  # checking the format of IP address
            raise ValueError('Unsupported IP format!')
        if not re.match(r'^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$', smac) or not re.match(r'^([a-fA-F0-9]{2}:){5}[a-fA-F0-9]{2}$', dmac):  # checking the format of mac address.
            raise ValueError('Unsupported MAC address format!')
        if type(opcode) != int:
            raise ValueError('Opcode should be an integer!')
        
        sip = tuple(sip.split('.'))
        dip = tuple(dip.split('.'))
        smac = tuple(smac.split(':'))
        dmac = tuple(dmac.split(':'))

        # checking the values of ip. they shouldn't be more than 255 or less than 0
        for items in [sip, dip]:
            for item in items:
                if int(item) > 255 or int(item) < 0:
                    raise ValueError('Wrong IP address!')

        self.sip = sip
        self.dip = dip
        self.smac = smac
        self.dmac = dmac
        self.opcode = opcode

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

    def make(self):
        # creates a packet of bytes format
        smac = Arp._make_mac_from_str(':'.join(self.smac))
        dmac = Arp._make_mac_from_str(':'.join(self.dmac))

        ether_header = struct.pack('!6B6BH', *dmac, *smac, Arp.__ether_type)
        arp_header = struct.pack('!2H2BH6B4B6B4B', Arp.__hw_type, Arp.__protocol_type, Arp.__hw_size, Arp.__protocol_size,
                                self.opcode, *smac, *tuple(map(int, self.sip)), *dmac, *tuple(map(int, self.dip)))
        self.packet = ether_header + arp_header
        return self.packet

