import struct
import re
from checkValues import *

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
        if not check_ip(sip) or not check_ip(dip):  # checking the format of IP address
            raise ValueError('Unsupported IP format!')
        if not check_mac(smac) or not check_mac(dmac):  # checking the format of mac address.
            raise ValueError('Unsupported MAC address format!')
        if type(opcode) != int:
            raise ValueError('Opcode should be an integer!')

        self.sip = sip
        self.dip = dip
        self.smac = smac
        self.dmac = dmac
        self.opcode = opcode

    @staticmethod
    def _make_mac_from_str(mac):
        # gets the mac address in form of string (e.g 08:a4:...) and returns a list of 6 integers representing each byte (e.g [8, 164,...])
        if not check_mac(mac):
            raise ValueError('Wrong MAC address')
        
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
        smac = Arp._make_mac_from_str(self.smac)
        dmac = Arp._make_mac_from_str(self.dmac)

        ether_header = struct.pack('!6B6BH', *dmac, *smac, Arp.__ether_type)
        arp_header = struct.pack('!2H2BH6B4B6B4B', Arp.__hw_type, Arp.__protocol_type, Arp.__hw_size, Arp.__protocol_size,
                                self.opcode, *smac, *tuple(map(int, self.sip.split('.'))), *dmac, *tuple(map(int, self.dip.split('.'))))
        self.packet = ether_header + arp_header
        return self.packet

    def update_values(self, d):
        # gets a dictionary. updates object values according to that dictionary. e.d -> {"sip": "192.168.1.150"}
        for item in d:
            if not item in self.__dict__:
                raise ValueError('Item not in object')
            if 'ip' in item and check_ip(d[item]):
                self.__dict__[item] = d[item]
            elif 'mac' in item and check_mac(d[item]):
                self.__dict__[item] = d[item]
            elif item == 'opcode':
                if type(d[item]) == int and d[item] < 256 * 256:
                    self.__dict__[item] = d[item]
