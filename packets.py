from struct import *
import re
import socket
import netifaces



class TCPpacket:
    """
        creates a tcp packet,
        
        params:
            dst(str): destination address. e.g -> "1.2.3.4" or "www.foo.com"
            dport(int): destination port
            iface(str): nome of the network intereface. e.g -> "eth0"
            sport(int): source port of packet. e.g -> 20
            flags(str): flags of tcp header. e.g -> SAP (SYN, ACK, PSH) 
    """

    def __init__(self, dst: str, dport: int, iface: str, sport: int, flags: str):
        self.dst = socket.gethostbyname(dst)  # translate name to ip. causes an error if name is not availabe

        # setting src ip address. causes an error if interface name is not valid. it's assumed that computer has
        # only one network card
        self.src = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
        self.sport = sport
        self.dport = dport
        self.flags_str = flags
        
        # calculates the value of flags in tcp header. e.g -> 'S': 2, 'A':16, 'SA': 18
        self._calculate_flags()

    @staticmethod
    def checksum(packet):
        # calculates checksum in one's complement methode

        l = len(packet)
        if l % 2 == 1:  # because 16 bits is two bytes, in order to sum up 2B by 2B, number of bytes should be even
            packet =  packet + b'\x00'
        
        res = 0
        numbers = unpack(f'!{l // 2}H', packet)
        for number in numbers:
            res += number
            if res >= 2 ** 16:  # carry bit
                res = res & 0xffff
                res += 1
        print(pack('!H', 0xffff - res))
        return 0xffff - res

    def _calculate_flags(self):
        all_flags = 'FSRPAUECN'  # the same order in tcp header from lowest to highes value

        # each flag adds a value to value of flags in tcp header. 
        # e.g: SYN bit is the second bit in flags. so syn bit will add 2 to flags value in tcp header
        flag_values = {all_flags[i]: 2 ** i for i in range(len(all_flags))}

        self.flags = 0
        for flag in self.flags_str:
            flag = flag.upper()
            if flag not in all_flags:
                raise ValueError(f'Flag "{flag}" is unknown')
            self.flags += flag_values[flag]


    def make(self):
        packet = pack(
            '!HHIIBBHHH',
            self.sport,  # src port
            self.dport,  # dst port
            0,           # seq number
            0,           # ack Number
            5 << 4,      # data offset and reserved bits
            self.flags,  # flags
            8192,        # window
            0,           # checksum (set to 0, calculate checksum, then change it)
            0            # urgent ptr
        )

        pseudo_header = pack(
            '!4s4sHH',
            pack('4B', *list(map(int, self.src.split('.')))),    # src address
            pack('4B', *list(map(int, self.dst.split('.')))),    # dst address
            socket.IPPROTO_TCP,                 # protocol number
            len(packet)                         # length
        )

        checksum = TCPpacket.checksum(pseudo_header + packet)

        packet = packet[:16] + pack('!H', checksum) + packet[18:]

        return packet
        
            