import socket
from struct import *

# a socket for packets recieved
conn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
raw_data, addr = conn.recvfrom(65535)

