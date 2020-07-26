from struct import *

def isiterable(item):
    # checks if the item is iterbale
    try:
        iter(item)
    except TypeError:
        return False
    else:
        return True

def retrive_mac(mac):
    # takes a the mac address in bytes format. returns a string which represents the mac address.
    # e.g: \x02\x10... -> 02:10:...
    assert(type(mac) is bytes)
    
    # making a dict to use to map numbers in dec format to alphabetic or numeric in hex
    d = {i: f'{i}' for i in range(10)}
    for i in range(10, 16):
        d[i] = chr(ord('a') + i - 10)

    # making a list of converted hex to decimal values in string format. e.g \x02\x10... -> ["02", "10", ...]
    res = list()
    for item in mac:
        # item is 1 byte in size. break it into two decimal of 4 bits. e.g \x10 -> 160 -> "10"
        if item // 16 > 16:
            raise ValueError('There is a problem with input')
        res.append(str(d[item // 16]) + str(d[item % 16]))
    return ":".join(res)


def ether(data):
    # gets a packet as input and returns src MAC, dst MAC, protocl number
    
    assert (isiterable(data) and len(data) >= 4)

    # 1. src and dst mac
    # first 12 bytes of packet is src and dst add.
    dst_src_mac = unpack("!6s 6s", data[:12]) # tuple of size 2. they are dst and src mac respectively in bytes format.

    # making src and dst mac in human readable format. eg:\x10\x02 -> 10:02
    dst_mac = retrive_mac(dst_src_mac[0])
    src_mac = retrive_mac(dst_src_mac[1])

    # 2. protocol number
    proto_num = unpack('!H', data[12:14])[0]

    return ({"Destination MAC": dst_mac, "Source MAc": src_mac, "Ethertype": proto_num}, data[14:])


def ip(data):
    # teakes a segment and returns its header values and seperates its ip headers.
    ip_headers = list(unpack('!BBHHHBBHBBBBBBBB', data[:20])) # returns a tuple of different parts of ip header

    for i in range(8, len(ip_headers)):  # in order to join IPs with '.' they need to be in string format
        ip_headers[i] = str(ip_headers[i])

    ip_fields = {
        'Version': ip_headers[0] // 16, # first byte consists of version and header length each 4 bits
        'Header length': (ip_headers[0] % 16) * 4,
        'TOS': ip_headers[1],
        'Total length': ip_headers[2],
        'Identifier': ip_headers[3],
        'Don\'t fragment': ip_headers[4] // (2 ** 14), # first bit of flags is always 0(reserved). second bit.
        'More fragments': (ip_headers[4] // 13) & 1, # third bit of flags.
        'Fragment offset': ip_headers[4] % (2 ** 13), # last 13 bits of flags.
        'TTL': ip_headers[5],
        'Protocol number': ip_headers[6],
        'Header checksum': ip_headers[7],
        'Source IP address': '.'.join(ip_headers[8:12]), # merging bytes of src and dst ip
        'Destination IP address': '.'.join(ip_headers[12:])
    }

    header_len = ip_fields['Header length']
    if (header_len > 20):  # IP header has options
        try:
            ip_fields['Options'] = unpack(f'!{header_len - 20}s', data[20: header_len])
        except:
            # print('HERE')
            # print(header_len)
            # print(len(data))
            # print(len(data[20:header_len]))
            input()

    return(ip_fields, data[header_len:])


def icmp(data):
    # decapsulates ICMP packet
    type_, code, ch_sum = unpack('!BBH', data[:4])
    icmp_fields = {
        'Type': type_,
        'Code': code,
        'Checksum': ch_sum,
        'Rest of header': repr(data[4:]) 
    }
    
    return (icmp_fields, None)  # because other functions return 2 objects, in order to be match with them returning a none


def arp(data):
    # decapsulates ARP packets.
    hw_type, proto_type, hw_add_len, proto_add_len, opcode = unpack('!HHBBH', data[:8])
    current = 8  # a pointer to byte number of data we are cuurently reading
    
    src_hw = unpack(f'!{hw_add_len}s', data[current : current + hw_add_len])[0]  # returns its src hw address in bytes format
    current += hw_add_len
    
    src_proto_add = unpack(f'!{proto_add_len}B', data[current : current + proto_add_len]) # returns a tupel of ip. e.g(192, 168, ...)
    current += proto_add_len


    dst_hw = unpack(f'!{hw_add_len}s', data[current : current + hw_add_len])[0]
    current += hw_add_len
    
    dst_proto_add = unpack(f'!{proto_add_len}B', data[current : current + proto_add_len])
    current += proto_add_len

    arp_fields = {
        'Hardware type': hw_type,
        'Protocol type': proto_type,
        'Hardware address length': hw_add_len,
        'Protocol address length': proto_add_len,
        'Opcode': opcode,
        'Source hardware address': retrive_mac(src_hw),
        'Source protocol address': '.'.join(map(str, src_proto_add)),
        'Destination hardware address': retrive_mac(dst_hw),
        'Destination protocol address': '.'.join(map(str, dst_proto_add))
    }

    if current < len(data):
        arp_fields['Data'] = repr(data[current])

    return (arp_fields, None)  # because other functions return 2 objects, in order to be match with them returning a none


def udp(data):
    # decapsulation of UDP packets
    src_port, dst_port, length, checksum = unpack('!4H',data[:8])
    return ({
        'Source port number': src_port,
        'Destination port number': dst_port,
        'Length': length,
        'CheckSum': checksum
    }, data[8:])

def tcp(data):
    # decapsulates TCP packets
    src_port, dst_port, seq_num, ack_num, header_len, flags, win_size, checksum, urg_ptr = unpack('!HHIIBBHHH', data[:20])
    current = 20  # a pointer to byte number we are reading
    
    # header length is from bit number 97 to 100 in tcp header but in the line above we got 1 byte in header length (97-104)
    # bit number 104 is nounce flag and bits 101, 102, 103 are reserved and are set to 0
    nounce = header_len % 2
    header_len = (header_len & (15 * 16)) // 16   # taking off those 4 bits
    header_len *= 4  # header length in tcp should be multiplied by 4

    tcp_fields = {
        'Source port number': src_port,
        'Destination port number': dst_port,
        'Sequence number': seq_num,
        'Acknowledgement number': ack_num,
        'Header length': header_len,
        'Nounce': nounce
    }

    flag_names = ('CWR', 'ECE', 'URG', 'ACK', 'PSH', 'RST', 'SYN', 'FIN')
    for item in reversed(flag_names):  # because each time we are getting the last bit names should go from last to first
        tcp_fields[item] = flags % 2
        flags = flags // 2

    tcp_fields.update((('Window size', win_size), ('Checksum', checksum), ('Urgent pointer', urg_ptr)))

    if header_len > 20:  # tcp packet has some optoins
        tcp_fields['Options'] = repr(data[current: header_len])
        current = header_len
    
    return (tcp_fields, data[current:])


def dns(data):
    # decapsulates dns packets
    
    def get_dns_name(data, start):
        # gets dns packet(bytes) and the number of the first bit of name and returns the name
        tmp = data[start]
        direct = True  # whether it is a pointer to name or not
        
        current = start

        if tmp // 64 == 3:  # a pointer to a name
            current = 256 * (data[start] % 64) + data[start + 1]
            direct = False
        
        res = str()
        while data[current] != 0:
            res += chr(data[current])
            current += 1
        
        return (res, current) if direct else (res, start + 1)

    def extract_record_dns(data, current, types):  
        # is used to extract answer and authority and additional records. return new and current position in bytes obj
        name, current = get_dns_name(data, current)
        current += 1
        new = {
            'Name': name,
            'Type': unpack('!H', data[current : current + 2])[0],
            'Class': unpack('!H', data[current + 2 : current + 4])[0],
            'TTL': unpack('!I', data[current + 4 : current + 8])[0],
            'Data length': unpack('!H', data[current + 8: current + 10])[0],
        }
        current += 10

        new['Type'] = types.get(new['Type'], new['Type']) # specify some common types
    
        # example for below code: CNAME:dns.google.com
        new[new['Type']] = unpack(f'!{new["Data length"]}s',
                                                data[current : current + new['Data length']])[0]

        current += new['Data length']

        if new['Type'] == 'A':
            new['A'] = '.'.join(list(map(lambda x: str(x), new['A'])))  # human readable IPv4

        return new, current

    
    
    id_, flags, num_of_quest, num_of_ans, num_of_auth, num_of_add = unpack('!6H', data[:12])
    current = 12  # a ptr to current number of byte
    
    queries = list()
    answers = list()
    authorities = list()
    additionals = list()

    types = {1: 'A', 2: 'NS', 5: 'CNAME', 15: 'MX'}

    for i in range(num_of_quest):  # information of each query
        name, current = get_dns_name(data, current)
        current += 1
        queries.append({
            'Name': name,
            'Type': unpack('!H', data[current : current + 2])[0],
            'Class': unpack('!H', data[current + 2 : current + 4])[0]
        })
        current += 4
        queries[-1]['Type'] = types.get(queries[-1]['Type'], queries[-1]['Type'])

    
    for i in range(num_of_ans):  # answers
        new_answer, current = extract_record_dns(data, current, types)
        answers.append(new_answer)


    for i in range(num_of_auth):    # authority
        new_authority, current = extract_record_dns(data, current, types)
        authorities.append(new_authority)


    for i in range(num_of_add):
        new_additional, current = extract_record_dns(data, current, types)
        additionals.append(new_additional)
    
    #id_, flags, num_of_quest, num_of_ans, num_of_auth, num_of_add

    dns_info = {
        'ID': id_,
        'Response': flags // (2 ** 15),   # first bit of flags
        'Opcode': (flags // (2 ** 11)) & 15,  # bit number 2 to 5
        'Trunced': (flags // (2 ** 9)) & 1,  # bit number 7
        'Recursive': (flags // (2 ** 8)) & 1,  # bit number 8
        'Non-authenticated data': (flags // (2 ** 4)) & 1, # bit number 12
    }

    if dns_info['Response']:  # adding flags which are related to response dns
        dns_info.update({
            'Authoritive DNS answer': (flags // (2 ** 10)) & 1,   # bit number 6
            'Recursion available': (flags // (2 ** 7)) & 1,   # bit number 9
            'Ans/Auth was authenticated': (flags // (2 ** 5)) &1,  # bit number 11
            'Status code': flags & 15   # bit number 13-16
        })
    
    dns_info.update({
        'Questions': num_of_quest,
        'Answer RR': num_of_ans,
        'Authority RR': num_of_auth,
        'Additional RR': num_of_add,
        'Queries': queries,
        'Answers': answers,
        'Authorities': authorities,
        'Additionals': additionals
    })

    return dns_info


def http(data):
    # decapsulating http request and response
    http = data.split(b'\r\n\r\n')
    if len(http) == 2:  # There is both header and message
        header, message = http
        header = list(map(lambda x: x.decode(), header.split(b'\r\n')))
        # header = header.split(b'\r\n')

    elif len(http) == 1:  # There is no data or juts headers
        header = http[0]
        message = ''
        try:
            header = list(map(lambda x: x.decode(), header.split(b'\r\n')))
        except UnicodeDecodeError:  # html code was broken into some parts. it's the continue of one of them
            message = http[0]
            header = ''
        # header = header.split(b'\r\n')
    else:
        return None

    return {'Header': header, 'Message': message}


# protocol numbers and ports supported
ip_prot, arp_prot = 2048, 2054
tcp_prot, udp_prot, icmp_prot = 6, 17, 1
http_prot, dns_prot = 80, 53


# mapping supported protocols to their related functions
layer_two_porotocols = {ip_prot: ip, arp_prot: arp}
layer_three_protocols = {tcp_prot: tcp, udp_prot: udp, icmp_prot: icmp}
layer_four_protocols = {http_prot: http, dns_prot: dns}


def extract(packet, start='ETH'):
    # gets the packet and returns all of headers in different layers

    # start specifies in which layer to start extracting
    # it is useful when working with sockets. because socket receive functions don't have ethernet headers
    # and in order to extract their headers we have to start from ip layer

    headers = dict()  # a mapping from protocol names to its headers
    status = False  # indicates that can packet be extracted. according to start parameter

    if start.upper() == 'ETH':
        status = True

    if status:
        head, data = ether(packet)
        headers['Ethernet'] = head

        ethtype = head['Ethertype']

        if ethtype not in layer_two_porotocols:  # unsupported protocol
            return
        
    
    if start.upper() == 'IP':
        ethtype = ip_prot
        data = packet
        status = True

    if status: 
        head, data = layer_two_porotocols[ethtype](data)
    
        if data is None: # arp
            return {
                'Ethernet': headers['Ethernet'],
                'ARP': head
            }   
        
        headers['IP'] = head  # only supported arp and ip in this layer. it is not arp because it has been checked. so it's ip

        if head['Protocol number'] not in layer_three_protocols \
            or head['Source IP address'].startswith('127'):
            # first condition -> unsupported protocol
            # second condition -> loopback
            return

        if head['Protocol number'] == tcp_prot:
            name = 'TCP'
        elif head['Protocol number'] == udp_prot:
            name = 'UDP'
        else:
            name = 'ICMP'

        head, data = layer_three_protocols[head['Protocol number']](data)

        if data is None:  # icmp
            return {
                'Ethernet': headers['Ethernet'],
                'IP': headers['IP'],
                'ICMP': head
            }

        headers[name] = head
    
    
    if dns_prot in (head['Source port number'], head['Destination port number']):  # storing the name of protocol in order to map this name to its related header in upper layer
        name = 'DNS'
    elif http_prot in (head['Source port number'], head['Destination port number']):
        name = 'HTTP'
    else:
        return  # it's not dns and http. -> unsupported protocol
    

    if head['Source port number'] in layer_four_protocols:
        head = layer_four_protocols[head['Source port number']](data)

    elif head['Destination port number'] in layer_four_protocols:
        head = layer_four_protocols[head['Destination port number']](data)

    headers[name] = head
    
    return headers
