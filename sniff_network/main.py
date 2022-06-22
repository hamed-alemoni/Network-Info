from scapy.all import * 

# sniffing network till count number of packet
def sniffing(count=1000):

    network_packets = sniff(count=count)

    extract_info(network_packets)

    answer = input('Do you want to save the result as a .pcap file (y/n) ? ')

    if answer == 'y':
        save_info(network_packets)

def save_info(network_packets):

        filename = input('enter filename (choose a new filename otherwise program will override the previous file) : ')

        fullname = filename + '.pcap'
        
        wrpcap(fullname,network_packets)

# extract tcp, udp, ip header info 
def extract_info(network_packets):

    # save number of udp packets
    udp_counter = 0

    # save number of tcp packets
    tcp_counter = 0

    for packet in network_packets:

        # ------------------------------ ip

        ip_info = get_ip_information(packet)
        if ip_info is not None:
            print(ip_info)

        # ------------------------------ percent

        udp_counter = counting_udp_packet(packet, udp_counter)
        tcp_counter = counting_tcp_packet(packet, tcp_counter)

        # ------------------------------ tcp

        tcp_info = get_tcp_information(packet)
        if tcp_info is not None:
            print(tcp_info)

        # ------------------------------ udp 

        udp_info = get_udp_information(packet)
        if udp_info is not None:
            print(udp_info)

    # ---------------------------------fragmentation

    number_of_datagram = fragmentation_info(network_packets)
    total_packets = len(network_packets)

    print(f'Number of total packets : {total_packets}')
    print(calculate_percent(udp_counter, tcp_counter, total_packets))
    print(f'Number of fragment datagrams : {number_of_datagram}')
    


# extract ip header info and return it in property way
def get_ip_information(packet):
    try:
        info = f'(IP)Source IP : {packet[IP].src} Destination IP : {packet[IP].dst} TTL : {packet[IP].ttl} Protocol Number : {packet[IP].proto} Length : {packet[IP].len} Frag : {packet[IP].frag} ID : {packet[IP].id} Flag : {packet[IP].flags}'
    except IndexError:
        info = None
    
    return info

# number of fragmented datagrams
def fragmentation_info(network_packets):

    datagrams = set()

    for packet in network_packets:

        try:
            if packet[IP].flags not in ['DF', '']:
                datagrams.add(packet[IP].id)
        except IndexError:
            pass

    return len(datagrams)



def get_tcp_information(packet):
    try:
        info = f'(TCP)Source Port : {packet[TCP].sport} Destination Port : {packet[TCP].dport} Sequence Number : {packet[TCP].seq} ACK Number : {packet[TCP].ack} Flags : {packet[TCP].flags} Length Of Window : {packet[TCP].window} Checksum : {packet[TCP].chksum} Length : {len(packet[TCP])}'
    except IndexError:
        info = None

    return info


def get_udp_information(packet):

    try:
        info = f'(UDP)Source Port : {packet[UDP].sport} Destination Port : {packet[UDP].dport} Length : {packet[UDP].len} Checksum : {packet[UDP].chksum}'
    except IndexError:
        info = None

    return info

# calculate percent of received packets between UDP and TCP protocol
def calculate_percent(udp_counter, tcp_counter, total_packets):

    udp_percent = (udp_counter / total_packets) * 100
    tcp_percent = (tcp_counter / total_packets) * 100

    return f'UDP percent {udp_percent} TCP percent {tcp_percent}.'


# counting number of udp packets
def counting_udp_packet(packet, udp_counter):

    try:
        if packet[UDP]:
            udp_counter += 1

    except IndexError:
        pass
    
    return udp_counter

# counting number of tcp packets
def counting_tcp_packet(packet, tcp_counter):

    try:
        if packet[TCP]:
            tcp_counter += 1

    except IndexError:
        pass

    return tcp_counter


       
count = int(input('How many packets do you want to show ?  '))
sniffing(count)
