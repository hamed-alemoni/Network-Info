from scapy.all import * 
import sys
answer = input(''' 
1. trace1 5,276 KB
2. trace2 7,524 KB
3. trace3 17,958 KB
4. Open another file
which file do you want to read :''')

if 0 < int(answer) < 4:

    network_packets = rdpcap(f'trace{int(answer)}.pcap')

elif int(answer) == 4:
    try:
        # get filename and open it if it's exist
        filename = input('enter filename : ') 

        fullname = filename + '.pcap'

        network_packets = rdpcap(fullname)

    except :
        # it doesn't exist
        print(f'No such file {fullname}')
        sys.exit(1)
        exit(1)



# extract tcp, udp, ip header info 
def extract_info():

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

    number_of_datagram = fragmentation_info()

    print(calculate_percent(udp_counter, tcp_counter, total_packets))
    print(f'Number of fragment datagrams : {number_of_datagram}')
    total_packets = len(network_packets)
    print(f'Number of total packets : {total_packets}')
    


# extract ip header info and return it in property way
def get_ip_information(packet):
    try:
        info = f'(IP)Source IP : {packet[IP].src} Destination IP : {packet[IP].dst} TTL : {packet[IP].ttl} Protocol Number : {packet[IP].proto} Length : {packet[IP].len} Frag : {packet[IP].frag} ID : {packet[IP].id} Flag : {packet[IP].flags}'
    except IndexError:
        info = None
    
    return info

# number of fragmented datagrams
def fragmentation_info():

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




extract_info()
