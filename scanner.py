from scapy.all import sniff

VALID_FILTERS = ['arp', 'tcp', 'udp', 'ip']

def parse_ethernet_header(hex_data):
    # Ethernet header is the first 14 bytes (28 hex characters)
    dest_mac = hex_data[0:12]
    source_mac = hex_data[12:24]
    ether_type = hex_data[24:28]
    
    # Convert hex MAC addresses to human-readable format
    dest_mac_readable = ':'.join(dest_mac[i:i+2] for i in range(0, 12, 2))
    source_mac_readable = ':'.join(source_mac[i:i+2] for i in range(0, 12, 2))
    
    print(f"Destination MAC: {dest_mac_readable}")
    print(f"Source MAC: {source_mac_readable}")
    print(f"EtherType: {ether_type}")

# Function to handle each captured packet
def packet_callback(packet, capture_filter):
    # Convert the raw packet to hex format
    raw_data = bytes(packet)
    hex_data = raw_data.hex()
    
    # Process the Ethernet header
    print(f"Captured Packet (Hex): {hex_data}")
    parse_ethernet_header(hex_data)

    ether_type = hex_data[24:28]
    
    if ether_type == '0806':
        print("This is an ARP packet.")
        parse_arp_packet(hex_data)
    elif ether_type == '0800':
        print("This is an IPv4 packet.")
        
        # If the filter is 'ip', call the function to display only the IPv4 header fields
        if capture_filter == 'ip':
            parse_ipv4_header_only(hex_data)
        else:
            # Continue parsing normally for TCP/UDP if the filter is not just 'ip'
            parse_ipv4_packet(hex_data)
            protocol = hex_data[46:48]
            if protocol == '06':
                print("This is a TCP packet.")
                parse_tcp_packet(hex_data)
            elif protocol == '11':
                print("This is a UDP packet.")
                parse_udp_packet(hex_data)

# Capture packets on a specified interface using a custom filter
def capture_packets(interface, capture_filter, packet_count):
    # Check if the capture filter is valid
    if capture_filter not in VALID_FILTERS:
        print(f"Error: '{capture_filter}' is not a valid filter. Choose from: {', '.join(VALID_FILTERS)}.")
        return

    # Define the callback with capture_filter
    def packet_callback_with_filter(packet):
        packet_callback(packet, capture_filter)

    # Start packet capture with error handling for invalid interfaces
    try:
        print(f"Starting packet capture on {interface} with filter: {capture_filter}")
        sniff(iface=interface, filter=capture_filter, prn=packet_callback_with_filter, count=packet_count)
    except OSError:
        print(f"Error: '{interface}' is not a valid network interface. Please check the interface name.")
    except Exception as e:
        print(f"An error occurred during packet capture: {e}")


def parse_arp_packet(hex_data):

    arp_header = hex_data[28:]
 
    hardware_type = arp_header[0:4]
    protocol_type = arp_header[4:8]
    hardware_size = arp_header[8:10]
    protocol_size = arp_header[10:12]
    opcode = arp_header[12:16]
    sender_mac = arp_header[16:28]
    sender_ip = arp_header[28:36]
    target_mac = arp_header[36:48]
    target_ip = arp_header[48:56] 

    # Convert sender and target IPs from hex to dotted decimal format
    sender_ip_readable = '.'.join(str(int(sender_ip[i:i+2], 16)) for i in range(0, len(sender_ip), 2))
    target_ip_readable = '.'.join(str(int(target_ip[i:i+2], 16)) for i in range(0, len(target_ip), 2))
   

    print(f"Hardware Type: {hardware_type}")
    print(f"Protocol Type: {protocol_type}")
    print(f"Hardware Size: {hardware_size}")
    print(f"Protocol Size: {protocol_size}")
    print(f"Opcode: {opcode}")
    print(f"Sender MAC: {sender_mac}")
    print(f"Sender IP: {sender_ip_readable}")
    print(f"Target MAC: {target_mac}")
    print(f"Target IP: {target_ip_readable}") 

# Function to parse and display only IPv4 header fields
def parse_ipv4_header_only(hex_data):
    # IPv4 starts after the Ethernet header (28 hex characters or 14 bytes)
    ipv4_header = hex_data[28:48]  # First 20 bytes are the IPv4 header

    # Ensure that we have enough data in the packet
    if len(hex_data) < 48:
        print("Packet is too short to contain an IPv4 header!")
        return

    version_ihl = ipv4_header[0:2]
    version = version_ihl[0]
    ihl = int(version_ihl[1], 16)  # IHL is the second nibble
    total_length = ipv4_header[4:8]
    protocol = ipv4_header[18:20]
    header_checksum = ipv4_header[20:24]

    # Adjust the offsets for extracting the source and destination IPs
    source_ip = hex_data[52:60]
    dest_ip = hex_data[60:68]

    # Convert IP addresses to readable format
    source_ip_readable = '.'.join(str(int(source_ip[i:i+2], 16)) for i in range(0, len(source_ip), 2))
    dest_ip_readable = '.'.join(str(int(dest_ip[i:i+2], 16)) for i in range(0, len(dest_ip), 2))

    print(f"Version: {version}")
    print(f"IHL: {ihl}")
    print(f"Total Length: {int(total_length, 16)}")
    print(f"Protocol: {protocol}")
    print(f"Header Checksum: {header_checksum}")
    print(f"Source IP: {source_ip_readable}")
    print(f"Destination IP: {dest_ip_readable}")

def parse_ipv4_packet(hex_data):
    # IPv4 starts after the Ethernet header (28 hex characters or 14 bytes)
    ipv4_header = hex_data[28:48]  # First 20 bytes are the IPv4 header

    # Ensure that we have enough data in the packet
    if len(hex_data) < 48:
        print("Packet is too short to contain an IPv4 header!")
        return

    version_ihl = ipv4_header[0:2]
    version = version_ihl[0]
    ihl = int(version_ihl[1], 16)  # IHL is the second nibble
    ip_header_length = ihl * 4 * 2  # IHL is in 32-bit words, multiply by 4 to get bytes, *2 for hex chars

    total_length = ipv4_header[4:8]
    protocol = ipv4_header[18:20]

    # Adjust the offsets for extracting the source and destination IPs
    source_ip = hex_data[52:60]  # Source IP is 4 bytes long, starts after byte 12
    dest_ip = hex_data[60:68]    # Destination IP is 4 bytes long, starts after byte 16

    # Debugging: Print raw hex values
    print(f"Source IP (Hex): {source_ip}")
    print(f"Destination IP (Hex): {dest_ip}")

    # Check if source or destination IP fields are missing or incomplete
    if len(source_ip) < 8 or len(dest_ip) < 8:
        print("Error: Source or Destination IP field is incomplete")
        return

    # Convert the hex representation to dotted decimal format
    try:
        source_ip_readable = '.'.join(str(int(source_ip[i:i+2], 16)) for i in range(0, len(source_ip), 2))
        dest_ip_readable = '.'.join(str(int(dest_ip[i:i+2], 16)) for i in range(0, len(dest_ip), 2))
    except ValueError as e:
        print(f"Error converting IP: {e}")
        return

    print(f"Version: {version}")
    print(f"IHL: {ihl}")
    print(f"Total Length: {int(total_length, 16)}")
    print(f"Protocol: {protocol}")
    print(f"Source IP: {source_ip_readable}")
    print(f"Destination IP: {dest_ip_readable}")

def parse_tcp_packet(hex_data):
    # Extract the IHL field from the IPv4 header
    version_ihl = hex_data[28:30]
    ihl = int(version_ihl[1], 16)  # IHL is in 32-bit words, so multiply by 4 to get the byte length
    ip_header_length = ihl * 4

    # Calculate the start of the TCP header
    tcp_start = 28 + ip_header_length * 2  # Ethernet header + IP header (in hex characters)

    # TCP header is at least 20 bytes (40 hex characters)
    tcp_header = hex_data[tcp_start:tcp_start + 40]

    if len(tcp_header) < 40:
        print("Error: TCP header is too short!")
        return

    # Extracting fields from the TCP header
    source_port = tcp_header[0:4]         # First 4 hex characters (2 bytes) for Source Port
    dest_port = tcp_header[4:8]           # Next 4 hex characters (2 bytes) for Destination Port
    seq_number = tcp_header[8:16]         # Next 8 hex characters (4 bytes) for Sequence Number
    ack_number = tcp_header[16:24]        # Next 8 hex characters (4 bytes) for Acknowledgment Number
    data_offset_reserved_flags = tcp_header[24:28]  # Data offset and flags
    window_size = tcp_header[28:32]       # Next 4 hex characters (2 bytes) for Window Size
    checksum = tcp_header[32:36]          # Next 4 hex characters (2 bytes) for Checksum
    urgent_pointer = tcp_header[36:40]    # Last 4 hex characters (2 bytes) for Urgent Pointer

    # Convert and print the parsed TCP fields
    try:
        source_port_readable = int(source_port, 16)
        dest_port_readable = int(dest_port, 16)
        seq_number_readable = int(seq_number, 16)
        ack_number_readable = int(ack_number, 16)
        window_size_readable = int(window_size, 16)
        checksum_readable = int(checksum, 16)
        urgent_pointer_readable = int(urgent_pointer, 16)
    except ValueError as e:
        print(f"Error converting TCP field: {e}")
        return

    print(f"Source Port: {source_port_readable}")
    print(f"Destination Port: {dest_port_readable}")
    print(f"Sequence Number: {seq_number_readable}")
    print(f"Acknowledgment Number: {ack_number_readable}")
    print(f"Window Size: {window_size_readable}")
    print(f"Checksum: {checksum_readable}")
    print(f"Urgent Pointer: {urgent_pointer_readable}")



def parse_udp_packet(hex_data):
    # Extract the IHL field from the IPv4 header
    version_ihl = hex_data[28:30]
    ihl = int(version_ihl[1], 16)  # IHL is the second nibble
    ip_header_length = ihl * 4  # IHL is in 32-bit words, so multiply by 4 to get the length in bytes

    # Calculate where the UDP header starts
    udp_start = 28 + ip_header_length * 2  # Ethernet header + IP header length (in hex characters)

    udp_header = hex_data[udp_start:udp_start + 16]  # UDP header is 8 bytes (16 hex characters)

    if len(udp_header) < 16:
        print("Error: UDP header is too short!")
        return

    source_port = udp_header[0:4]  # First 4 hex characters (2 bytes) for the source port
    dest_port = udp_header[4:8]    # Next 4 hex characters (2 bytes) for the destination port
    udp_length = udp_header[8:12]  # Next 4 hex characters (2 bytes) for the UDP length
    udp_checksum = udp_header[12:16]  # Next 4 hex characters (2 bytes) for the UDP checksum

    # Debug: Print the raw hex data for UDP
    print(f"Raw UDP Header (Hex): {udp_header}")
    print(f"UDP Length (Hex): {udp_length}")
    print(f"UDP Checksum (Hex): {udp_checksum}")

    try:
        source_port_readable = int(source_port, 16)
        dest_port_readable = int(dest_port, 16)
        udp_length_readable = int(udp_length, 16)
        udp_checksum_readable = int(udp_checksum, 16)
    except ValueError as e:
        print(f"Error converting UDP field: {e}")
        return

    print(f"Source Port: {source_port_readable}")
    print(f"Destination Port: {dest_port_readable}")
    print(f"UDP Length: {udp_length_readable}")
    print(f"UDP Checksum: {udp_checksum_readable}")



# Example usage (replace with actual interface and filter)
capture_packets('Wi-Fi', 'udp', 1)

