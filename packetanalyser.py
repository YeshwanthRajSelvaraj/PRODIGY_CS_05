from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
import time

# Callback function to process each packet
def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        # Extract IP information
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        
        # Determine protocol
        protocol = packet[IP].proto
        proto_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol, "Unknown")
        
        # Print basic packet info
        print(f"\n[Packet Captured at {time.ctime()}]")
        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {proto_name}")
        
        # Extract additional details based on protocol
        if TCP in packet:
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
        elif UDP in packet:
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")
        elif ICMP in packet:
            print("ICMP Packet (e.g., Ping)")
        
        # Display payload if present
        if Raw in packet:
            payload = packet[Raw].load
            try:
                # Attempt to decode payload as UTF-8
                payload_str = payload.decode('utf-8', errors='ignore')
                print(f"Payload (text): {payload_str[:50]}..." if len(payload_str) > 50 else payload_str)
            except:
                # Fallback to hexadecimal if decoding fails
                print(f"Payload (hex): {payload.hex()[:50]}...")
        
        print("-" * 50)

# Function to start sniffing
def start_sniffing(interface=None, count=10, filter=None):
    print("WARNING: Use this packet sniffer ethically and with permission only!")
    print("Unauthorized network monitoring may be illegal in your jurisdiction.")
    print(f"\nStarting packet capture on {interface or 'default interface'}...")
    print(f"Filter: {filter or 'None'}")
    print(f"Capturing {count} packets. Press CTRL+C to stop early.")
    
    try:
        # Start sniffing with the specified parameters
        sniff(iface=interface, prn=packet_callback, count=count, filter=filter, store=0)
    except KeyboardInterrupt:
        print("\nSniffing stopped by user.")
    except Exception as e:
        print(f"\nError: {str(e)}")
        print("You may need to run with sudo/admin privileges or check your interface.")
    
    print(f"\nCapture complete.")

def main():
    # Default settings
    interface = None  # Use default interface
    packet_count = 10
    filter_str = None  # No filter by default (captures all packets)
    
    # Get user input (optional)
    interface_input = input("Enter network interface (press Enter for default): ").strip()
    interface = interface_input if interface_input else None
    
    count_input = input("Enter number of packets to capture (default 10): ").strip()
    packet_count = int(count_input) if count_input.isdigit() else 10
    
    filter_input = input("Enter filter (e.g., 'tcp port 80', press Enter for none): ").strip()
    filter_str = filter_input if filter_input else None
    
    start_sniffing(interface, packet_count, filter_str)

if __name__ == "__main__":
    # Requires scapy: pip install scapy
    # May require root/admin privileges
    main()

#output
#WARNING: Use this packet sniffer ethically and with permission only!
#Unauthorized network monitoring may be illegal in your jurisdiction.

#Starting packet capture on default interface...
#Filter: None
#Capturing 10 packets. Press CTRL+C to stop early.

#[Packet Captured at Wed Apr 09 12:00:00 2025]
#Source IP: 192.168.1.100
#Destination IP: 8.8.8.8
#Protocol: UDP
#Source Port: 12345
#Destination Port: 53
#Payload (text): ...
#--------------------------------------------------

#[Packet Captured at Wed Apr 09 12:00:01 2025]
#Source IP: 8.8.8.8
#Destination IP: 192.168.1.100
#Protocol: UDP
#Source Port: 53
#Destination Port: 12345
#Payload (hex): 4500023c1d...
#--------------------------------------------------

#Capture complete.
