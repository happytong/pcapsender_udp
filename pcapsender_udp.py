import argparse
from scapy.all import *
import time
from datetime import datetime

# --- Parse command-line arguments ---
parser = argparse.ArgumentParser(description="PCAP UDP replayer with dynamic MAC resolution.")
parser.add_argument("--pcap", required=True, help="Path to the PCAP file to replay")
parser.add_argument("--src-ip", required=True, help="Custom source IP address")
parser.add_argument("--dst-ip", required=True, help="Custom destination IP address")
parser.add_argument("--dst-port", type=int, help="Filter packets by destination port (optional)")
parser.add_argument("--info", action="store_true", help="Show extra debug info")
args = parser.parse_args()

PCAP_FILE = args.pcap
CUSTOM_SRC_IP = args.src_ip
CUSTOM_DST_IP = args.dst_ip
DEST_PORT = args.dst_port
# Set your network interface name here
IFACE_NAME = "Intel(R) Ethernet Connection (10) I219-V"  # Replace with your NIC name on Windows or eth0/en0/etc on Linux/Mac

# --- Resolve MAC address of target IP ---
def resolve_mac(ip, iface):
    # Send ARP request to resolve MAC address for the given IP
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
    response = srp1(arp_request, iface=iface, timeout=2, verbose=False)
    if response:
        return response[Ether].src
    return None

dst_mac = resolve_mac(CUSTOM_DST_IP, IFACE_NAME)
if not dst_mac:
    print(f"Could not resolve MAC for {CUSTOM_DST_IP}. Target might be offline.")
    exit(1)

# --- Load pcap ---
packets = rdpcap(PCAP_FILE)

# Filter packets if DEST_PORT is provided
if DEST_PORT:
    filtered_packets = [pkt for pkt in packets if pkt.haslayer(UDP) and pkt[UDP].dport == DEST_PORT]
    if not filtered_packets:
        print(f"No packets found with destination port {DEST_PORT}.")
        exit(1)
    packets = filtered_packets

# Store timestamps and packets for replay
timestamps = [(pkt.time, pkt) for pkt in packets]
script_start_time = time.time()
log_file = open("send.log", "w")

# --- Log stream info ---
first_pkt = timestamps[0][1]
if first_pkt.haslayer(IP):
    src_ip = first_pkt[IP].src
    dst_ip = first_pkt[IP].dst
else:
    src_ip = dst_ip = "Unknown"

port_info = ""
if first_pkt.haslayer(UDP):
    port_info = f"UDP {first_pkt[UDP].sport} -> {first_pkt[UDP].dport}"
elif first_pkt.haslayer(TCP):
    port_info = f"TCP {first_pkt[TCP].sport} -> {first_pkt[TCP].dport}"

print(f"\n==> Stream Info: from {src_ip} to {dst_ip}, {port_info}, sending via interface '{IFACE_NAME}' to MAC {dst_mac}\n")
log_file.write(f"Stream Info: from {src_ip} to {dst_ip}, {port_info}, to MAC {dst_mac}\n")

# --- Replay packets ---
prev_send_time = None
last_frame_sent = None

for i, (timestamp, pkt) in enumerate(timestamps):
    # Create a copy to avoid modifying the original packet
    modified_pkt = pkt.copy()
    
    # Strip existing Ethernet layer if present
    if modified_pkt.haslayer(Ether):
        modified_pkt = modified_pkt[Ether].payload
    
    # Modify IP addresses
    if modified_pkt.haslayer(IP):
        modified_pkt[IP].src = CUSTOM_SRC_IP
        modified_pkt[IP].dst = CUSTOM_DST_IP
        del modified_pkt[IP].chksum  # Remove checksum so Scapy recalculates it
        # Recalculate transport layer checksums
        if modified_pkt.haslayer(UDP):
            del modified_pkt[UDP].chksum
        elif modified_pkt.haslayer(TCP):
            del modified_pkt[TCP].chksum
    
    # Add new Ethernet layer with resolved MAC
    ether = Ether(dst=dst_mac)
    full_pkt = ether / modified_pkt

    # Handle timing: sleep to match original packet timing (max 5 seconds)
    if i > 0:
        prev_timestamp = timestamps[i - 1][0]
        time_diff = timestamp - prev_timestamp
        sleep_time = min(max(time_diff, 0), 5.0)
        time.sleep(float(sleep_time))

    actual_send_time = time.time()
    time_diff_ms = int((actual_send_time - prev_send_time) * 1000) if prev_send_time else 0
    prev_send_time = actual_send_time
    last_frame_sent = i + 1

    # Log payload in hex if present
    if pkt.haslayer(Raw):
        payload = pkt[Raw].load
        payload_hex = ' '.join(f"{b:02x}" for b in payload)
    else:
        payload_hex = "No payload"

    # Send the packet on the specified interface
    sendp(full_pkt, iface=IFACE_NAME, verbose=False)

    # Log send time and payload
    dt = datetime.fromtimestamp(actual_send_time)
    milliseconds = dt.microsecond // 1000
    log_line = (f"Sent at: {dt.strftime('%Y-%m-%d %H:%M:%S')}.{milliseconds:03d}ms, "
                f"{last_frame_sent}, {time_diff_ms}ms, Payload: [{payload_hex}]")
    print(log_line)
    log_file.write(log_line + "\n")

# --- Summary ---
total_runtime = time.time() - script_start_time
h, m, s = int(total_runtime // 3600), int((total_runtime % 3600) // 60), int(total_runtime % 60)
print(f"\nTotal script run time: {h}h{m}m{s}s")
log_file.write(f"\nTotal run time: {h}h{m}m{s}s\n")
log_file.close()
